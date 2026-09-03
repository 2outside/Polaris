//! 配置运行时：`polaris-store` + `polaris-config-engine` 的运行时装配。
//!
//! Polaris 锚点：`main/services/ConfigManager.ts`。
//! - `loadConfig` → [`ConfigManager::load_full`]（read → sanitize → migrate → validate → 填默认 + currentConfig 缓存）
//! - `saveConfig` → `ConfigManager::save_full`（再跑 sanitize+validate + 原子 tmp→rename 写盘 + 刷缓存）
//! - `get(key)` / `set(key, value)` → currentConfig 投影取值 / 原地改 + 异步落盘
//!
//! 纯逻辑纪律：`store::ConfigStore` / `sanitize` / `validate` / `migrate` 全在 domain crate，
//! 本层仅注入 [`StdFs`]（std::fs，0o600）+ 持有 currentConfig 缓存（Polaris ConfigManager.currentConfig）。

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

use polaris_store::fs::{random_tmp_suffix, ConfigFs, StdFs};
use polaris_store::{ConfigStore, LoadResult, StoreError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFERRED_DELETIONS_FILE: &str = "pending-config-deletions.json";
const DEFERRED_DELETIONS_VERSION: u8 = 1;
const STAGED_PENDING_FILE: &str = "staged-config.pending";
const STAGED_PENDING_VERSION: u8 = 1;

/// 未保存草稿对运行态节点选择的最小投影。正文仍只在渲染端；这里不复制配置，只携带自动故障切换
/// 必须知道的节点 id。`scope_known=false` 只会来自升级前的空 marker：此时调用方必须保守地把整个
/// 节点域视为未知，不能猜一份草稿没有改节点。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StagedNodeMask {
    pub pending: bool,
    pub node_ids: BTreeSet<String>,
    pub scope_known: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StagedPendingMarker {
    version: u8,
    node_ids: BTreeSet<String>,
}

/// [`ConfigManager::with_current`] 闭包内的**重入探针**（debug 构型，release 完全编译掉）。
///
/// # 为什么要有牙，而不是只写一行注释
///
/// `with_current` 的闭包跑在 `cache` 的**读锁**里，闭包内再碰 `ConfigManager` 就是死锁面（细节见该
/// 方法文档）。而这个坑的失效形态**极不友好**：
/// - 取写锁那条（`save_full` / `set_value`）是**必然**自死锁 —— 一写就挂，尚算显形；
/// - 取读锁那条（`current` / 嵌套 `with_current`）平时**看起来是好的** —— std 的 `RwLock` 在无写者
///   排队时递归读通常拿得到，只有「恰好有另一条腿在写配置」的那一瞬才永久阻塞。也就是说它能过
///   全部单测、过 code review、过真机冒烟，然后在用户改配置的那一刻挂死。
///
/// 靠文档防这种坑等于没防。故 debug 构型下用一个 thread-local 深度计数把「在闭包里又回来读/写配置」
/// **就地打成 panic**：坏用法在写出来的当天、在单测里就炸，而不是在生产里挂死。
/// release 构型下 [`ReentrancyProbe`] 是零字段 ZST、`enter`/`Drop` 皆空 —— 无 TLS 访问、无分支。
#[cfg(debug_assertions)]
mod reentrancy {
    use std::cell::Cell;

    thread_local! {
        /// 当前线程正处在几层 `with_current` 闭包里（>0 = 读锁在手，禁止再碰 ConfigManager）。
        static DEPTH: Cell<u32> = const { Cell::new(0) };
    }

    /// 进入闭包时 +1、离开（含 panic 展开）时 -1。用 `Drop` 而非手工配对：闭包 panic 时也必须归零，
    /// 否则一个失败测试会把同线程后续所有配置读全打成 panic，故障从一条变成一片。
    pub(super) struct ReentrancyProbe;

    impl ReentrancyProbe {
        pub(super) fn enter() -> Self {
            DEPTH.with(|d| d.set(d.get() + 1));
            Self
        }
    }

    impl Drop for ReentrancyProbe {
        fn drop(&mut self) {
            DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
        }
    }

    /// `ConfigManager` 每个入口开头调一次：若正在 `with_current` 闭包里 → 立刻 panic。
    pub(super) fn deny_inside_projection(entry: &str) {
        assert!(
            DEPTH.with(Cell::get) == 0,
            "ConfigManager::{entry} 在 with_current 闭包内被调用 —— 读锁正持在手上，\
             取写锁必然自死锁、递归读会在有写者排队时永久阻塞。闭包内只做纯投影，\
             把第二次配置读平铺到闭包外面。"
        );
    }
}

#[cfg(not(debug_assertions))]
mod reentrancy {
    pub(super) struct ReentrancyProbe;
    impl ReentrancyProbe {
        #[inline(always)]
        pub(super) fn enter() -> Self {
            Self
        }
    }
    #[inline(always)]
    pub(super) fn deny_inside_projection(_entry: &str) {}
}

use reentrancy::{deny_inside_projection, ReentrancyProbe};

/// [`ConfigManager::update`] 闭包的裁决：写不写盘，以及调用方要 return 的那个值。
///
/// 两个变体**都带 `R`**：「不写」在真实站点上通常是**以另一种方式成功了**
/// （净零序、无命中、内容等价），不是失败 —— 失败走 `Err(StoreError)` 或调用方自己塞进 `R`。
#[derive(Debug)]
pub enum Decision<R> {
    /// 落盘，然后把 `R` 与已落盘的配置一起还给调用方。
    Write(R),
    /// **不落盘、不广播**，直接把 `R` 还给调用方（闭包对 cfg 的改动一律丢弃）。
    Skip(R),
}

/// 「配置已保存、运行态尚未 Apply」期间必须保留的不可逆删除意图。
///
/// 这不是第二份配置：条目只携带执行副作用所需的最小身份。执行前仍会对照最新 config 复核；若实体
/// 已被重新加入，则丢弃意图而不删除。WARP token 只落 0o600 的运行时状态文件，不进入前端快照/备份。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum DeferredConfigDeletion {
    RuleResource {
        file_name: String,
    },
    BuiltinRuleResource {
        tag: String,
        file_name: String,
    },
    AppIcon {
        app_id: String,
    },
    TailscaleState {
        server_id: String,
    },
    WarpDevice {
        server_id: String,
        device_id: String,
        token: String,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeferredDeletionJournal {
    version: u8,
    entries: Vec<DeferredConfigDeletion>,
}

impl Default for DeferredDeletionJournal {
    fn default() -> Self {
        Self {
            version: DEFERRED_DELETIONS_VERSION,
            entries: Vec::new(),
        }
    }
}

/// 延迟删除消费结果。只暴露计数，绝不把可能含 WARP token 的条目带进日志或 IPC。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DeferredDeletionSummary {
    pub applied: usize,
    pub cancelled: usize,
    pub retrying: usize,
}

/// 配置运行时（`State`-managed，单实例）。
///
/// 持有配置目录路径 + currentConfig 缓存（`RwLock<Value>`，读多写少）。
/// FS 经 [`StdFs`]（std::fs 实现，写入 0o600）——纯逻辑 crate 的 trait 注入点。
pub struct ConfigManager {
    /// 配置目录（`<app_config_dir>/polaris/`）。
    dir: PathBuf,
    /// config.json 绝对路径。
    path: PathBuf,
    /// currentConfig 缓存（Polaris ConfigManager.currentConfig；首次 load 填充）。
    cache: RwLock<Option<Value>>,
    /// **配置文件事务锁** —— 读取时可能发生的首装/迁移落盘、普通保存、原子读改写与删除日志消费
    /// 全部按这把锁串行。这样不只避免两个 writer 丢更新，也避免 `load_full` 的迁移落盘从旁路覆盖
    /// 一次已完成的更新。
    ///
    /// **与 [`Self::cache`] 是两把互不相干的锁**，这一点是本设计成立的前提：临界区内会调
    /// `load_full_under_write_lock`（末尾取 `cache` 写锁）与保存腿（先取读锁拿旧 icon id、末尾取写锁刷缓存），
    /// 若本锁与 `cache` 是同一把，那两次调用就是自死锁。
    write_lock: Mutex<()>,
    /// 配置保存与延迟删除消费的事务锁。所有 save 都经它串行，关掉「journal 已写、config 未写时被
    /// Apply 提前消费」及「消费复核后实体又被并发加入」两类竞态；与 `write_lock` 分离以免锁层反转。
    deferred_delete_lock: Mutex<()>,
    /// 渲染端是否仍有未落盘草稿。内存位守本进程的托盘/启动入口，旁边的空标记文件守崩溃重启。
    /// 正常退出留下 `clean-exit.marker` 时，新进程会忽略并清掉本标记；app:restart / 崩溃则保留。
    /// 草稿存在位、节点遮罩与范围判据必须是同一份原子快照。拆成多个 atomic/lock 会允许自动
    /// 故障切换读到 `pending=true` 搭配旧遮罩，从而穿透刚建立的未保存节点边界。
    staged_mask: RwLock<StagedNodeMask>,
}

impl ConfigManager {
    /// 新建（dir = `<app_config_dir>/polaris/`）。不立即读盘——lazy load（首次命令触发）。
    pub fn new(dir: PathBuf) -> Self {
        let path = dir.join("config.json");
        let staged_pending_path = dir.join(STAGED_PENDING_FILE);
        let clean_exit = StdFs.exists(&dir.join(crate::clean_exit::CLEAN_EXIT_MARKER_FILENAME));
        let staged_pending = !clean_exit && StdFs.exists(&staged_pending_path);
        let staged_marker = staged_pending
            .then(|| StdFs.read_to_string(&staged_pending_path).ok())
            .flatten()
            .and_then(|raw| serde_json::from_str::<StagedPendingMarker>(&raw).ok())
            .filter(|marker| marker.version == STAGED_PENDING_VERSION);
        if clean_exit {
            // 正常退出的渲染端草稿按既有 Q1-b 契约丢弃。这里同步清后端镜像，避免 2s 自动连接
            // 早于主窗 hydrate 时把一份已被判作废的旧草稿误当阻塞条件。
            if let Err(error) = StdFs.remove(&staged_pending_path) {
                log::warn!("清理正常退出遗留的草稿标记失败: {error}");
            }
        }
        Self {
            dir,
            path,
            cache: RwLock::new(None),
            write_lock: Mutex::new(()),
            deferred_delete_lock: Mutex::new(()),
            staged_mask: RwLock::new(StagedNodeMask {
                pending: staged_pending,
                node_ids: staged_marker
                    .as_ref()
                    .map_or_else(BTreeSet::new, |marker| marker.node_ids.clone()),
                scope_known: staged_marker.is_some(),
            }),
        }
    }

    /// 配置目录（供其他运行时复用，如 mesh state / helper token）。
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// config.json 路径。
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 渲染端未保存草稿的跨入口镜像。只表达“有/无”，草稿正文仍唯一保存在主窗 `localStorage`。
    #[must_use]
    pub fn has_staged_pending(&self) -> bool {
        self.staged_mask
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending
    }

    /// 自动故障切换消费的草稿节点遮罩快照。`pending=false` 时其余字段没有语义；升级前空 marker
    /// 会得到 `pending=true, scope_known=false`，调用方据此 fail-closed。
    #[must_use]
    pub fn staged_node_mask(&self) -> StagedNodeMask {
        self.staged_mask
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// 更新未保存草稿标记。内存位先更新，确保当前进程里的托盘入口立即看到；持久文件 best-effort，
    /// 失败不会反过来吃掉渲染端草稿，只会让崩溃后的自动连接少一道后端保险（前端恢复后会再次同步）。
    #[cfg(test)]
    pub fn set_staged_pending(&self, pending: bool) {
        self.set_staged_pending_snapshot(pending, None);
    }

    /// 更新草稿 marker 及其节点遮罩。`node_ids=None` 是旧调用方/旧 marker 的未知范围；新渲染端即使
    /// 草稿只改了非节点配置也会显式传 `Some(empty)`，这样故障切换仍可在运行态 clean 节点间工作。
    pub fn set_staged_pending_snapshot(&self, pending: bool, node_ids: Option<Vec<String>>) {
        let scope_known = node_ids.is_some();
        let node_ids: BTreeSet<String> = node_ids.unwrap_or_default().into_iter().collect();
        {
            let mut guard = self
                .staged_mask
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *guard = StagedNodeMask {
                pending,
                node_ids: node_ids.clone(),
                scope_known,
            };
        }
        let path = self.dir.join(STAGED_PENDING_FILE);
        let result = if pending {
            let marker = StagedPendingMarker {
                version: STAGED_PENDING_VERSION,
                node_ids,
            };
            serde_json::to_string(&marker)
                .map_err(StoreError::from)
                .and_then(|content| {
                    StdFs
                        .create_dir_all(&self.dir)
                        .and_then(|()| StdFs.write(&path, &content))
                })
        } else {
            StdFs.remove(&path)
        };
        if let Err(error) = result {
            log::warn!("同步未保存草稿标记失败（pending={pending}）: {error}");
        }
    }

    /// 加载配置（read → sanitize → migrate → validate + 填默认），刷新 currentConfig 缓存。
    ///
    /// 维度7 #7：坏 JSON/坏字段绝不崩溃，回落默认配置；损坏的磁盘真实文件绝不覆盖。仅新装默认值
    /// 与迁移链已确认的改写会在本层 best-effort 落盘，保证带标记迁移真正一次完成。
    pub fn load_full(&self) -> Result<Value, StoreError> {
        deny_inside_projection("load_full");
        let _write_guard = self
            .write_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.load_full_under_write_lock()
    }

    /// 调用方已持有 [`Self::write_lock`] 的加载腿。加载本身可能因首装或迁移而写盘，所以不能当成
    /// 普通只读操作从事务锁旁路执行。
    fn load_full_under_write_lock(&self) -> Result<Value, StoreError> {
        let LoadResult {
            config,
            loaded_from_disk,
            migration_delta,
            was_missing,
            error,
        } = ConfigStore::load(&StdFs, &self.path);
        // 加载或校验失败 → 回落默认（LoadResult 已处理），但记日志保留 error 上下文。
        if let Some(e) = &error {
            log::warn!("config load fallback (loaded_from_disk={loaded_from_disk}): {e}");
        }
        // 新装（文件本不存在）→ 落盘一次默认配置；迁移有改写 → 同步落盘迁移值与幂等标记。
        // 若只把迁移后的 Value 放进 cache、忽略 migration_delta，重启后还会从旧磁盘形态重复迁移；
        // 更糟的是「用户关闭预热」这类一次性默认纠偏无法证明已经完成。损坏配置的 fallback 同时满足
        // was_missing=false + migration_delta.changed=false，仍保持“不覆盖损坏原件”的安全边界。
        //
        // 第 4 参是**原子写的 12hex tmp 后缀**（`randomBytes(6).toString('hex')` 等价），
        // 不是品牌名/应用名。此处曾误传字面量 `"polaris"` → debug 撞 `tmp_path` 的
        // `debug_assert` **首启即崩**（本行正是 P0 的触发点：config.json 不存在才走到）；
        // release 下则静默产出永不被清扫的 `config.json.polaris.tmp`。
        if was_missing || migration_delta.changed {
            if let Err(e) = ConfigStore::save(&StdFs, &self.path, &config, &random_tmp_suffix()) {
                log::warn!(
                    "config load persist failed (was_missing={was_missing}, migrated={}): {e}",
                    migration_delta.changed
                );
            }
        }
        // 刷缓存（持有写锁）。
        if let Ok(mut guard) = self.cache.write() {
            *guard = Some(config.clone());
        }
        Ok(config)
    }

    /// 读 currentConfig 缓存（不触盘）。缓存未暖 → 触发一次 load_full（Polaris getCurrentConfig 懒加载）。
    ///
    /// **恒返回 owned `Value` = 恒一次整份深拷贝**（读锁只护到 clone 为止）。200 节点级配置下这不是
    /// 小数目，故**每帧 / 每 tick 调用的路径一律改用 [`with_current`](Self::with_current) 做投影**；
    /// 本方法留给「确实要整份 owned 配置」的调用点（改完要 `save_full` 的写腿、要跨 `await` 搬运给
    /// 异步任务的腿、要整份 `from_value::<UserConfig>` 的起核腿）—— 那些地方即便换成 `with_current`
    /// 也得在闭包里 clone 出整份，零收益且平白多一条闭包内禁忌。
    pub fn current(&self) -> Result<Value, StoreError> {
        deny_inside_projection("current");
        if let Ok(guard) = self.cache.read() {
            if let Some(c) = guard.as_ref() {
                return Ok(c.clone());
            }
        }
        self.load_full()
    }

    /// currentConfig 缓存的**持锁投影入口**：读锁一直持到 `f` 返回，`f` 只取它真正要的那几个字段。
    ///
    /// 与 [`current`](Self::current) 的唯一差别是**谁付整份深拷贝的账**：`current()` 恒 clone 整份配置
    /// （含 `servers` 数组与全部规则）再把 owned 值交出去；本方法一次都不 clone。缓存未暖 / 锁中毒 →
    /// 与 `current()` 同款回落：先 `load_full()` 读盘，再对结果跑 `f`（此时读锁已释放，不会撞
    /// `load_full` 内部的写锁）。
    ///
    /// # ⚠️ 闭包内禁忌（唯一、但是硬的）
    ///
    /// `f` 执行期间 `self.cache` 的**读锁是持着的**，故闭包内**禁止再调用 `ConfigManager` 的任何方法**：
    ///
    /// - `save_full` / `set_value` / `load_full` 要 `cache.write()` —— 同线程「持读锁再取写锁」是
    ///   **必然自死锁**：`std::sync::RwLock` 既不可重入也不支持读锁升级，那个 `write()` 永远等不到
    ///   自己手里的读锁释放。
    /// - `current` / `get_value` / `with_current` 只要 `cache.read()`，看似无害，**同样禁止**：std 的
    ///   `RwLock::read` 文档明写「本线程已持有该锁时可能 panic」，且在**有写者排队**时，写者优先的实现
    ///   （Linux futex 版即是）会让这次递归读**永久阻塞**。即：平时怎么测都不复现，只在「恰好有另一条
    ///   腿在写配置」的那一瞬变成死锁 —— 最难查的那类。
    ///
    /// 所以 `f` 只该做**纯投影**：从 `&Value` 取字段 → 转成 owned 值返回。不做 I/O、不回调进运行时的
    /// 其它子系统（那些子系统日后完全可能自己去读配置），也无处 `await`（本方法是同步的）。
    /// 需要「投影 + 再读一次配置」的调用点，把两次读**平铺**成先后两句，不要嵌套。
    ///
    /// 这条禁忌**在 debug 构型下是有牙的**：闭包执行期间挂着 [`reentrancy`] 探针，闭包内再调
    /// `ConfigManager` 任一入口会立刻 panic（而不是等某次「恰好有人在写配置」时挂死）。
    pub fn with_current<T>(&self, f: impl FnOnce(&Value) -> T) -> Result<T, StoreError> {
        deny_inside_projection("with_current");
        if let Ok(guard) = self.cache.read() {
            if let Some(c) = guard.as_ref() {
                let _probe = ReentrancyProbe::enter();
                return Ok(f(c));
            }
        }
        // 缓存未暖 / 锁中毒 → 读盘一次。注意读锁已随上面的 `if let` 作用域释放（`load_full` 要写锁）。
        let cfg = self.load_full()?;
        // 回落腿并不持读锁，探针仍照挂：调用方无从得知本次走了哪条腿，禁忌必须两条腿一致，
        // 否则「冷缓存下能跑、暖起来就死」是更坏的形态。
        let _probe = ReentrancyProbe::enter();
        Ok(f(&cfg))
    }

    /// 保存配置（再跑 sanitize+validate + 原子写）+ 刷缓存。上游 `saveConfig`。
    ///
    /// 顺带在此唯一汇流点做**图标缓存驱逐 reconcile**：diff 旧/新 `customAppPresets` 的 id 集，
    /// 删掉已移除自定义应用的 `<userData>/icons/<id>.*` 本地缓存。挂在这里（而非某个屏幕调 evict
    /// 命令）覆盖所有令 app id 消失的写路径（删除 / 备份整类替换 / 工厂重置），避免跨文件缝。
    /// best-effort：unlink 失败仅记日志，绝不影响配置保存本身。
    #[cfg(test)]
    pub fn save_full(&self, config: &Value) -> Result<(), StoreError> {
        deny_inside_projection("save_full");
        let _write_guard = self
            .write_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.save_full_under_write_lock(config).map(drop)
    }

    /// 调用方已持有 `write_lock` 的保存腿；只供 [`Self::update_with_cleanup`] 复用，避免 Mutex 重入。
    fn save_full_under_write_lock(&self, config: &Value) -> Result<Value, StoreError> {
        let _guard = self
            .deferred_delete_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.save_full_with_icon_reconcile(config, true)
    }

    /// 暂存层「保存」专用：先以旧/新配置生成持久删除意图，再落配置；此刻不执行任何不可逆清理。
    ///
    /// 意图采用 write-ahead 顺序。若进程在写意图后、写 config 前崩溃，消费端会看见实体仍在最新配置中，
    /// 将该条判为 cancelled，故不会误删；反过来若先写 config 再写意图，崩溃会永久丢失清理凭据。
    #[cfg(test)]
    pub fn save_full_deferred_cleanup(
        &self,
        current: &Value,
        config: &Value,
    ) -> Result<(), StoreError> {
        let _write_guard = self
            .write_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.save_full_deferred_cleanup_under_write_lock(current, config)
            .map(drop)
    }

    /// 调用方已持有 `write_lock` 的延迟清理保存腿；与普通保存共享同一条写队列。
    fn save_full_deferred_cleanup_under_write_lock(
        &self,
        current: &Value,
        config: &Value,
    ) -> Result<Value, StoreError> {
        self.save_full_deferred_cleanup_with_explicit_under_write_lock(current, config, &[])
    }

    fn save_full_deferred_cleanup_with_explicit_under_write_lock(
        &self,
        current: &Value,
        config: &Value,
        explicit: &[DeferredConfigDeletion],
    ) -> Result<Value, StoreError> {
        let _guard = self
            .deferred_delete_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // 删除意图必须按**实际会写盘**的规范形求差集。若 sanitize 会剔除一个坏实体，而这里仍拿
        // 清洗前入参求差集，就会出现“磁盘实体没了、删除 journal 却从未记录”的永久资产泄漏。
        let canonical = ConfigStore::canonicalize_for_save(config)?;
        let mut additions = derive_deferred_deletions(current, &canonical);
        additions.extend_from_slice(explicit);
        self.stage_deferred_deletion_entries_locked(additions)?;
        self.save_canonical_with_icon_reconcile(canonical, false)
    }

    fn save_full_with_icon_reconcile(
        &self,
        config: &Value,
        reconcile_icons: bool,
    ) -> Result<Value, StoreError> {
        deny_inside_projection("save_full");
        let canonical = ConfigStore::canonicalize_for_save(config)?;
        self.save_canonical_with_icon_reconcile(canonical, reconcile_icons)
    }

    fn save_canonical_with_icon_reconcile(
        &self,
        canonical: Value,
        reconcile_icons: bool,
    ) -> Result<Value, StoreError> {
        // 旧 id 集须在刷缓存前从当前缓存取（此刻仍持旧配置）；缓存未暖则无旧态可 diff（冷启无删除发生）。
        let old_ids = self
            .cache
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(crate::icon_cache::custom_app_ids));
        // 同上：第 4 参是随机 12hex tmp 后缀，非品牌名。每次保存都须取新值——
        // 恒定后缀会让并发 saveConfig 撞同一个 tmp 路径，原子写的隔离性即失效。
        ConfigStore::save(&StdFs, &self.path, &canonical, &random_tmp_suffix())?;
        // LOW-4：只有 `customAppPresets` 的 id 集**实际变化**才跑 read_dir + unlink reconcile。
        // `set_value` 走此汇流点保存**任何**键（mixedPort / 开关 / 规则…），绝大多数与自定义应用无关；
        // 无条件 reconcile 会让每次保存都白遍历一遍 `<userData>/icons/`。先比 id 集，未变即跳过整个
        // 磁盘遍历。变化时行为不变（reconcile 仅删「旧有新无」，共享 / 复用 id 保留，unlink best-effort）。
        if reconcile_icons {
            if let Some(old) = old_ids {
                let new_ids = crate::icon_cache::custom_app_ids(&canonical);
                if old != new_ids {
                    crate::icon_cache::reconcile_removed(
                        &crate::icon_cache::icons_dir(&self.dir),
                        &old,
                        &new_ids,
                    );
                }
            }
        }
        if let Ok(mut guard) = self.cache.write() {
            *guard = Some(canonical.clone());
        }
        Ok(canonical)
    }

    fn deferred_deletions_path(&self) -> PathBuf {
        self.dir.join(DEFERRED_DELETIONS_FILE)
    }

    fn load_deferred_deletions_locked(&self) -> Result<DeferredDeletionJournal, StoreError> {
        let path = self.deferred_deletions_path();
        if !StdFs.exists(&path) {
            return Ok(DeferredDeletionJournal::default());
        }
        let text = StdFs.read_to_string(&path)?;
        let journal: DeferredDeletionJournal =
            serde_json::from_str(&text).map_err(StoreError::from_parse)?;
        if journal.version != DEFERRED_DELETIONS_VERSION {
            return Err(StoreError::validation(format!(
                "unsupported deferred deletion journal version: {}",
                journal.version
            )));
        }
        Ok(journal)
    }

    fn save_deferred_deletions_locked(
        &self,
        journal: &DeferredDeletionJournal,
    ) -> Result<(), StoreError> {
        let path = self.deferred_deletions_path();
        if journal.entries.is_empty() {
            return StdFs.remove(&path);
        }
        let content = serde_json::to_string_pretty(journal).map_err(StoreError::from)?;
        polaris_store::atomic_write_plan(&path, &random_tmp_suffix(), &content).execute(&StdFs)
    }

    #[cfg(test)]
    fn stage_deferred_deletions(
        &self,
        current: &Value,
        incoming: &Value,
    ) -> Result<(), StoreError> {
        let _guard = self
            .deferred_delete_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.stage_deferred_deletions_locked(current, incoming)
    }

    #[cfg(test)]
    fn stage_deferred_deletions_locked(
        &self,
        current: &Value,
        incoming: &Value,
    ) -> Result<(), StoreError> {
        self.stage_deferred_deletion_entries_locked(derive_deferred_deletions(current, incoming))
    }

    fn stage_deferred_deletion_entries_locked(
        &self,
        additions: Vec<DeferredConfigDeletion>,
    ) -> Result<(), StoreError> {
        if additions.is_empty() {
            return Ok(());
        }
        let mut journal = self.load_deferred_deletions_locked()?;
        for entry in additions {
            if !journal.entries.contains(&entry) {
                journal.entries.push(entry);
            }
        }
        self.save_deferred_deletions_locked(&journal)
    }

    /// Apply / 冷启动消费延迟删除。每条先按最新配置复核；执行失败保留在日志中，下一次 Apply/启动重试。
    pub(crate) fn process_deferred_deletions(
        &self,
        mut apply: impl FnMut(&DeferredConfigDeletion, &Value) -> Result<(), String>,
    ) -> Result<DeferredDeletionSummary, StoreError> {
        deny_inside_projection("process_deferred_deletions");
        // 锁序与保存腿保持一致：write → deferred-delete。消费期间配置不能被重新加入/删除；否则
        // “复核未取消 → 执行删除”之间仍有竞态。此前反向先拿 deletion 再 cold-current 拿 write，
        // 还会与 save 的 write→deletion 构成冷启动死锁。
        let _write_guard = self
            .write_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _delete_guard = self
            .deferred_delete_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // 在两把事务锁内重读磁盘真值；不用 cache，外部编辑/迁移同样必须参与取消判定。
        let current = self.load_full_under_write_lock()?;
        let journal = self.load_deferred_deletions_locked()?;
        let mut summary = DeferredDeletionSummary::default();
        let mut remaining = Vec::new();
        for entry in journal.entries {
            if deferred_deletion_is_cancelled(&entry, &current) {
                summary.cancelled += 1;
                continue;
            }
            match apply(&entry, &current) {
                Ok(()) => summary.applied += 1,
                Err(error) => {
                    summary.retrying += 1;
                    log::warn!("延迟配置删除执行失败，将在下次 Apply/启动重试: {error}");
                    remaining.push(entry);
                }
            }
        }
        self.save_deferred_deletions_locked(&DeferredDeletionJournal {
            version: DEFERRED_DELETIONS_VERSION,
            entries: remaining,
        })?;
        Ok(summary)
    }

    /// **原子读改写** —— 把「读一份配置 → 改它 → 落盘」变成一个不可分割的动作。
    ///
    /// # 它修的缺陷
    ///
    /// 历史生产写入点曾普遍采用 `load_full()` / `current()` → mutate → `save_full()` 的**分离**三步，
    /// 中间没有任何互斥。于是：
    ///
    /// - 两个写入者交错 ⇒ **丢更新**（后写的那份基于旧读，把前者的改动整份覆盖掉）；
    /// - `config_save` 的 `baseVersion` 乐观并发闸被**架空**：它在第 1 步比对版本、第 3 步才写，
    ///   任何别的写入者落在这两步之间都能让那次比对失去意义。
    ///
    /// 而这确实可达：订阅自动更新写验证器、诊断抓包恢复、热切 commit 都跑在 tokio 任务里，
    /// 与命令处理天然并发。
    ///
    /// # 闭包返回「写不写」+ **调用方自己的返回值**，而不是 `Result`
    ///
    /// 这里的形状是被全仓 30 个站点的普查逼出来的，别按直觉改回 `Result<Option<T>, E>`：
    /// 「不写」这条出口**既不唯一、也不都是错误**。逐站点数下来，读与写之间有 2–4 条不写的出口，
    /// 而其中好几条是**带不同载荷的成功**：
    ///
    /// - `server_delete_batch` 无命中 → `ApiResponse::ok(0u32)`
    /// - `rule_resources_delete` NotFound → `ApiResponse::ok(json!({…}))`
    /// - `rules_reorder` 净零序 → `ok_void()`（**刻意不 save 不广播**）
    /// - `perform_subscription_update` 内容等价 → `update_ok(0,0,0,true,…)`
    /// - `proxy.rs` 热切 commit → `false`
    ///
    /// 一个笼统的 `Ok(None)` 装不下它们；而把它们塞进 `E` 则要么得给共享 crate 加
    /// `From<StoreError> for String`，要么得借 `StoreError::Validation` 转手 —— 后者的 Display 是
    /// `"config validation failed: {0}"`，会把 `"服务器不存在: xxx"` 污染成
    /// `"config validation failed: 服务器不存在: xxx"`，是真的用户可见变化。
    ///
    /// 故：闭包返回 [`Decision<R>`]，`R` 就是调用方要 return 的那个东西（任意类型）。
    /// 读或写失败 ⇒ `Err(StoreError)`，调用方照它今天的写法映射（30 个站点今天都把读失败与写失败
    /// 收敛成同一句 `ApiResponse::err(format!("{e}"))`，故合并不丢信息）。
    ///
    /// `Write` 腿连**已落盘的那份配置**一起返回（`Some(cfg)`）：调用方拿它去
    /// `broadcast_config_changed`，不必再读一次（再读又是一次可被别人插入的窗口）。
    /// `Skip` 腿给 `None` —— **它必须不广播**：净零改动多发一次 `configChanged` 就多一次
    /// `switch_mode` 评估。
    ///
    /// # 整份替换也走这里（不需要第二个原语）
    ///
    /// 闭包拿到的是 `&mut Value`，故「整份替换」就是 `*cfg = next.clone()`
    /// （备份导入、`config_save` 落用户提交的全量配置都是这一形态）。**不要**为它另开一个跳过读的
    /// 入口：那等于又造一条不持锁的写路径，而本方法存在的全部意义就是「只剩一条」。
    ///
    /// # 读的是锁内 `load_full_under_write_lock`，不是 `current`（勿改）
    ///
    /// 本方法自己拥有那次锁内磁盘重读。有人把它改成基于 `current()` 会**偷偷把不变式换成
    /// 「与缓存一致」** —— 而缓存只由本进程的写刷新，外部改动（用户手改 config.json、另一个进程）
    /// 一律看不见，于是「原子读改写」退化成「原子地基于一份可能过期的快照改写」。
    ///
    /// # 锁的边界：到落盘为止，**不含广播**
    ///
    /// 调用方必须在本方法**返回之后**才 `broadcast_config_changed`。那条广播会
    /// `spawn(switch_mode_with(...))`，而 `switch_mode` 有几条腿回读 `config.current()`；把广播圈进
    /// 临界区（或改成同步等待它）就是把一个会回读配置的调用放进持锁区间。这里是后来者最容易
    /// 好心扩大锁范围的地方。
    ///
    /// # 不重入（静态、全构建配置）
    ///
    /// `write_lock` 是私有字段，临界区内只调用显式的 `*_under_write_lock` 腿，任何被调方都不会
    /// 再次获取它。这是构造性结论，不依赖 debug-only 的 [`reentrancy`] 探针。
    ///
    /// 本方法入口直接调用 `deny_inside_projection`；因此在 `with_current` 闭包里调用 `update` 会在
    /// 获取事务锁之前立刻 panic，而不会等到缓存写锁处自死锁。
    ///
    /// # 锁中毒
    ///
    /// 闭包 panic 会毒化 `write_lock`；此处**恢复**而非传播。落盘是原子的（tmp→rename），
    /// 一次 panic 留下的要么是完整旧文件要么是完整新文件，没有撕裂态；而让一次闭包 panic
    /// 永久锁死此后所有配置写入，比那次 panic 本身糟得多。
    pub fn update<R>(
        &self,
        f: impl FnOnce(&mut Value) -> Decision<R>,
    ) -> Result<(R, Option<Value>), StoreError> {
        self.update_with_cleanup(false, f)
    }

    /// [`Self::update`] 的延迟不可逆清理形态：同一临界区内保留旧配置、生成删除 journal、落新配置。
    pub fn update_deferred_cleanup<R>(
        &self,
        f: impl FnOnce(&mut Value) -> Decision<R>,
    ) -> Result<(R, Option<Value>), StoreError> {
        self.update_with_cleanup(true, f)
    }

    /// 在普通配置差集之外附带显式不可逆动作。用于“重置内置资源”这类配置里没有对应集合实体可供
    /// 自动 diff 的操作；意图与配置仍按同一个 write-ahead 临界区提交，Skip 腿绝不写 journal。
    pub(crate) fn update_with_explicit_deletions<R>(
        &self,
        deletions: Vec<DeferredConfigDeletion>,
        f: impl FnOnce(&mut Value) -> Decision<R>,
    ) -> Result<(R, Option<Value>), StoreError> {
        deny_inside_projection("update_with_explicit_deletions");
        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut cfg = self.load_full_under_write_lock()?;
        let current = cfg.clone();
        match f(&mut cfg) {
            Decision::Skip(r) => Ok((r, None)),
            Decision::Write(r) => {
                let saved = self.save_full_deferred_cleanup_with_explicit_under_write_lock(
                    &current, &cfg, &deletions,
                )?;
                Ok((r, Some(saved)))
            }
        }
    }

    pub fn update_with_cleanup<R>(
        &self,
        defer_cleanup: bool,
        f: impl FnOnce(&mut Value) -> Decision<R>,
    ) -> Result<(R, Option<Value>), StoreError> {
        deny_inside_projection("update_with_cleanup");
        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut cfg = self.load_full_under_write_lock()?;
        let current = defer_cleanup.then(|| cfg.clone());
        match f(&mut cfg) {
            // 不写：闭包对 `cfg` 的改动一律丢弃（它拿的是本方法的局部副本）。
            Decision::Skip(r) => Ok((r, None)),
            Decision::Write(r) => {
                let saved = if let Some(current) = current.as_ref() {
                    self.save_full_deferred_cleanup_under_write_lock(current, &cfg)?
                } else {
                    self.save_full_under_write_lock(&cfg)?
                };
                Ok((r, Some(saved)))
            }
        }
    }

    /// 取单键（currentConfig 投影）。上游 `configManager.get(key)`。
    ///
    /// Polaris 的 get 支持 dotted path（如 'servers'）；此处投影顶层键（与 Polaris ConfigManager.get
    /// 主路径一致，复杂路径交由渲染端处理）。
    pub fn get_value(&self, key: &str) -> Result<Value, StoreError> {
        deny_inside_projection("get_value");
        let cfg = self.current()?;
        Ok(cfg.get(key).cloned().unwrap_or(Value::Null))
    }

    /// 置单键（currentConfig 原地改 + 落盘 + 广播由调用方触发）。上游 `configManager.set(key, value)`。
    #[cfg(test)]
    pub fn set_value(&self, key: &str, value: Value) -> Result<Value, StoreError> {
        deny_inside_projection("set_value");
        let (_, saved) = self.update(|cfg| {
            // 原地替换 / 插入顶层键。
            if let Some(obj) = cfg.as_object_mut() {
                obj.insert(key.to_string(), value);
            }
            Decision::Write(())
        })?;
        saved.ok_or_else(|| StoreError::validation("set_value write unexpectedly skipped"))
    }

    /// 取配置目录下某子路径（mesh state / helper token 等复用）。
    #[must_use]
    pub fn join(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.dir.join(relative)
    }
}

fn collection_ids(config: &Value, key: &str) -> std::collections::HashSet<String> {
    config
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn removed_collection_entries<'a>(
    current: &'a Value,
    incoming: &Value,
    key: &str,
) -> Vec<&'a Value> {
    let next_ids = collection_ids(incoming, key);
    current
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| {
                    item.get("id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| !next_ids.contains(id))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn warp_credentials(server: &Value) -> Option<(&str, &str)> {
    let device = server.get("wireguardSettings")?.get("warpDevice")?;
    Some((
        device.get("deviceId")?.as_str()?,
        device.get("token")?.as_str()?,
    ))
}

fn derive_deferred_deletions(current: &Value, incoming: &Value) -> Vec<DeferredConfigDeletion> {
    let mut out = Vec::new();
    for server in removed_collection_entries(current, incoming, "servers") {
        let Some(server_id) = server.get("id").and_then(Value::as_str) else {
            continue;
        };
        if server
            .get("protocol")
            .and_then(Value::as_str)
            .is_some_and(|protocol| protocol.eq_ignore_ascii_case("tailscale"))
        {
            out.push(DeferredConfigDeletion::TailscaleState {
                server_id: server_id.to_string(),
            });
        }
        if let Some((device_id, token)) = warp_credentials(server) {
            if !device_id.is_empty() && !token.is_empty() {
                out.push(DeferredConfigDeletion::WarpDevice {
                    server_id: server_id.to_string(),
                    device_id: device_id.to_string(),
                    token: token.to_string(),
                });
            }
        }
    }
    for resource in removed_collection_entries(current, incoming, "ruleResources") {
        if let Some(file_name) = resource
            .get("fileName")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
        {
            out.push(DeferredConfigDeletion::RuleResource {
                file_name: file_name.to_string(),
            });
        }
    }
    for preset in removed_collection_entries(current, incoming, "customAppPresets") {
        if let Some(app_id) = preset.get("id").and_then(Value::as_str) {
            out.push(DeferredConfigDeletion::AppIcon {
                app_id: app_id.to_string(),
            });
        }
    }
    out
}

fn deferred_deletion_is_cancelled(entry: &DeferredConfigDeletion, current: &Value) -> bool {
    match entry {
        DeferredConfigDeletion::RuleResource { file_name } => current
            .get("ruleResources")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items.iter().any(|item| {
                    item.get("fileName").and_then(Value::as_str) == Some(file_name.as_str())
                })
            }),
        DeferredConfigDeletion::BuiltinRuleResource { tag, .. } => current
            .get("builtinGeoMeta")
            .and_then(Value::as_object)
            .is_some_and(|metadata| metadata.contains_key(tag)),
        DeferredConfigDeletion::AppIcon { app_id } => {
            let removed_stem = crate::icon_cache::sanitize_stem(app_id);
            collection_ids(current, "customAppPresets")
                .iter()
                .any(|current_id| crate::icon_cache::sanitize_stem(current_id) == removed_stem)
        }
        DeferredConfigDeletion::TailscaleState { server_id } => current
            .get("servers")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items.iter().any(|server| {
                    server.get("id").and_then(Value::as_str) == Some(server_id.as_str())
                        && server
                            .get("protocol")
                            .and_then(Value::as_str)
                            .is_some_and(|protocol| protocol.eq_ignore_ascii_case("tailscale"))
                })
            }),
        DeferredConfigDeletion::WarpDevice {
            device_id, token, ..
        } => current
            .get("servers")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|server| warp_credentials(server) == Some((device_id, token)))
            }),
    }
}

#[cfg(test)]
mod tests;
