//! 系统代理状态 + ProxyMarker（marker 崩溃恢复，维度7 #8 纯逻辑）+ stripSelf / restorePlan。
//!
//! 1:1 移植自 上游 `SystemProxyManager.ts` 的基类 `SystemProxyBase`（marker IO + 防自指 + 恢复计划）。
//! FS 抽象为 [`MarkerFs`] trait —— marker 写/读/清是纯逻辑，测试用内存 mock，生产用真实文件系统。
//!
//! 维度7 #8（marker 崩溃恢复）覆盖在 [`proxy_ops::SystemProxyController::recover_from_marker`](crate::proxy_ops::SystemProxyController::recover_from_marker)：
//! 崩溃后 marker 残留 → 重启读 marker → 清除残留代理（防死端口断网）。本模块提供 marker 读写真值。

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// 系统代理状态。上游 `SystemProxyStatus`。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemProxyStatus {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub http_proxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub https_proxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub socks_proxy: Option<String>,
    /// macOS：该网络服务原有的「绕过代理的主机与域名」清单（`-getproxybypassdomains`）。
    ///
    /// `None` = **没捕获过**（非 mac 平台 / 旧 marker / 读失败），此时 restore **不碰** bypass；
    /// `Some(vec![])` = 捕获到「一条都没有」，restore 需写 `Empty` 哨兵清空。两者必须可分辨 ——
    /// 混同会把「没读到」当成「用户本来就是空的」，反而把人家的清单清掉。
    ///
    /// 为什么需要它：enable 会对**每个**网络服务下发 `-setproxybypassdomains`，而该子命令是
    /// **整表覆盖**（`networksetup(8)` 措辞 "Set ... **to** `<domain1>` \[domain2\]..."，另给 `Empty`
    /// 哨兵专用于清空 ⇒ 若是追加，需要的是 remove 动词）。不捕获就没法还原，用户自定义的
    /// 内网域名会被 Polaris 的默认清单永久替换掉。
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bypass_domains: Option<Vec<String>>,
}

impl SystemProxyStatus {
    /// 任一代理协议非空即视为有实际代理服务器配置（用于恢复决策 / 状态判空）。
    pub fn has_any_proxy(&self) -> bool {
        self.http_proxy.is_some() || self.https_proxy.is_some() || self.socks_proxy.is_some()
    }
}

/// macOS 单个网络服务的完整代理配置快照。
///
/// `configuration_plist` 保存 SystemConfiguration 的完整 Proxies property-list，而不是只保存
/// [`SystemProxyStatus`] 的三协议投影。后者只用于自指判定与诊断；真正恢复必须保留 PAC、自动发现、
/// 例外清单及系统未来新增字段。`service_id` 是稳定键，显示名只作日志，不参与匹配。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacProxyServiceSnapshot {
    pub service_id: String,
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub service_enabled: bool,
    #[serde(default)]
    pub had_proxy_protocol: bool,
    #[serde(default)]
    pub protocol_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub configuration_plist: Option<String>,
    #[serde(default)]
    pub status: SystemProxyStatus,
    /// Polaris 会修改的 Proxies 字典成员的 exact 载体。`None` 只表示旧 marker；V2 macOS
    /// 事务必须携带该字段，所有权比较与恢复只消费这里列出的成员，不覆盖 PAC/自动发现等未触字段。
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub touched: Option<MacProxyTouchedSnapshot>,
    /// 捕获值指向 Polaris 自己时不得原样恢复死端口；恢复腿改为只关闭静态三协议代理。
    #[serde(default)]
    pub clear_on_restore: bool,
}

/// macOS Proxies protocol 中 Polaris 实际触碰的成员。
///
/// 每个成员保存 absent 或单值 property-list XML；这既保留空字符串、0、空数组，也保留将来系统
/// 写入的其它 CF 类型。protocol presence/enabled 放在同一载体，确保 helper 能在持锁后完成
/// compare-and-apply / compare-and-restore。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacProxyTouchedSnapshot {
    pub protocol_present: bool,
    pub protocol_enabled: bool,
    #[serde(default)]
    pub http_enabled: MacProxyPropertyValue,
    #[serde(default)]
    pub http_host: MacProxyPropertyValue,
    #[serde(default)]
    pub http_port: MacProxyPropertyValue,
    #[serde(default)]
    pub https_enabled: MacProxyPropertyValue,
    #[serde(default)]
    pub https_host: MacProxyPropertyValue,
    #[serde(default)]
    pub https_port: MacProxyPropertyValue,
    #[serde(default)]
    pub socks_enabled: MacProxyPropertyValue,
    #[serde(default)]
    pub socks_host: MacProxyPropertyValue,
    #[serde(default)]
    pub socks_port: MacProxyPropertyValue,
    #[serde(default)]
    pub exceptions: MacProxyPropertyValue,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "plist", rename_all = "camelCase")]
pub enum MacProxyPropertyValue {
    #[default]
    Absent,
    PropertyListXml(String),
}

/// enable 前的跨平台代理快照。
///
/// `fallback` 保持三平台旧 marker 的投影；各平台 exact 数据分别用强类型字段承载。
/// 当前 common controller 尚未接 Linux/Windows exact，故旧路径两字段均保持 `None`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyOriginalSettings {
    pub fallback: Option<SystemProxyStatus>,
    pub mac_services: Vec<MacProxyServiceSnapshot>,
    /// Linux 九键 exact 快照；当前 common controller 尚未接线，旧路径保持 `None`。
    pub linux_gsettings: Option<LinuxGSettingsSnapshot>,
    /// Windows Internet Settings 三值 exact 快照；当前 common controller 尚未接线。
    pub windows_registry: Option<WindowsProxyRegistrySnapshot>,
}

impl ProxyOriginalSettings {
    pub fn from_status(status: SystemProxyStatus) -> Self {
        Self {
            fallback: Some(status),
            mac_services: Vec::new(),
            linux_gsettings: None,
            windows_registry: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.fallback.is_none()
            && self.mac_services.is_empty()
            && self.linux_gsettings.is_none()
            && self.windows_registry.is_none()
    }

    /// 丢弃所有指向当前/上一轮 Polaris 端口的捕获值，避免停止后恢复死端口。
    /// 若上一份 marker 保存了同一 service ID 的真实原值，则优先沿用它，防重复 enable 覆盖恢复锚点。
    pub fn strip_self(
        mut self,
        address: &str,
        http_port: u16,
        socks_port: u16,
        marker_our_host_port: Option<&str>,
        previous_original: Option<&Self>,
    ) -> Self {
        let http = format!("{address}:{http_port}");
        let socks = format!("{address}:{socks_port}");
        let points_to_us = |status: &SystemProxyStatus| {
            status.enabled
                && [&status.http_proxy, &status.https_proxy, &status.socks_proxy]
                    .into_iter()
                    .flatten()
                    .any(|proxy| {
                        proxy == &http
                            || proxy == &socks
                            || marker_our_host_port.is_some_and(|marker| proxy == marker)
                    })
        };

        self.fallback = self.fallback.take().and_then(|status| {
            if !points_to_us(&status) {
                return Some(status);
            }
            previous_original
                .and_then(|previous| previous.fallback.as_ref())
                .filter(|previous| !points_to_us(previous))
                .cloned()
        });
        for service in &mut self.mac_services {
            if points_to_us(&service.status) {
                if let Some(previous) = previous_original
                    .and_then(|previous| {
                        previous
                            .mac_services
                            .iter()
                            .find(|previous| previous.service_id == service.service_id)
                    })
                    .filter(|previous| !points_to_us(&previous.status))
                {
                    *service = previous.clone();
                    continue;
                }
                service.clear_on_restore = true;
                service.configuration_plist = None;
                service.status = SystemProxyStatus::default();
            }
        }
        self
    }
}

/// Linux GNOME system proxy 的九键原始 GVariant 快照。
///
/// 每个值均保存 `gsettings get` 的 canonical raw（不保存 set argv 的输入形态），从而能够精确
/// 还原 dormant host/port、`http.enabled`、`ignore-hosts` 与 `mode`。字段顺序的唯一真值在
/// `proxy_ops::linux::LINUX_GSETTINGS_KEYS`；本类型只承载强类型字段，避免无约束 map。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxGSettingsSnapshot {
    pub http_host: String,
    pub http_port: String,
    pub http_enabled: String,
    pub https_host: String,
    pub https_port: String,
    pub socks_host: String,
    pub socks_port: String,
    pub ignore_hosts: String,
    pub mode: String,
}

impl LinuxGSettingsSnapshot {
    pub(crate) fn raw_values(&self) -> [&str; 9] {
        [
            &self.http_host,
            &self.http_port,
            &self.http_enabled,
            &self.https_host,
            &self.https_port,
            &self.socks_host,
            &self.socks_port,
            &self.ignore_hosts,
            &self.mode,
        ]
    }
}

/// Windows `REG_SZ` 的 exact 存在性与原值。
///
/// 注册表中「值不存在」「值存在但为空串」「值存在且非空」是三种不同状态；恢复时
/// 必须分别执行 delete / set-empty / set-value，不得折叠。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "camelCase")]
pub enum WindowsRegistryStringValue {
    #[default]
    Absent,
    PresentEmpty,
    /// 该变体只承载非空值；捕获边界必须把空串归入 [`Self::PresentEmpty`]。
    PresentValue(String),
}

/// Windows `REG_DWORD` 的 exact 存在性与原始 `u32`。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "camelCase")]
pub enum WindowsRegistryDwordValue {
    #[default]
    Absent,
    PresentValue(u32),
}

/// Windows `HKCU\\...\\Internet Settings` 中 Polaris 会修改的三个值的 exact 快照。
///
/// `ProxyEnable` 保留原始 DWORD（不只折成 bool）；两个字符串保留 absent/empty/value 三态。
/// 本类型只承载真值，捕获/恢复接线由后续 common controller 事务批次完成。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsProxyRegistrySnapshot {
    pub proxy_server: WindowsRegistryStringValue,
    pub proxy_override: WindowsRegistryStringValue,
    pub proxy_enable: WindowsRegistryDwordValue,
}

/// Marker V2 的一侧平台快照。
///
/// `projection` 保留现有三协议投影；三平台 exact 数据各用强类型可选字段，不把平台数据塞进
/// 无约束的 JSON 对象。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyTransactionSnapshot {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub projection: Option<SystemProxyStatus>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub mac_services: Vec<MacProxyServiceSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub linux_gsettings: Option<LinuxGSettingsSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub windows_registry: Option<WindowsProxyRegistrySnapshot>,
}

impl ProxyTransactionSnapshot {
    #[must_use]
    pub fn from_original(settings: &ProxyOriginalSettings) -> Self {
        Self {
            projection: settings.fallback.clone(),
            mac_services: settings.mac_services.clone(),
            linux_gsettings: settings.linux_gsettings.clone(),
            windows_registry: settings.windows_registry.clone(),
        }
    }

    pub(crate) fn original_settings(&self) -> Option<ProxyOriginalSettings> {
        let settings = ProxyOriginalSettings {
            fallback: self.projection.clone(),
            mac_services: self.mac_services.clone(),
            linux_gsettings: self.linux_gsettings.clone(),
            windows_registry: self.windows_registry.clone(),
        };
        (!settings.is_empty()).then_some(settings)
    }
}

/// Marker V2 的持久事务阶段。旧 marker 没有该字段，按既有语义视作 `Owned`。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProxyMarkerPhase {
    Applying,
    #[default]
    Owned,
    Restoring,
    RestoredPendingClear,
}

/// marker 文件落地结构。上游 `writeMarker` 写入的 JSON。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyMarkerData {
    /// 我们的代理 `address:port`（恢复/检测自指用）。
    pub our_host_port: String,
    /// 写入时间戳（ms，上游 `Date.now()`）。用于诊断，不参与判定。
    #[serde(default)]
    pub at: u64,
    /// Marker V2 的事务身份。旧 marker 缺失时为 `None`，不得参与 CAS 更新/删除。
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub txn_id: Option<String>,
    /// 平台 mutation plan 版本；0 表示旧 marker。
    #[serde(default)]
    pub plan_version: u32,
    /// 多键写事务所处阶段；旧 marker 默认按既有 owned marker 处理。
    #[serde(default)]
    pub phase: ProxyMarkerPhase,
    /// V2 envelope 内的诊断投影。strict controller **绝不**把这三项当恢复 authority；旧 reader
    /// 看不到不兼容 envelope，因此也绝不能据此发起有损恢复。
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub original: Option<ProxyTransactionSnapshot>,
    /// 本轮第一笔 OS 写入前的即时状态。它与 `original` 分离：System→System 重接管时，
    /// `original` 始终保留最早可恢复锚点，而 `apply_base` 描述本轮允许出现的写入前缀。
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub apply_base: Option<ProxyTransactionSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub applied: Option<ProxyTransactionSnapshot>,
    /// V2 strict 恢复唯一真值。三项只存在于不兼容的 `systemProxyTxnV2` envelope 内。
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exact_original: Option<ProxyTransactionSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exact_apply_base: Option<ProxyTransactionSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exact_applied: Option<ProxyTransactionSnapshot>,
    /// enable 前的原始代理快照（关机跨会话恢复用；Linux 写入，Win/macOS 可选）。
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub original_settings: Option<SystemProxyStatus>,
    /// macOS 原生事务的逐服务完整快照。旧 marker 没有该字段，默认空并走既有回退。
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub mac_service_settings: Vec<MacProxyServiceSnapshot>,
}

/// 当前版本唯一支持的精确系统代理 mutation plan。
pub const PROXY_TRANSACTION_PLAN_VERSION: u32 = 1;

const PROXY_TRANSACTION_ENVELOPE_KEY: &str = "systemProxyTxnV2";

/// marker 的严格读取结果。损坏、未来版本和 IO 错误都不能再折成“不存在”，否则控制器会在
/// 不知道旧事务归属的情况下开启新事务并覆盖恢复锚点。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyMarkerRead {
    Missing,
    Legacy(ProxyMarkerData),
    CurrentValidated(ProxyMarkerData),
    UnsupportedVersion(u32),
    Invalid(String),
    IoError(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMarkerMutationOutcome {
    Updated,
    Mismatch,
    PersistFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyMarkerBeginOutcome {
    Begun(ProxyMarkerData),
    Occupied(ProxyMarkerRead),
    PersistFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyMarkerReplaceOutcome {
    Replaced(Box<ProxyMarkerData>),
    Mismatch,
    PersistFailed,
}

impl ProxyMarkerData {
    pub fn original_snapshot(&self) -> Option<ProxyOriginalSettings> {
        if let Some(snapshot) = self
            .original
            .as_ref()
            .and_then(ProxyTransactionSnapshot::original_settings)
        {
            return Some(snapshot);
        }
        let snapshot = ProxyOriginalSettings {
            fallback: self.original_settings.clone(),
            mac_services: self.mac_service_settings.clone(),
            linux_gsettings: None,
            windows_registry: None,
        };
        (!snapshot.is_empty()).then_some(snapshot)
    }
}

/// FS 抽象：marker 文件读写。生产用真实文件系统，测试用内存 mock。
/// read 在文件不存在 / 内容损坏时返回 None（不抛）；write/rm 返回 IO 结果，由上层按平台可逆性决策。
pub trait MarkerFs {
    /// 写 marker 文件（覆盖）。失败返回 Err；普通路径可降级，需要完整快照的路径必须中止接管。
    fn write_marker(&self, path: &str, data: &str) -> std::io::Result<()>;
    /// 读 marker 文件全文。不存在 → Ok(None)；读失败 → Ok(None)（Polaris catch → null）。
    fn read_marker(&self, path: &str) -> Option<String>;
    /// 严格读取入口。默认适配旧测试替身；生产实现覆盖后区分 NotFound 与其它 IO 错误。
    fn read_marker_checked(&self, path: &str) -> std::io::Result<Option<String>> {
        Ok(self.read_marker(path))
    }
    /// 删 marker 文件（force：不存在不报错）。失败返回 Err。
    fn remove_marker(&self, path: &str) -> std::io::Result<()>;

    /// 获取覆盖整段 read-check-write/remove 的跨进程排他锁。内存替身默认 no-op；生产文件系统
    /// 必须锁住稳定 sibling lockfile，且锁竞争只能有界等待。
    fn acquire_marker_mutation_lock(
        &self,
        _path: &str,
    ) -> std::io::Result<MarkerMutationLockGuard> {
        Ok(MarkerMutationLockGuard::default())
    }
}

/// marker mutation 的 RAII 锁。`File` drop 会在正常退出、panic 与进程崩溃时由 OS 释放锁；
/// lockfile 本身保持稳定，不能随 marker 的 rename/remove 删除。
#[derive(Debug, Default)]
pub struct MarkerMutationLockGuard {
    _file: Option<std::fs::File>,
}

/// [`MarkerFs`] 的生产实现：真实文件系统（同步 API，文件极小）。
///
/// 语义继承上游 `SystemProxyBase` 的同步 marker IO，并强化崩溃一致性：
/// - `write`：父目录不存在先建；三平台均在同目录写临时文件、同步文件并原子替换，确保不会向读者
///   暴露截断/半写内容，返回成功后才允许修改系统。
/// - `read`：不存在 / 读失败 → `None`（上游 catch → null；ENOENT 与 JSON 损坏一视同仁）。
/// - `remove`：**不存在不报错**（上游 `fs.rmSync(path, { force: true })`）—— 这是
///   [`crate::proxy_ops::SystemProxyController::ensure_cleared`] 幂等性的地基：重复清理必须静默成功。
///
/// **同步 API 是有意的**：marker 清理要能用在退出/崩溃兜底这类同步路径上（上游注释明写
/// 「可安全用于 process 'exit' 等同步退出路径」）。
#[derive(Debug, Clone, Copy, Default)]
pub struct StdMarkerFs;

impl MarkerFs for StdMarkerFs {
    fn write_marker(&self, path: &str, data: &str) -> std::io::Result<()> {
        use std::io::Write;
        use std::sync::atomic::{AtomicU64, Ordering};

        let path = std::path::Path::new(path);
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        // userData 目录首次运行可能不存在；已存在则 no-op。
        std::fs::create_dir_all(parent)?;

        // 同目录 create-new temp → fsync → rename：读者只能看到旧 marker 或完整新 marker，phase
        // 更新绝不 truncate 现有恢复锚点。Rust 1.98 离线 std 文档确认 `rename` 在 Windows 使用
        // MoveFileExW（并回退 SetFileInformationByHandle），目标为普通文件时支持替换。
        static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let file_name = path.file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "marker 路径缺少文件名")
        })?;
        let mut opened = None;
        for _ in 0..16 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let temp_name = format!(
                ".{}.{}.{}.tmp",
                file_name.to_string_lossy(),
                std::process::id(),
                sequence
            );
            let temp_path = parent.join(temp_name);
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
            {
                Ok(file) => {
                    opened = Some((temp_path, file));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        let (temp_path, mut file) = opened.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "无法分配唯一的 marker 临时文件",
            )
        })?;
        let written = file
            .write_all(data.as_bytes())
            .and_then(|()| file.sync_all());
        drop(file);
        let result = written.and_then(|()| std::fs::rename(&temp_path, path));
        if result.is_err() {
            let _ = std::fs::remove_file(&temp_path);
        }
        result
    }

    fn read_marker(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    fn read_marker_checked(&self, path: &str) -> std::io::Result<Option<String>> {
        match std::fs::read_to_string(path) {
            Ok(raw) => Ok(Some(raw)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn remove_marker(&self, path: &str) -> std::io::Result<()> {
        match std::fs::remove_file(path) {
            // force 语义：不存在视为已清除（幂等）。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    fn acquire_marker_mutation_lock(&self, path: &str) -> std::io::Result<MarkerMutationLockGuard> {
        const ATTEMPTS: usize = 20;
        const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(10);

        let marker_path = std::path::Path::new(path);
        let parent = marker_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        std::fs::create_dir_all(parent)?;
        let file_name = marker_path.file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "marker 路径缺少文件名")
        })?;
        let lock_path = parent.join(format!("{}.lock", file_name.to_string_lossy()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;

        for attempt in 0..ATTEMPTS {
            match file.try_lock() {
                Ok(()) => {
                    return Ok(MarkerMutationLockGuard { _file: Some(file) });
                }
                Err(std::fs::TryLockError::WouldBlock) if attempt + 1 < ATTEMPTS => {
                    std::thread::sleep(RETRY_DELAY);
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "system proxy marker lock is busy",
                    ));
                }
                Err(std::fs::TryLockError::Error(error)) => return Err(error),
            }
        }
        unreachable!("bounded marker lock loop always returns")
    }
}

/// ProxyMarker：marker 写/读/清 + 防自指判定。纯逻辑（FS + marker 路径注入）。
/// 上游 `SystemProxyBase` 的 marker 部分抽离。
pub struct ProxyMarker<Fs: MarkerFs> {
    fs: Fs,
    path: String,
}

// `ProxyMarker` 可能由同一进程里的不同 controller 实例指向同一路径；先用进程锁串行化本进程，
// 再由 MarkerFs 的稳定 sibling lockfile 串行化跨进程 mutation。
static PROXY_MARKER_MUTATION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_marker_mutation() -> std::sync::MutexGuard<'static, ()> {
    PROXY_MARKER_MUTATION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotKind {
    Projection,
    Mac,
    Linux,
    Windows,
}

fn snapshot_kind(snapshot: &ProxyTransactionSnapshot) -> Option<SnapshotKind> {
    let exact = usize::from(!snapshot.mac_services.is_empty())
        + usize::from(snapshot.linux_gsettings.is_some())
        + usize::from(snapshot.windows_registry.is_some());
    if exact > 1 {
        return None;
    }
    if !snapshot.mac_services.is_empty() {
        Some(SnapshotKind::Mac)
    } else if snapshot.linux_gsettings.is_some() {
        Some(SnapshotKind::Linux)
    } else if snapshot.windows_registry.is_some() {
        Some(SnapshotKind::Windows)
    } else {
        snapshot
            .projection
            .as_ref()
            .map(|_| SnapshotKind::Projection)
    }
}

fn parse_plist_xml(xml: &str) -> Result<plist::Value, plist::Error> {
    plist::Value::from_reader_xml(xml.as_bytes())
}

fn touched_properties(touched: &MacProxyTouchedSnapshot) -> [&MacProxyPropertyValue; 10] {
    [
        &touched.http_enabled,
        &touched.http_host,
        &touched.http_port,
        &touched.https_enabled,
        &touched.https_host,
        &touched.https_port,
        &touched.socks_enabled,
        &touched.socks_host,
        &touched.socks_port,
        &touched.exceptions,
    ]
}

/// macOS service ID 的共享 validator。所有 snapshot 与 ID-only helper payload 都复用这里的
/// 数量、长度、控制字符与唯一性约束。
pub(crate) fn validate_mac_service_ids<'a>(
    ids: impl IntoIterator<Item = &'a str>,
) -> Result<std::collections::BTreeSet<&'a str>, String> {
    const MAX_SERVICES: usize = 64;
    const MAX_ID_BYTES: usize = 256;

    let mut unique = std::collections::BTreeSet::new();
    for id in ids {
        if unique.len() == MAX_SERVICES {
            return Err(format!(
                "macOS 系统代理事务服务数非法：{}",
                MAX_SERVICES + 1
            ));
        }
        if id.is_empty()
            || id.len() > MAX_ID_BYTES
            || id.chars().any(char::is_control)
            || !unique.insert(id)
        {
            return Err("macOS 系统代理事务含非法或重复 service ID".into());
        }
    }
    if unique.is_empty() {
        return Err("macOS 系统代理事务服务数非法：0".into());
    }
    Ok(unique)
}

/// macOS exact snapshot 的唯一结构 validator。`paired` 存在时还要求两侧承载完全相同的
/// 稳定 service ID 集；Vec 枚举顺序不是所有权。marker、helper compare/V2 payload 及消费捕获范围的
/// legacy 入口都必须复用此 API；调用方不得各自挑字段验证。
pub(crate) fn validate_mac_proxy_snapshots(
    snapshots: &[MacProxyServiceSnapshot],
    paired: Option<&[MacProxyServiceSnapshot]>,
) -> Result<(), String> {
    let ids = validate_mac_service_ids(
        snapshots
            .iter()
            .map(|snapshot| snapshot.service_id.as_str()),
    )?;
    for service in snapshots {
        if service.service_name.is_empty()
            || service.service_name.len() > 1024
            || service.service_name.contains(['\0', '\r', '\n'])
        {
            return Err(format!(
                "macOS 系统代理事务服务名非法：{}",
                service.service_id
            ));
        }
        if !service.service_enabled {
            return Err(format!(
                "macOS 系统代理事务包含非 enabled 服务：{}",
                service.service_id
            ));
        }
        let touched = service
            .touched
            .as_ref()
            .ok_or_else(|| format!("macOS 服务 {} 缺少 touched 快照", service.service_id))?;
        if service.had_proxy_protocol != touched.protocol_present
            || service.protocol_enabled != touched.protocol_enabled
        {
            return Err(format!(
                "macOS 服务 {} 的 protocol 元数据与 touched 不一致",
                service.service_id
            ));
        }
        let properties = touched_properties(touched);
        if !touched.protocol_present {
            if touched.protocol_enabled
                || service.configuration_plist.is_some()
                || service.clear_on_restore
                || service.status != SystemProxyStatus::default()
                || properties
                    .iter()
                    .any(|value| !matches!(value, MacProxyPropertyValue::Absent))
            {
                return Err(format!(
                    "macOS 服务 {} 的 absent protocol 快照非法",
                    service.service_id
                ));
            }
            continue;
        }
        for value in properties {
            if let MacProxyPropertyValue::PropertyListXml(xml) = value {
                if parse_plist_xml(xml).is_err() {
                    return Err(format!(
                        "macOS 服务 {} 含不可解析的 property-list XML",
                        service.service_id
                    ));
                }
            }
        }
        if service.clear_on_restore {
            // 防自指快照的唯一合法 NULL 形态：protocol 确实存在，但恢复动作只能关闭静态三协议。
            if service.configuration_plist.is_some()
                || service.status != SystemProxyStatus::default()
            {
                return Err(format!(
                    "macOS 服务 {} 的 clear_on_restore 组合非法",
                    service.service_id
                ));
            }
        } else {
            let configuration = service.configuration_plist.as_deref().ok_or_else(|| {
                format!(
                    "macOS 服务 {} 的 present protocol configuration 为 NULL",
                    service.service_id
                )
            })?;
            if !matches!(
                parse_plist_xml(configuration),
                Ok(plist::Value::Dictionary(_))
            ) {
                return Err(format!(
                    "macOS 服务 {} 含不可解析的 configuration plist",
                    service.service_id
                ));
            }
        }
    }
    if let Some(paired) = paired {
        validate_mac_proxy_snapshots(paired, None)?;
        let paired_ids =
            validate_mac_service_ids(paired.iter().map(|snapshot| snapshot.service_id.as_str()))?;
        if ids != paired_ids {
            return Err("macOS 系统代理快照的 service ID 集不一致".into());
        }
    }
    Ok(())
}

fn valid_transaction_snapshot(snapshot: &ProxyTransactionSnapshot) -> bool {
    let Some(kind) = snapshot_kind(snapshot) else {
        return false;
    };
    if snapshot.projection.is_none() {
        return false;
    }
    match kind {
        // Current V2 is deliberately exact-only. Projection remains serialized solely for legacy
        // diagnostics/backward readers and must never become a recovery authority.
        SnapshotKind::Projection => false,
        SnapshotKind::Mac => validate_mac_proxy_snapshots(&snapshot.mac_services, None).is_ok(),
        SnapshotKind::Linux => snapshot
            .linux_gsettings
            .as_ref()
            .is_some_and(|linux| linux.raw_values().into_iter().all(|raw| !raw.is_empty())),
        SnapshotKind::Windows => snapshot.windows_registry.as_ref().is_some_and(|windows| {
            [windows.proxy_server.clone(), windows.proxy_override.clone()]
                .into_iter()
                .all(|value| match value {
                    WindowsRegistryStringValue::PresentValue(value) => !value.is_empty(),
                    WindowsRegistryStringValue::Absent
                    | WindowsRegistryStringValue::PresentEmpty => true,
                })
        }),
    }
}

fn valid_transaction_snapshot_pair(
    left: &ProxyTransactionSnapshot,
    right: &ProxyTransactionSnapshot,
) -> bool {
    match (snapshot_kind(left), snapshot_kind(right)) {
        (Some(SnapshotKind::Mac), Some(SnapshotKind::Mac)) => {
            validate_mac_proxy_snapshots(&left.mac_services, Some(&right.mac_services)).is_ok()
        }
        (left_kind, right_kind) => left_kind.is_some() && left_kind == right_kind,
    }
}

fn downgrade_projection(snapshot: &ProxyTransactionSnapshot) -> ProxyTransactionSnapshot {
    ProxyTransactionSnapshot {
        projection: snapshot.projection.clone(),
        ..Default::default()
    }
}

fn current_marker(
    our_host_port: &str,
    original: ProxyTransactionSnapshot,
    apply_base: ProxyTransactionSnapshot,
    applied: ProxyTransactionSnapshot,
) -> ProxyMarkerData {
    ProxyMarkerData {
        our_host_port: our_host_port.to_owned(),
        at: now_ms(),
        txn_id: Some(new_proxy_txn_id()),
        plan_version: PROXY_TRANSACTION_PLAN_VERSION,
        phase: ProxyMarkerPhase::Applying,
        original_settings: original.projection.clone(),
        // V2 mac exact snapshot 绝不双写进 legacy full-plist 字段。
        mac_service_settings: Vec::new(),
        original: Some(downgrade_projection(&original)),
        apply_base: Some(downgrade_projection(&apply_base)),
        applied: Some(downgrade_projection(&applied)),
        exact_original: Some(original),
        exact_apply_base: Some(apply_base),
        exact_applied: Some(applied),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProxyMarkerEnvelope<'a> {
    system_proxy_txn_v2: &'a ProxyMarkerData,
}

impl<Fs: MarkerFs> ProxyMarker<Fs> {
    pub fn new(fs: Fs, path: impl Into<String>) -> Self {
        Self {
            fs,
            path: path.into(),
        }
    }

    /// marker 文件路径。
    pub fn path(&self) -> &str {
        &self.path
    }

    fn legacy_data(
        our_host_port: &str,
        original: Option<&ProxyOriginalSettings>,
    ) -> ProxyMarkerData {
        ProxyMarkerData {
            our_host_port: our_host_port.to_owned(),
            at: now_ms(),
            txn_id: None,
            plan_version: 0,
            phase: ProxyMarkerPhase::Owned,
            original: None,
            apply_base: None,
            applied: None,
            exact_original: None,
            exact_apply_base: None,
            exact_applied: None,
            original_settings: original.and_then(|snapshot| snapshot.fallback.clone()),
            mac_service_settings: original
                .map(|snapshot| snapshot.mac_services.clone())
                .unwrap_or_default(),
        }
    }

    /// legacy CLI 事务也必须以 whole-marker CAS 创建，不能覆盖严格读取失败或并发新事务。
    pub fn begin_legacy_if_absent(
        &self,
        our_host_port: &str,
        original: Option<&ProxyOriginalSettings>,
    ) -> ProxyMarkerBeginOutcome {
        let _process_guard = lock_marker_mutation();
        let Ok(_storage_guard) = self.fs.acquire_marker_mutation_lock(&self.path) else {
            return ProxyMarkerBeginOutcome::PersistFailed;
        };
        let read = self.read_checked_unlocked();
        if read != ProxyMarkerRead::Missing {
            return ProxyMarkerBeginOutcome::Occupied(read);
        }
        let data = Self::legacy_data(our_host_port, original);
        if our_host_port.is_empty() {
            return ProxyMarkerBeginOutcome::PersistFailed;
        }
        if self.write_json_unlocked(&data) {
            ProxyMarkerBeginOutcome::Begun(data)
        } else {
            ProxyMarkerBeginOutcome::PersistFailed
        }
    }

    /// 仅在 marker 确实不存在时创建 current V2 Applying intent。
    pub fn begin_if_absent(
        &self,
        our_host_port: &str,
        original: &ProxyTransactionSnapshot,
        apply_base: &ProxyTransactionSnapshot,
        applied: &ProxyTransactionSnapshot,
    ) -> ProxyMarkerBeginOutcome {
        let _process_guard = lock_marker_mutation();
        let Ok(_storage_guard) = self.fs.acquire_marker_mutation_lock(&self.path) else {
            return ProxyMarkerBeginOutcome::PersistFailed;
        };
        let read = self.read_checked_unlocked();
        if read != ProxyMarkerRead::Missing {
            return ProxyMarkerBeginOutcome::Occupied(read);
        }
        if our_host_port.is_empty()
            || !valid_transaction_snapshot(original)
            || !valid_transaction_snapshot(apply_base)
            || !valid_transaction_snapshot(applied)
            || snapshot_kind(original) != snapshot_kind(apply_base)
            || snapshot_kind(original) != snapshot_kind(applied)
            || !valid_transaction_snapshot_pair(original, apply_base)
            || !valid_transaction_snapshot_pair(apply_base, applied)
        {
            return ProxyMarkerBeginOutcome::PersistFailed;
        }
        let data = current_marker(
            our_host_port,
            original.clone(),
            apply_base.clone(),
            applied.clone(),
        );
        if self.write_json_unlocked(&ProxyMarkerEnvelope {
            system_proxy_txn_v2: &data,
        }) {
            ProxyMarkerBeginOutcome::Begun(data)
        } else {
            ProxyMarkerBeginOutcome::PersistFailed
        }
    }

    /// System→System 目标变化：只替换仍为同一 Owned 事务的 marker，并保留最早 original。
    pub fn replace_if_current(
        &self,
        old_txn_id: &str,
        our_host_port: &str,
        apply_base: &ProxyTransactionSnapshot,
        applied: &ProxyTransactionSnapshot,
    ) -> ProxyMarkerReplaceOutcome {
        let _process_guard = lock_marker_mutation();
        let Ok(_storage_guard) = self.fs.acquire_marker_mutation_lock(&self.path) else {
            return ProxyMarkerReplaceOutcome::PersistFailed;
        };
        let ProxyMarkerRead::CurrentValidated(current) = self.read_checked_unlocked() else {
            return ProxyMarkerReplaceOutcome::Mismatch;
        };
        if current.txn_id.as_deref() != Some(old_txn_id) || current.phase != ProxyMarkerPhase::Owned
        {
            return ProxyMarkerReplaceOutcome::Mismatch;
        }
        let Some(exact_original) = current.exact_original else {
            return ProxyMarkerReplaceOutcome::Mismatch;
        };
        if our_host_port.is_empty()
            || !valid_transaction_snapshot(apply_base)
            || !valid_transaction_snapshot(applied)
            || snapshot_kind(&exact_original) != snapshot_kind(apply_base)
            || snapshot_kind(&exact_original) != snapshot_kind(applied)
            || !valid_transaction_snapshot_pair(&exact_original, apply_base)
            || !valid_transaction_snapshot_pair(apply_base, applied)
        {
            return ProxyMarkerReplaceOutcome::Mismatch;
        }
        let replacement = current_marker(
            our_host_port,
            exact_original,
            apply_base.clone(),
            applied.clone(),
        );
        if self.write_json_unlocked(&ProxyMarkerEnvelope {
            system_proxy_txn_v2: &replacement,
        }) {
            ProxyMarkerReplaceOutcome::Replaced(Box::new(replacement))
        } else {
            ProxyMarkerReplaceOutcome::PersistFailed
        }
    }

    pub fn update_current_phase(
        &self,
        txn_id: &str,
        expected: ProxyMarkerPhase,
        next: ProxyMarkerPhase,
    ) -> ProxyMarkerMutationOutcome {
        let _process_guard = lock_marker_mutation();
        let Ok(_storage_guard) = self.fs.acquire_marker_mutation_lock(&self.path) else {
            return ProxyMarkerMutationOutcome::PersistFailed;
        };
        let ProxyMarkerRead::CurrentValidated(mut current) = self.read_checked_unlocked() else {
            return ProxyMarkerMutationOutcome::Mismatch;
        };
        if current.txn_id.as_deref() != Some(txn_id) || current.phase != expected {
            return ProxyMarkerMutationOutcome::Mismatch;
        }
        if !matches!(
            (expected, next),
            (ProxyMarkerPhase::Applying, ProxyMarkerPhase::Owned)
                | (ProxyMarkerPhase::Applying, ProxyMarkerPhase::Restoring)
                | (ProxyMarkerPhase::Owned, ProxyMarkerPhase::Restoring)
                | (
                    ProxyMarkerPhase::Restoring,
                    ProxyMarkerPhase::RestoredPendingClear
                )
        ) {
            return ProxyMarkerMutationOutcome::Mismatch;
        }
        current.phase = next;
        if self.write_json_unlocked(&ProxyMarkerEnvelope {
            system_proxy_txn_v2: &current,
        }) {
            ProxyMarkerMutationOutcome::Updated
        } else {
            ProxyMarkerMutationOutcome::PersistFailed
        }
    }

    pub fn clear_current(
        &self,
        txn_id: &str,
        expected: ProxyMarkerPhase,
    ) -> ProxyMarkerMutationOutcome {
        let _process_guard = lock_marker_mutation();
        let Ok(_storage_guard) = self.fs.acquire_marker_mutation_lock(&self.path) else {
            return ProxyMarkerMutationOutcome::PersistFailed;
        };
        let ProxyMarkerRead::CurrentValidated(current) = self.read_checked_unlocked() else {
            return ProxyMarkerMutationOutcome::Mismatch;
        };
        if current.txn_id.as_deref() != Some(txn_id) || current.phase != expected {
            return ProxyMarkerMutationOutcome::Mismatch;
        }
        if self.fs.remove_marker(&self.path).is_ok() {
            ProxyMarkerMutationOutcome::Updated
        } else {
            ProxyMarkerMutationOutcome::PersistFailed
        }
    }

    /// legacy 没有 txn_id；只能把读到的整份 marker 当 CAS token，绝不按 host:port 模糊删除。
    pub fn clear_legacy_if_current(
        &self,
        expected: &ProxyMarkerData,
    ) -> ProxyMarkerMutationOutcome {
        let _process_guard = lock_marker_mutation();
        let Ok(_storage_guard) = self.fs.acquire_marker_mutation_lock(&self.path) else {
            return ProxyMarkerMutationOutcome::PersistFailed;
        };
        let ProxyMarkerRead::Legacy(current) = self.read_checked_unlocked() else {
            return ProxyMarkerMutationOutcome::Mismatch;
        };
        if &current != expected {
            return ProxyMarkerMutationOutcome::Mismatch;
        }
        if self.fs.remove_marker(&self.path).is_ok() {
            ProxyMarkerMutationOutcome::Updated
        } else {
            ProxyMarkerMutationOutcome::PersistFailed
        }
    }

    pub fn read_checked(&self) -> ProxyMarkerRead {
        let _guard = lock_marker_mutation();
        self.read_checked_unlocked()
    }

    fn read_checked_unlocked(&self) -> ProxyMarkerRead {
        let raw = match self.fs.read_marker_checked(&self.path) {
            Ok(None) => return ProxyMarkerRead::Missing,
            Ok(Some(raw)) => raw,
            Err(error) => return ProxyMarkerRead::IoError(error.to_string()),
        };
        let value: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(value) => value,
            Err(error) => return ProxyMarkerRead::Invalid(error.to_string()),
        };
        let Some(root) = value.as_object() else {
            return ProxyMarkerRead::Invalid("marker root is not an object".into());
        };
        let Some(enveloped) = root.get(PROXY_TRANSACTION_ENVELOPE_KEY) else {
            if ["exact_original", "exact_apply_base", "exact_applied"]
                .iter()
                .any(|key| root.contains_key(*key))
            {
                return ProxyMarkerRead::Invalid(
                    "top-level exact fields are not a current marker envelope".into(),
                );
            }
            let data: ProxyMarkerData = match serde_json::from_value(value) {
                Ok(data) => data,
                Err(error) => return ProxyMarkerRead::Invalid(error.to_string()),
            };
            if data.our_host_port.is_empty() {
                return ProxyMarkerRead::Invalid("marker our_host_port is empty".into());
            }
            return if data.plan_version == 0
                && data.txn_id.is_none()
                && data.phase == ProxyMarkerPhase::Owned
                && data.exact_original.is_none()
                && data.exact_apply_base.is_none()
                && data.exact_applied.is_none()
            {
                ProxyMarkerRead::Legacy(data)
            } else {
                ProxyMarkerRead::Invalid("invalid legacy marker".into())
            };
        };
        if root.len() != 1 {
            return ProxyMarkerRead::Invalid(
                "current marker envelope must be the only root field".into(),
            );
        }
        let Some(object) = enveloped.as_object() else {
            return ProxyMarkerRead::Invalid("current marker envelope is not an object".into());
        };
        let data: ProxyMarkerData = match serde_json::from_value(enveloped.clone()) {
            Ok(data) => data,
            Err(error) => return ProxyMarkerRead::Invalid(error.to_string()),
        };
        if data.our_host_port.is_empty() {
            return ProxyMarkerRead::Invalid("marker our_host_port is empty".into());
        }
        if data.plan_version != PROXY_TRANSACTION_PLAN_VERSION {
            return ProxyMarkerRead::UnsupportedVersion(data.plan_version);
        }
        let has_all_v2_fields = [
            "txn_id",
            "plan_version",
            "phase",
            "exact_original",
            "exact_apply_base",
            "exact_applied",
        ]
        .iter()
        .all(|key| object.contains_key(*key));
        if !has_all_v2_fields {
            return ProxyMarkerRead::Invalid("current marker is missing required V2 fields".into());
        }
        if data.txn_id.as_deref().is_none_or(str::is_empty)
            || data
                .exact_original
                .as_ref()
                .is_none_or(|snapshot| !valid_transaction_snapshot(snapshot))
            || data
                .exact_apply_base
                .as_ref()
                .is_none_or(|snapshot| !valid_transaction_snapshot(snapshot))
            || data
                .exact_applied
                .as_ref()
                .is_none_or(|snapshot| !valid_transaction_snapshot(snapshot))
        {
            return ProxyMarkerRead::Invalid("current marker contains invalid V2 snapshots".into());
        }
        let original_kind = snapshot_kind(data.exact_original.as_ref().expect("checked"));
        if snapshot_kind(data.exact_apply_base.as_ref().expect("checked")) != original_kind
            || snapshot_kind(data.exact_applied.as_ref().expect("checked")) != original_kind
            || !valid_transaction_snapshot_pair(
                data.exact_original.as_ref().expect("checked"),
                data.exact_apply_base.as_ref().expect("checked"),
            )
            || !valid_transaction_snapshot_pair(
                data.exact_apply_base.as_ref().expect("checked"),
                data.exact_applied.as_ref().expect("checked"),
            )
        {
            return ProxyMarkerRead::Invalid("current marker snapshot platform mismatch".into());
        }
        let projection_matches = [
            (&data.original, &data.exact_original),
            (&data.apply_base, &data.exact_apply_base),
            (&data.applied, &data.exact_applied),
        ]
        .into_iter()
        .all(|(legacy, exact)| {
            matches!(
                legacy.as_ref().and_then(snapshot_kind),
                Some(SnapshotKind::Projection)
            ) && legacy.as_ref().and_then(|value| value.projection.as_ref())
                == exact.as_ref().and_then(|value| value.projection.as_ref())
        });
        if !projection_matches
            || !data.mac_service_settings.is_empty()
            || data.original_settings
                != data
                    .exact_original
                    .as_ref()
                    .and_then(|snapshot| snapshot.projection.clone())
        {
            return ProxyMarkerRead::Invalid(
                "current marker downgrade projection is invalid".into(),
            );
        }
        ProxyMarkerRead::CurrentValidated(data)
    }

    fn write_json_unlocked<T: Serialize>(&self, data: &T) -> bool {
        // 序列化失败理论不会发生（纯数据结构），但仍降级为不抛。
        let Ok(json) = serde_json::to_string(data) else {
            return false;
        };
        self.fs.write_marker(&self.path, &json).is_ok()
    }
}

/// 防自指：若 status 已指向我们自己的代理（`address:httpPort` 或 marker 记录的 our_host_port），
/// 返回 None（视为无原始）—— 杜绝把自身代理当原始保存、disable 后恢复死端口致断网。
/// 上游 `SystemProxyBase.stripSelf`。
pub fn strip_self(
    status: Option<&SystemProxyStatus>,
    address: &str,
    http_port: u16,
    marker_our_host_port: Option<&str>,
) -> Option<SystemProxyStatus> {
    let status = status?;
    if !status.enabled {
        return Some(status.clone());
    }
    let ours = format!("{address}:{http_port}");
    let points_to_us = |p: &Option<String>| -> bool {
        match p {
            Some(proxy) => proxy == &ours || matches!(marker_our_host_port, Some(m) if proxy == m),
            None => false,
        }
    };
    if points_to_us(&status.http_proxy)
        || points_to_us(&status.https_proxy)
        || points_to_us(&status.socks_proxy)
    {
        return None;
    }
    Some(status.clone())
}

/// Linux gsettings 三 schema 恢复计划条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePlanEntry {
    pub schema: &'static str, // "http" | "https" | "socks"
    pub hp: Option<HostPort>,
}

/// 解析出的 `host:port`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

/// 从 `host:port` 健壮拆分（用最后一个冒号作端口分隔符，兼容裸 IPv6 如 `::1:8080`）。
/// 缺端口 / 端口非数字 / 越界 → None。上游 `LinuxSystemProxy.splitHostPort`。
pub fn split_host_port(proxy: Option<&str>) -> Option<HostPort> {
    let proxy = proxy?;
    let idx = proxy.rfind(':')?;
    if idx == 0 {
        return None; // 以 ':' 开头（无 host）
    }
    let host = &proxy[..idx];
    let port_str = &proxy[idx + 1..];
    if host.is_empty() {
        return None;
    }
    let port: u32 = port_str.parse().ok()?;
    if port == 0 || port > 65535 {
        return None;
    }
    Some(HostPort {
        host: host.to_string(),
        port: port as u16,
    })
}

/// Linux gsettings 三 schema 的恢复计划（capture-three）：hp 非空 = 回写该快照值；
/// None = 该 schema 原本未设，须清空（撤销 enable 期对它的写入）。
/// 上游 `LinuxSystemProxy.restorePlan`。
pub fn restore_plan(snap: Option<&SystemProxyStatus>) -> [RestorePlanEntry; 3] {
    let s = snap;
    [
        RestorePlanEntry {
            schema: "http",
            hp: split_host_port(s.and_then(|x| x.http_proxy.as_deref())),
        },
        RestorePlanEntry {
            schema: "https",
            hp: split_host_port(s.and_then(|x| x.https_proxy.as_deref())),
        },
        RestorePlanEntry {
            schema: "socks",
            hp: split_host_port(s.and_then(|x| x.socks_proxy.as_deref())),
        },
    ]
}

/// ms 时间戳（上游 `Date.now()`）。测试可注入，生产用系统时间。
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn new_proxy_txn_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TXN_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = TXN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    // `RandomState::new()` is independently randomized by std. Combining that process entropy with
    // pid + a monotonic-in-process sequence avoids relying on wall-clock monotonicity and makes a
    // PID/sequence repeat after restart insufficient to collide with an earlier persisted marker.
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    hasher.write_u64(sequence);
    format_proxy_txn_id(std::process::id(), sequence, hasher.finish())
}

fn format_proxy_txn_id(process_id: u32, sequence: u64, entropy: u64) -> String {
    format!("{process_id:08x}-{sequence:016x}-{entropy:016x}")
}

/// 测试辅助：跨模块共享的内存 FS mock（marker 崩溃恢复测试用）。
#[cfg(test)]
pub mod proxy_tests_helpers {
    use super::MarkerFs;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// 内存 FS mock（单文件，模拟 marker 文件读写）。内部状态共享，可 Clone 跨「进程」会话。
    #[derive(Clone)]
    pub struct MemFs {
        inner: Rc<MemFsInner>,
    }
    struct MemFsInner {
        file: RefCell<Option<String>>,
        read_calls: RefCell<u32>,
    }
    impl MemFs {
        pub fn new() -> Self {
            Self {
                inner: Rc::new(MemFsInner {
                    file: RefCell::new(None),
                    read_calls: RefCell::new(0),
                }),
            }
        }
        pub fn read_calls(&self) -> u32 {
            *self.inner.read_calls.borrow()
        }
    }
    impl Default for MemFs {
        fn default() -> Self {
            Self::new()
        }
    }
    impl MarkerFs for MemFs {
        fn write_marker(&self, _path: &str, data: &str) -> std::io::Result<()> {
            *self.inner.file.borrow_mut() = Some(data.to_string());
            Ok(())
        }
        fn read_marker(&self, _path: &str) -> Option<String> {
            *self.inner.read_calls.borrow_mut() += 1;
            self.inner.file.borrow().clone()
        }
        fn remove_marker(&self, _path: &str) -> std::io::Result<()> {
            *self.inner.file.borrow_mut() = None;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
