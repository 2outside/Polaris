//! `proxy_ops` 生产实现：平台操作 trait + 运行时 `Platform` 分派的 `SystemProxyOpsImpl`。
//!
//! **本模块持有执行与重试**（三平台 enable 的 `retry_op` 边界包整段命令序列，设计文档 T2），
//! 以及 macOS legacy 路径「原生事务优先 / `Unavailable` 回落 networksetup CLI」的
//! 唯一二择点（T3）。exact 路径一旦被 controller 选中就 fail closed，不再回落 CLI。
//! 命令构造与输出解析在 `windows.rs` / `macos_cli.rs` / `linux.rs`，本模块不重复实现。

use super::linux::{
    linux_applied_snapshot, linux_disable_command, linux_enable_commands,
    linux_exact_restore_commands, linux_gsettings_get_command, linux_gsettings_mode_get_command,
    linux_restore_schema_commands, linux_set_mode_manual_command, parse_gsettings_port,
    parse_gsettings_string, validate_linux_gsettings_snapshot, LINUX_GSETTINGS_KEYS,
};
use super::macos_cli::{
    mac_list_manageable_services, mac_read_proxy_command, mac_service_disable_commands,
    mac_service_enable_commands, mac_service_restore_commands, parse_mac_bypass_domains,
    parse_mac_service_proxy, MAC_BYPASS_READ_SUB, MAC_PROXY_READ_SUBS,
};
use super::model::{MacProxyTransactionWriter, ProxyEnableRequest, WindowsProxyRegistryWriter};
// 仅 macOS 原生事务腿（`execute_macos_transaction`）消费；非 macOS 上该腿被 cfg 掉。
#[cfg(target_os = "macos")]
use super::model::MacProxyWriterError;
use super::retry::{retry_op, LINUX_ENABLE_RETRY, MAC_ENABLE_RETRY, WIN_ENABLE_RETRY};
use super::windows::{
    parse_win_proxy_enable, parse_win_proxy_server, windows_clear_quic_command,
    windows_disable_commands, windows_enable_commands, windows_enable_values,
    windows_query_command, windows_registry_projection, windows_restore_commands,
    WINDOWS_QUIC_CLEANUP_TIMEOUT,
};
use super::PROXY_EXEC_TIMEOUT;
use crate::error::SystemIntegrationError;
use crate::exec::{Command, CommandRunner};
use crate::proxy::{
    validate_mac_proxy_snapshots, MacProxyPropertyValue, MacProxyServiceSnapshot,
    ProxyOriginalSettings, ProxyTransactionSnapshot, SystemProxyStatus,
    WindowsProxyRegistrySnapshot, WindowsRegistryDwordValue, WindowsRegistryStringValue,
};
use polaris_helper_proto::Platform;
use std::sync::Arc;
use std::time::{Duration, Instant};

// 同一进程内所有 exact apply/restore 共用一把锁，让“即时重捕获 → 首写”不会被另一个
// Polaris controller 插入。它不是跨进程原子 CAS；外部工具仍可能在 compare 与首写之间竞争，
// 这里只能把该窗口压到同一平台事务入口内部。macOS helper 仍以 SCPreferences 锁完成跨进程 compare。
static EXACT_PROXY_TRANSACTION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_exact_proxy_transaction() -> std::sync::MutexGuard<'static, ()> {
    EXACT_PROXY_TRANSACTION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn ownership_lost(platform: &str, action: &str, expected: &str) -> SystemIntegrationError {
    SystemIntegrationError::proxy(format!(
        "{platform} exact {action} ownership lost: actual snapshot no longer matches {expected}"
    ))
}

// ── 平台操作 trait（系统调用经此抽象；测试 mock）──

/// 当前状态相对固定写序的关系。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxySnapshotRelation {
    /// 当前状态仍逐项等于本轮首写前的 `from`，没有任何 mutation 成员落地。
    Unchanged,
    Exact,
    /// 至少一个、但尚非全部 mutation 成员已按固定写序落地。
    Prefix,
    Foreign,
}

/// 平台系统代理操作抽象。三平台实现 cfg-gated；测试用 mock 实现。
/// 语义对齐 上游 `ISystemProxyManager`。
pub trait SystemProxyOps {
    /// 读当前代理状态（上游 `getProxyStatus`）。
    ///
    /// **口径：残留检测**——macOS 上扫**全部**网络服务（代理可能设在非首服务上）。
    /// 用于 `ensure_cleared` 门控 2 与 `detect_foreign_proxy`。**不要**拿它做 enable 前的原始快照
    /// 捕获，那条走 [`capture_original_status`](Self::capture_original_status)（口径不同，见其文档）。
    fn get_proxy_status(&self) -> Result<SystemProxyStatus, SystemIntegrationError>;

    /// 读 **enable 前的原始代理快照**（disable 时回写的真值来源）。
    ///
    /// # 为什么与 [`get_proxy_status`](Self::get_proxy_status) 刻意分家
    ///
    /// 两者问的是**不同问题**，合用一个实现会让其中一个必然错：
    ///
    /// - `get_proxy_status` 问「**系统里还有没有**代理残留」→ 必须扫全部服务，漏一个就误判「无残留」。
    /// - 本方法问「**待会儿要往回写什么**」→ 命令回退只读 `restore_proxy` 的旧回写目标；macOS
    ///   原生生产路径走 [`capture_original_settings`](Self::capture_original_settings)，一次捕获全部服务。
    ///
    /// 对齐 上游 `SystemProxyManager.ts:472`（原始快照只读首个服务）。
    ///
    /// # 与 `restore_proxy` 的成对不变式（**改一个必须改另一个**）
    ///
    /// 「捕获源」与「回写目标」必须一一对应，否则就是跨服务污染。命令回退两端锚在
    /// `services[0]`；原生路径按稳定 service ID 逐项对应。Win/Linux 无逐服务概念。
    fn capture_original_status(&self) -> Result<SystemProxyStatus, SystemIntegrationError> {
        self.get_proxy_status()
    }

    /// 捕获 enable 前的完整可恢复快照。默认平台沿用单份状态；macOS 原生实现覆盖为逐服务快照。
    fn capture_original_settings(&self) -> Result<ProxyOriginalSettings, SystemIntegrationError> {
        self.capture_original_status()
            .map(ProxyOriginalSettings::from_status)
    }

    /// 是否禁止在原值快照缺失时继续接管。逐服务写入的 macOS 原生路径必须可逆；
    /// Win/Linux 保留既有的 fail-closed 兼容语义。
    fn requires_original_snapshot(&self) -> bool {
        false
    }

    /// 是否能执行 V2 exact compare/apply/restore。默认替身与 macOS CLI 走 legacy whole-marker 路径；
    /// Linux exact gsettings 与注入原生 writer 的 Windows，以及 compare-capable mac helper 覆盖。
    fn exact_transaction_available(&self) -> Result<bool, SystemIntegrationError> {
        Ok(false)
    }

    /// 列出应设代理的网络服务（macOS 用；Win/Linux 返回单元素占位）。
    /// Polaris macOS `getNetworkServices`。
    fn list_network_services(&self) -> Result<Vec<String>, SystemIntegrationError>;

    /// 设代理（apply 平台命令）。
    /// Polaris 三平台 enableProxy retry 块的实际执行。
    fn set_proxy(&self, req: &ProxyEnableRequest) -> Result<(), SystemIntegrationError>;

    /// 用本次捕获的快照限定接管射程。默认平台无逐服务概念，直接复用
    /// [`set_proxy`](Self::set_proxy)；macOS 原生路径只写快照中的稳定 service ID。
    fn set_proxy_from_snapshot(
        &self,
        req: &ProxyEnableRequest,
        _original: Option<&ProxyOriginalSettings>,
    ) -> Result<(), SystemIntegrationError> {
        self.set_proxy(req)
    }

    /// 清/禁用代理（无原始可恢复时）。
    /// Polaris 三平台 disableProxy else 分支。
    fn clear_proxy(&self) -> Result<(), SystemIntegrationError>;

    /// 恢复原始代理设置。
    /// Polaris 三平台 disableProxy if 分支 / restoreProxySettings。
    fn restore_proxy(&self, original: &SystemProxyStatus) -> Result<(), SystemIntegrationError>;

    /// 恢复完整快照。旧实现/旧 marker 没有逐服务数据时保持原来的单份状态语义。
    fn restore_original_settings(
        &self,
        original: &ProxyOriginalSettings,
    ) -> Result<(), SystemIntegrationError> {
        match original.fallback.as_ref() {
            Some(status) => self.restore_proxy(status),
            None => self.clear_proxy(),
        }
    }

    /// V2 事务读取面。默认投影实现只服务纯内存替身；三平台生产实现覆盖为 exact 快照。
    fn capture_transaction_snapshot(
        &self,
    ) -> Result<ProxyTransactionSnapshot, SystemIntegrationError> {
        self.capture_original_settings()
            .map(|settings| ProxyTransactionSnapshot::from_original(&settings))
    }

    /// 第一笔系统写入前生成完整 applied 真值。
    fn build_applied_snapshot(
        &self,
        req: &ProxyEnableRequest,
        _apply_base: &ProxyTransactionSnapshot,
    ) -> Result<ProxyTransactionSnapshot, SystemIntegrationError> {
        let http = req.our_host_port();
        Ok(ProxyTransactionSnapshot {
            projection: Some(SystemProxyStatus {
                enabled: true,
                http_proxy: Some(http.clone()),
                https_proxy: Some(http),
                socks_proxy: Some(format!("{}:{}", req.address, req.socks_port)),
                bypass_domains: Some(req.bypass_list.clone()),
            }),
            ..Default::default()
        })
    }

    fn apply_transaction(
        &self,
        req: &ProxyEnableRequest,
        apply_base: &ProxyTransactionSnapshot,
    ) -> Result<(), SystemIntegrationError> {
        let settings = apply_base.original_settings();
        self.set_proxy_from_snapshot(req, settings.as_ref())
    }

    /// `current` 是控制器读到的 expected ownership；macOS helper 会在持锁后再次核对它。
    fn restore_transaction(
        &self,
        original: &ProxyTransactionSnapshot,
        _current: &ProxyTransactionSnapshot,
    ) -> Result<(), SystemIntegrationError> {
        match original.original_settings() {
            Some(settings) => self.restore_original_settings(&settings),
            None => self.clear_proxy(),
        }
    }

    fn snapshot_relation(
        &self,
        from: &ProxyTransactionSnapshot,
        to: &ProxyTransactionSnapshot,
        current: &ProxyTransactionSnapshot,
    ) -> ProxySnapshotRelation {
        if current == to {
            ProxySnapshotRelation::Exact
        } else if current == from {
            ProxySnapshotRelation::Unchanged
        } else {
            ProxySnapshotRelation::Foreign
        }
    }
}

// ── 生产实现（运行时 Platform 分派 + CommandRunner 下发；零 cfg）──

/// [`SystemProxyOps`] 的生产实现。
///
/// 命令构造/输出解析仍靠运行时 [`Platform`] 分派，Linux CI 可跑三平台纯逻辑；只有 macOS 生产构造
/// 额外启用编译期隔离的原生事务。`with_platform` 永远关闭原生写，跨平台测试不会碰宿主配置。
///
/// **本结构体只做「跑哪条命令 + 把输出交给纯函数解析」**，不含判定逻辑（判定全在上面的纯函数里）。
pub struct SystemProxyOpsImpl<R: CommandRunner> {
    pub(super) runner: R,
    pub(super) platform: Platform,
    /// Windows `reg.exe` 绝对路径（规避 PATH 缺 System32，见 [`crate::exec::system32`]）。
    pub(super) reg_exe: String,
    /// Windows `netsh.exe` 绝对路径。
    netsh_exe: String,
    /// 重试退避 sleep（注入便于测试：生产 [`std::thread::sleep`]，测试传 no-op 杜绝真睡）。
    sleeper: fn(Duration),
    /// 只由生产构造在真 macOS 上开启。`with_platform` 恒为 false，Linux/macOS 单测继续使用命令 mock，
    /// 不会因为指定 `Platform::Mac` 而触碰宿主代理。
    native_macos: bool,
    /// root helper 写入口。legacy 路径在 `None` 或 helper 明确“不支持/未连接”时
    /// 回落旧 networksetup；exact 路径一旦被选中则任何 helper 失败都 fail closed。
    macos_writer: Option<Arc<dyn MacProxyTransactionWriter>>,
    /// Windows 原生 HKCU 窄写入口；未注入时继续走三条 `reg.exe`，保持库调用方与测试兼容。
    windows_registry_writer: Option<Arc<dyn WindowsProxyRegistryWriter>>,
    /// App setup 已在后台执行旧 QUIC 规则迁移时，enable 热路径不再重复 `netsh`。
    skip_quic_cleanup_on_enable: bool,
}

impl<R: CommandRunner> SystemProxyOpsImpl<R> {
    /// 生产构造：平台取本机，Windows 二进制路径按本机 env 解析。
    pub fn new(runner: R) -> Self {
        let mut ops = Self::with_platform(runner, Platform::current());
        ops.native_macos = cfg!(target_os = "macos") && ops.platform == Platform::Mac;
        ops
    }

    /// 指定平台构造（测试用：Linux 上构造 Mac/Win ops 断言其 argv 与解析）。
    pub fn with_platform(runner: R, platform: Platform) -> Self {
        Self {
            runner,
            platform,
            reg_exe: crate::exec::system32_from_env("reg.exe"),
            netsh_exe: crate::exec::system32_from_env("netsh.exe"),
            sleeper: std::thread::sleep,
            native_macos: false,
            macos_writer: None,
            windows_registry_writer: None,
            skip_quic_cleanup_on_enable: false,
        }
    }

    /// 注入 macOS root helper 原生写事务。其它平台持有但不会调用。
    pub fn with_macos_writer(mut self, writer: Arc<dyn MacProxyTransactionWriter>) -> Self {
        self.macos_writer = Some(writer);
        self
    }

    /// 注入 Windows 原生 HKCU 窄写入口，并按 App setup 的预热状态决定是否跳过 enable 内重复清理。
    pub fn with_windows_registry_writer(
        mut self,
        writer: Arc<dyn WindowsProxyRegistryWriter>,
        quic_cleanup_prewarmed: bool,
    ) -> Self {
        self.windows_registry_writer = Some(writer);
        self.skip_quic_cleanup_on_enable = quic_cleanup_prewarmed;
        self
    }

    fn notify_windows_proxy_changed(&self) -> Result<(), SystemIntegrationError> {
        match &self.windows_registry_writer {
            Some(writer) => writer
                .notify_settings_changed()
                .map_err(SystemIntegrationError::from),
            None => Ok(()),
        }
    }

    #[cfg(target_os = "macos")]
    pub(super) fn uses_native_macos(&self) -> bool {
        self.native_macos && self.platform == Platform::Mac
    }

    #[cfg(target_os = "macos")]
    fn macos_writer_available(&self) -> bool {
        self.macos_writer
            .as_ref()
            .is_some_and(|writer| writer.available())
    }

    #[cfg(target_os = "macos")]
    fn execute_macos_transaction(&self, payload_hex: &str) -> Result<bool, SystemIntegrationError> {
        let Some(writer) = self.macos_writer.as_ref() else {
            return Ok(false);
        };
        match writer.execute(payload_hex) {
            Ok(()) => Ok(true),
            Err(MacProxyWriterError::Unavailable(error)) => {
                log::warn!(
                    "macOS 原生系统代理 helper 尚不可用，回落 networksetup 兼容路径：{error}"
                );
                Ok(false)
            }
            Err(MacProxyWriterError::Failed(error)) => Err(SystemIntegrationError::proxy(error)),
        }
    }

    /// exact 路径的 helper 执行门：controller 已经根据 capability probe 选中该路径，
    /// 此后 helper 消失或返回 `Unavailable` 都是事务失败，不得改走 networksetup 产生第二笔写。
    #[cfg(target_os = "macos")]
    fn execute_macos_exact_transaction(
        &self,
        payload_hex: &str,
    ) -> Result<(), SystemIntegrationError> {
        let writer = self.macos_writer.as_ref().ok_or_else(|| {
            SystemIntegrationError::proxy("macOS exact proxy helper disappeared after probe")
        })?;
        if !writer.available() {
            return Err(SystemIntegrationError::proxy(
                "macOS exact proxy helper became unavailable after probe",
            ));
        }
        writer
            .execute(payload_hex)
            .map_err(|error| SystemIntegrationError::proxy(error.to_string()))
    }

    /// 测试：换成 no-op sleeper（重试路径不真睡）。
    #[cfg(test)]
    pub(super) fn with_noop_sleeper(mut self) -> Self {
        self.sleeper = |_| {};
        self
    }

    pub(super) fn run(
        &self,
        cmd: &Command,
    ) -> Result<crate::exec::CommandOutput, SystemIntegrationError> {
        self.run_with_timeout(cmd, PROXY_EXEC_TIMEOUT)
    }

    /// 复用唯一命令执行缝，只为明确属于 best-effort 的动作收紧墙钟；必要事务仍走 [`Self::run`]。
    fn run_with_timeout(
        &self,
        cmd: &Command,
        timeout: Duration,
    ) -> Result<crate::exec::CommandOutput, SystemIntegrationError> {
        self.runner
            .run(cmd, timeout)
            .map_err(SystemIntegrationError::proxy)
    }

    /// 逐条跑；任一失败即返回（enable 的 argv 序列是整体，半套=坏状态）。
    fn run_all(&self, cmds: &[Command]) -> Result<(), SystemIntegrationError> {
        for c in cmds {
            self.run(c)?;
        }
        Ok(())
    }

    fn apply_windows_attempt(
        &self,
        req: &ProxyEnableRequest,
    ) -> Result<(), SystemIntegrationError> {
        let attempt_started = Instant::now();
        let registry_started = Instant::now();
        let registry_result = if let Some(writer) = &self.windows_registry_writer {
            writer
                .write(&windows_enable_values(req))
                .and_then(|()| writer.notify_settings_changed())
                .map_err(SystemIntegrationError::from)
        } else {
            self.run_all(&windows_enable_commands(&self.reg_exe, req))
        };
        if let Err(error) = registry_result {
            log::info!(
                "Windows 系统代理写入耗时：注册表失败于{}ms，本次尝试={}ms",
                registry_started.elapsed().as_millis(),
                attempt_started.elapsed().as_millis()
            );
            return Err(error);
        }
        let registry_ms = registry_started.elapsed().as_millis();
        let (quic_cleanup, quic_ms) = if self.skip_quic_cleanup_on_enable {
            ("prewarmed", 0)
        } else {
            let quic_started = Instant::now();
            let outcome = if let Err(err) = self.run_with_timeout(
                &windows_clear_quic_command(&self.netsh_exe),
                WINDOWS_QUIC_CLEANUP_TIMEOUT,
            ) {
                log::warn!(
                    "Windows QUIC legacy firewall-rule cleanup skipped after proxy enable: {err}"
                );
                "skipped"
            } else {
                "ok"
            };
            (outcome, quic_started.elapsed().as_millis())
        };
        log::info!(
            "Windows 系统代理写入耗时：注册表={registry_ms}ms，QUIC旧规则清理={quic_ms}ms，\
             本次尝试={}ms，QUIC清理={quic_cleanup}",
            attempt_started.elapsed().as_millis()
        );
        Ok(())
    }

    /// macOS：读单服务三协议代理。
    fn mac_read_service(&self, service: &str) -> SystemProxyStatus {
        let mut st = SystemProxyStatus::default();
        // best-effort 逐协议：单协议读失败按「未设」（上游 readServiceProxy 由外层 try/catch 兜）。
        let read = |sub: &str| -> Option<String> {
            let out = self.run(&mac_read_proxy_command(sub, service)).ok()?;
            parse_mac_service_proxy(&out.stdout)
        };
        st.http_proxy = read(MAC_PROXY_READ_SUBS[0]);
        st.https_proxy = read(MAC_PROXY_READ_SUBS[1]);
        st.socks_proxy = read(MAC_PROXY_READ_SUBS[2]);
        // bypass 清单：enable 会整表覆盖它，不在这里捕获就永远还不回去。
        // 读失败 → `None`（**没捕获过**），restore 据此不碰 bypass —— 绝不把读失败折成「本来就是空的」。
        st.bypass_domains = self
            .run(&mac_read_proxy_command(MAC_BYPASS_READ_SUB, service))
            .ok()
            .map(|out| parse_mac_bypass_domains(&out.stdout));
        st.enabled = st.has_any_proxy();
        st
    }

    /// Linux：严格读单 schema 的 `host:port`；命令失败或非 canonical string/int 均 Err。
    fn linux_collect_schema(&self, schema: &str) -> Result<Option<String>, SystemIntegrationError> {
        let host_out = self.run(&linux_gsettings_get_command(schema, "host"))?;
        let host = parse_gsettings_string(&host_out.stdout).ok_or_else(|| {
            SystemIntegrationError::proxy(format!("invalid Linux GSettings {schema}.host"))
        })?;
        if host.trim().is_empty() {
            return Ok(None);
        }
        let port_out = self.run(&linux_gsettings_get_command(schema, "port"))?;
        let port = parse_gsettings_port(&port_out.stdout);
        let port = port.parse::<u16>().map_err(|_| {
            SystemIntegrationError::proxy(format!("invalid Linux GSettings {schema}.port"))
        })?;
        Ok(Some(format!("{host}:{port}")))
    }

    /// Linux 三协议严格投影。capture 保留 dormant `host:0`；status 只保留非零端口的生效值。
    fn linux_protocol_projection(
        &self,
        include_dormant: bool,
    ) -> Result<SystemProxyStatus, SystemIntegrationError> {
        let active = |proxy: Option<String>| {
            if include_dormant || crate::proxy::split_host_port(proxy.as_deref()).is_some() {
                proxy
            } else {
                None
            }
        };
        let http_proxy = active(self.linux_collect_schema("http")?);
        let https_proxy = active(self.linux_collect_schema("https")?);
        let socks_proxy = active(self.linux_collect_schema("socks")?);
        if http_proxy.is_none() && https_proxy.is_none() && socks_proxy.is_none() {
            return Ok(SystemProxyStatus::default());
        }
        Ok(SystemProxyStatus {
            enabled: true,
            http_proxy,
            https_proxy,
            socks_proxy,
            bypass_domains: None,
        })
    }

    fn capture_linux_exact(&self) -> Result<ProxyTransactionSnapshot, SystemIntegrationError> {
        let mut values = Vec::with_capacity(LINUX_GSETTINGS_KEYS.len());
        for entry in LINUX_GSETTINGS_KEYS {
            let output = self.run(&Command::new("gsettings", ["get", entry.schema, entry.key]))?;
            let raw = output.stdout.trim_end_matches(['\r', '\n']).to_owned();
            values.push(raw);
        }
        let snapshot = crate::proxy::LinuxGSettingsSnapshot {
            http_host: values[0].clone(),
            http_port: values[1].clone(),
            http_enabled: values[2].clone(),
            https_host: values[3].clone(),
            https_port: values[4].clone(),
            socks_host: values[5].clone(),
            socks_port: values[6].clone(),
            ignore_hosts: values[7].clone(),
            mode: values[8].clone(),
        };
        validate_linux_gsettings_snapshot(&snapshot).map_err(SystemIntegrationError::proxy)?;
        let projection = super::linux::linux_snapshot_projection(&snapshot);
        Ok(ProxyTransactionSnapshot {
            projection: Some(projection),
            linux_gsettings: Some(snapshot),
            ..Default::default()
        })
    }
}

fn ordered_prefix_relation<T: PartialEq>(
    from: &[T],
    to: &[T],
    current: &[T],
) -> ProxySnapshotRelation {
    if from.len() != to.len() || to.len() != current.len() {
        return ProxySnapshotRelation::Foreign;
    }
    if current == to {
        return ProxySnapshotRelation::Exact;
    }
    if current == from {
        return ProxySnapshotRelation::Unchanged;
    }
    for prefix in 1..to.len() {
        if current[..prefix] == to[..prefix] && current[prefix..] == from[prefix..] {
            return ProxySnapshotRelation::Prefix;
        }
    }
    ProxySnapshotRelation::Foreign
}

#[derive(Clone, PartialEq, Eq)]
enum MacOwnershipMember {
    ProtocolPresent(bool),
    ProtocolEnabled(bool),
    Property(MacProxyPropertyValue),
}

fn mac_ownership_members(
    scope: &[MacProxyServiceSnapshot],
    reference_order: &[MacProxyServiceSnapshot],
) -> Option<Vec<MacOwnershipMember>> {
    validate_mac_proxy_snapshots(reference_order, Some(scope)).ok()?;
    let mut members = Vec::with_capacity(reference_order.len() * 12);
    for reference in reference_order {
        let service = scope
            .iter()
            .find(|service| service.service_id == reference.service_id)?;
        let touched = service.touched.as_ref()?;
        members.push(MacOwnershipMember::ProtocolPresent(
            touched.protocol_present,
        ));
        members.push(MacOwnershipMember::ProtocolEnabled(
            touched.protocol_enabled,
        ));
        members.extend(
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
            .into_iter()
            .cloned()
            .map(MacOwnershipMember::Property),
        );
    }
    Some(members)
}

pub(crate) fn mac_snapshot_relation(
    from: &[MacProxyServiceSnapshot],
    to: &[MacProxyServiceSnapshot],
    current: &[MacProxyServiceSnapshot],
) -> ProxySnapshotRelation {
    let (Some(from_members), Some(to_members), Some(current_members)) = (
        mac_ownership_members(from, from),
        mac_ownership_members(to, from),
        mac_ownership_members(current, from),
    ) else {
        return ProxySnapshotRelation::Foreign;
    };
    if current_members == to_members {
        return ProxySnapshotRelation::Exact;
    }
    if current_members == from_members {
        return ProxySnapshotRelation::Unchanged;
    }
    for prefix in 1..to_members.len() {
        if current_members[..prefix] == to_members[..prefix]
            && current_members[prefix..] == from_members[prefix..]
        {
            return ProxySnapshotRelation::Prefix;
        }
    }
    ProxySnapshotRelation::Foreign
}

fn windows_snapshot_relation(
    from: &WindowsProxyRegistrySnapshot,
    to: &WindowsProxyRegistrySnapshot,
    current: &WindowsProxyRegistrySnapshot,
) -> ProxySnapshotRelation {
    let to_matches = [
        current.proxy_server == to.proxy_server,
        current.proxy_override == to.proxy_override,
        current.proxy_enable == to.proxy_enable,
    ];
    if to_matches.into_iter().all(std::convert::identity) {
        return ProxySnapshotRelation::Exact;
    }
    let from_matches = [
        current.proxy_server == from.proxy_server,
        current.proxy_override == from.proxy_override,
        current.proxy_enable == from.proxy_enable,
    ];
    if from_matches.into_iter().all(std::convert::identity) {
        return ProxySnapshotRelation::Unchanged;
    }
    for prefix in 1..3 {
        if to_matches[..prefix].iter().all(|matched| *matched)
            && from_matches[prefix..].iter().all(|matched| *matched)
        {
            return ProxySnapshotRelation::Prefix;
        }
    }
    ProxySnapshotRelation::Foreign
}

impl<R: CommandRunner> SystemProxyOps for SystemProxyOpsImpl<R> {
    fn exact_transaction_available(&self) -> Result<bool, SystemIntegrationError> {
        match self.platform {
            Platform::Linux => Ok(true),
            Platform::Win => Ok(self.windows_registry_writer.is_some()),
            Platform::Mac => {
                #[cfg(target_os = "macos")]
                if self.uses_native_macos() {
                    let Some(writer) = self.macos_writer.as_ref() else {
                        return Ok(false);
                    };
                    if !writer.available() {
                        return Ok(false);
                    }
                    return match writer.compare_capable() {
                        Ok(capable) => Ok(capable),
                        Err(MacProxyWriterError::Unavailable(error)) => {
                            log::warn!(
                                "macOS compare capability 尚不可用，选择 legacy networksetup：{error}"
                            );
                            Ok(false)
                        }
                        Err(MacProxyWriterError::Failed(error)) => {
                            Err(SystemIntegrationError::proxy(error))
                        }
                    };
                }
                Ok(false)
            }
            Platform::Other => Err(SystemIntegrationError::UnsupportedPlatform(
                "system proxy transaction".into(),
            )),
        }
    }

    fn get_proxy_status(&self) -> Result<SystemProxyStatus, SystemIntegrationError> {
        #[cfg(target_os = "macos")]
        if self.uses_native_macos() {
            return crate::macos_proxy::read_any_status().map_err(SystemIntegrationError::proxy);
        }
        match self.platform {
            Platform::Win => {
                // ProxyEnable 未启用 → 直接 disabled（上游 getProxyStatus 早退）。
                let Ok(enable_out) = self.run(&windows_query_command(&self.reg_exe, "ProxyEnable"))
                else {
                    return Ok(SystemProxyStatus::default()); // 上游 catch → { enabled: false }
                };
                if !parse_win_proxy_enable(&enable_out.stdout) {
                    return Ok(SystemProxyStatus::default());
                }
                let Ok(server_out) = self.run(&windows_query_command(&self.reg_exe, "ProxyServer"))
                else {
                    // 上游：ProxyServer 读不到但 enabled=true → { enabled: true }（无协议明细）。
                    return Ok(SystemProxyStatus {
                        enabled: true,
                        ..Default::default()
                    });
                };
                Ok(parse_win_proxy_server(&server_out.stdout))
            }
            Platform::Mac => {
                // 逐服务检查：代理可能设在非首个服务上（以太网优先 / VPN / 多网卡）。任一服务有启用
                // 代理即返回 —— 只看 services[0] 会漏检非首服务上的残留（上游 macOS 误判「无残留」的修复）。
                for service in self.list_network_services()? {
                    let st = self.mac_read_service(&service);
                    if st.enabled {
                        return Ok(st);
                    }
                }
                Ok(SystemProxyStatus::default())
            }
            Platform::Linux => {
                let mode_out = self.run(&linux_gsettings_mode_get_command())?;
                let mode = parse_gsettings_string(&mode_out.stdout)
                    .ok_or_else(|| SystemIntegrationError::proxy("invalid Linux GSettings mode"))?;
                if mode != "manual" {
                    return Ok(SystemProxyStatus::default());
                }
                self.linux_protocol_projection(false)
            }
            Platform::Other => Err(SystemIntegrationError::UnsupportedPlatform(
                "system proxy".into(),
            )),
        }
    }

    /// macOS：**只读首个**网络服务（= [`restore_proxy`](Self::restore_proxy) 的回写目标），
    /// 不扫全部（对齐 上游 `SystemProxyManager.ts:472`）。Windows 委托 `get_proxy_status`；Linux
    /// 为 legacy restore 对称读取三协议 dormant projection，刻意不消费 mode/http.enabled。Linux
    /// exact 九键快照由未接线的 V2 carrier/command builder 承载。为什么口径与 status 不同，见
    /// trait 方法文档。
    fn capture_original_status(&self) -> Result<SystemProxyStatus, SystemIntegrationError> {
        if self.platform == Platform::Linux {
            return self.linux_protocol_projection(true);
        }
        if self.platform != Platform::Mac {
            return self.get_proxy_status();
        }
        // 无网络服务（无网卡 / 解析空）→ 无可捕获也无可回写 → 空快照（disable 退化为 clear）。
        let Some(first) = self.list_network_services()?.into_iter().next() else {
            return Ok(SystemProxyStatus::default());
        };
        Ok(self.mac_read_service(&first))
    }

    fn capture_original_settings(&self) -> Result<ProxyOriginalSettings, SystemIntegrationError> {
        #[cfg(target_os = "macos")]
        if self.uses_native_macos() && self.macos_writer.is_some() {
            let mac_services =
                crate::macos_proxy::capture_all().map_err(SystemIntegrationError::proxy)?;
            crate::proxy::validate_mac_proxy_snapshots(&mac_services, None)
                .map_err(SystemIntegrationError::proxy)?;
            let fallback = mac_services.first().map(|service| service.status.clone());
            return Ok(ProxyOriginalSettings {
                fallback,
                mac_services,
                linux_gsettings: None,
                windows_registry: None,
            });
        }
        self.capture_original_status()
            .map(ProxyOriginalSettings::from_status)
    }

    fn requires_original_snapshot(&self) -> bool {
        #[cfg(target_os = "macos")]
        if self.uses_native_macos() && self.macos_writer.is_some() {
            return true;
        }
        false
    }

    fn list_network_services(&self) -> Result<Vec<String>, SystemIntegrationError> {
        match self.platform {
            // 写入 `networksetup` 时，目标集合必须由 `networksetup` 自己给出。SystemConfiguration
            // 会额外列出已脱离当前 service order 的历史网卡，并返回本地化显示名；把那份名字传给
            // `networksetup` 会得到 exit=4/8，正是「helper 卸载后 System 起核但代理直连」的根因。
            Platform::Mac => mac_list_manageable_services(|c| self.run(c)),
            // Win/Linux 的代理是全局设置（注册表 / gsettings），无「逐服务」概念 → 单元素占位
            // （与 trait doc 一致；调用方按单目标遍历即可）。
            Platform::Win | Platform::Linux => Ok(vec![String::new()]),
            Platform::Other => Err(SystemIntegrationError::UnsupportedPlatform(
                "system proxy".into(),
            )),
        }
    }

    fn set_proxy(&self, req: &ProxyEnableRequest) -> Result<(), SystemIntegrationError> {
        // retry 边界对齐上游：包**整个平台 enable 命令序列**（不含 marker/getProxyStatus——那在
        // `SystemProxyController::enable` 里、上游同样在 retry 外）。瞬时抖动整序重试，不误判失败回滚。
        match self.platform {
            Platform::Win => retry_op(
                &WIN_ENABLE_RETRY,
                || self.apply_windows_attempt(req),
                self.sleeper,
            ),
            Platform::Mac => retry_op(
                &MAC_ENABLE_RETRY,
                || {
                    // 逐服务设（与 getProxyStatus/disable 遍历同口径）。getNetworkServices 在 retry 内
                    // 重取——对齐上游 mac retry 闭包（`SystemProxyManager.ts:485`）。
                    let services = self.list_network_services()?;
                    let commands_per_service = services
                        .first()
                        .map_or(0, |svc| mac_service_enable_commands(svc, req).len());
                    log::info!(
                        "macOS 系统代理接管：服务数={}，每服务命令数={commands_per_service}",
                        services.len()
                    );
                    for svc in &services {
                        self.run_all(&mac_service_enable_commands(svc, req))?;
                    }
                    Ok(())
                },
                self.sleeper,
            ),
            Platform::Linux => retry_op(
                &LINUX_ENABLE_RETRY,
                || {
                    let commands =
                        linux_enable_commands(req).map_err(SystemIntegrationError::proxy)?;
                    self.run_all(&commands)
                },
                self.sleeper,
            ),
            Platform::Other => Err(SystemIntegrationError::UnsupportedPlatform(
                "system proxy".into(),
            )),
        }
    }

    fn set_proxy_from_snapshot(
        &self,
        req: &ProxyEnableRequest,
        _original: Option<&ProxyOriginalSettings>,
    ) -> Result<(), SystemIntegrationError> {
        #[cfg(target_os = "macos")]
        if self.uses_native_macos() && self.macos_writer_available() {
            let captured = _original
                .ok_or_else(|| SystemIntegrationError::proxy("macOS helper enable 缺少捕获范围"))?;
            crate::proxy::validate_mac_proxy_snapshots(&captured.mac_services, None)
                .map_err(SystemIntegrationError::proxy)?;
            let service_ids = captured
                .mac_services
                .iter()
                .map(|service| service.service_id.clone())
                .collect::<Vec<_>>();
            let payload = crate::macos_proxy::enable_transaction_payload(req, service_ids)
                .map_err(SystemIntegrationError::proxy)?;
            if self.execute_macos_transaction(&payload)? {
                return Ok(());
            }
        }
        self.set_proxy(req)
    }

    fn clear_proxy(&self) -> Result<(), SystemIntegrationError> {
        match self.platform {
            Platform::Win => {
                // 禁用时务必先清 QUIC 规则（上游 disableProxy 首行）。best-effort：清不掉不阻断禁用
                // —— 关代理是断网防线，不能被一条防火墙规则清理失败拖住。
                let _ = self.run_with_timeout(
                    &windows_clear_quic_command(&self.netsh_exe),
                    WINDOWS_QUIC_CLEANUP_TIMEOUT,
                );
                self.run(&windows_disable_commands(&self.reg_exe))?;
                self.notify_windows_proxy_changed()
            }
            Platform::Mac => {
                #[cfg(target_os = "macos")]
                if self.uses_native_macos() && self.macos_writer_available() {
                    let payload = crate::macos_proxy::clear_transaction_payload()
                        .map_err(SystemIntegrationError::proxy)?;
                    if self.execute_macos_transaction(&payload)? {
                        return Ok(());
                    }
                }
                let services = self.list_network_services()?;
                for svc in &services {
                    self.run_all(&mac_service_disable_commands(svc))?;
                }
                Ok(())
            }
            Platform::Linux => self.run(&linux_disable_command()).map(|_| ()),
            Platform::Other => Err(SystemIntegrationError::UnsupportedPlatform(
                "system proxy".into(),
            )),
        }
    }

    fn restore_proxy(&self, original: &SystemProxyStatus) -> Result<(), SystemIntegrationError> {
        // 无实际原始代理 → 等价于「关」（对齐上游 disableProxy 的 else 分支 / restorePlan 全空腿）。
        if !original.enabled || !original.has_any_proxy() {
            return self.clear_proxy();
        }
        match self.platform {
            Platform::Win => {
                let _ = self.run_with_timeout(
                    &windows_clear_quic_command(&self.netsh_exe),
                    WINDOWS_QUIC_CLEANUP_TIMEOUT,
                );
                // 回写原始 ProxyServer 串 + ProxyEnable=1。
                self.run_all(&windows_restore_commands(&self.reg_exe, original))?;
                self.notify_windows_proxy_changed()
            }
            Platform::Mac => {
                // **只往捕获源（services[0]）回写原始，其余服务一律关**。
                //
                // 为什么不能逐服务全铺（这是修掉的真实缺陷）：`original` 是**单个**服务的快照
                // （见 `capture_original_status`），而 `set_proxy` 把代理设到了**全部**服务上。
                // 若 disable 时把这份快照铺回全部服务，那些**本来就没设代理**的服务（Ethernet /
                // Thunderbolt / VPN…）会被平白写上一份用户从未配过的代理并 `state on` ——
                // 用户的网络配置被我们污染，且比接管前更糟（接管前它们是干净的）。
                //
                // 对称性：enable 在**全部**服务上留了痕 → disable 必须在**全部**服务上撤干净；
                // 但「撤」对捕获源是「回到原值」，对其余服务是「关」（它们的原值就是关）。
                let services = self.list_network_services()?;
                let mut it = services.iter();
                if let Some(first) = it.next() {
                    self.run_all(&mac_service_restore_commands(first, original))?;
                }
                for svc in it {
                    self.run_all(&mac_service_disable_commands(svc))?;
                }
                Ok(())
            }
            Platform::Linux => {
                // capture-three + 对称撤销：set 原本设了的、clear 原本未设的。
                self.run(&linux_set_mode_manual_command())?;
                for entry in crate::proxy::restore_plan(Some(original)) {
                    self.run_all(&linux_restore_schema_commands(&entry))?;
                }
                Ok(())
            }
            Platform::Other => Err(SystemIntegrationError::UnsupportedPlatform(
                "system proxy".into(),
            )),
        }
    }

    fn restore_original_settings(
        &self,
        original: &ProxyOriginalSettings,
    ) -> Result<(), SystemIntegrationError> {
        if self.platform == Platform::Mac && !original.mac_services.is_empty() {
            crate::proxy::validate_mac_proxy_snapshots(&original.mac_services, None)
                .map_err(SystemIntegrationError::proxy)?;
        }
        #[cfg(target_os = "macos")]
        if self.uses_native_macos()
            && self.macos_writer_available()
            && !original.mac_services.is_empty()
        {
            let payload = crate::macos_proxy::restore_transaction_payload(&original.mac_services)
                .map_err(SystemIntegrationError::proxy)?;
            if self.execute_macos_transaction(&payload)? {
                return Ok(());
            }
        }

        // helper 缺失/卸载/过旧时，完整原生快照仍可按 `networksetup` 当前可管理的服务名恢复其
        // 静态三协议与 bypass。只处理本轮 fallback enable 真正触碰过的集合；原生快照里那些已
        // 脱离 service order 的历史网卡不会再被错误传给 `networksetup`。匹配不到的当前服务只关
        // 静态代理，确保不会留下 Polaris 死端口。
        if self.platform == Platform::Mac && !original.mac_services.is_empty() {
            let services = self.list_network_services()?;
            for service_name in &services {
                let snapshot = original
                    .mac_services
                    .iter()
                    .find(|snapshot| snapshot.service_name == *service_name);
                match snapshot {
                    Some(snapshot) if !snapshot.clear_on_restore => self.run_all(
                        &mac_service_restore_commands(service_name, &snapshot.status),
                    )?,
                    Some(_) | None => {
                        self.run_all(&mac_service_disable_commands(service_name))?;
                    }
                }
            }
            return Ok(());
        }
        match original.fallback.as_ref() {
            Some(status) => self.restore_proxy(status),
            None => self.clear_proxy(),
        }
    }

    fn capture_transaction_snapshot(
        &self,
    ) -> Result<ProxyTransactionSnapshot, SystemIntegrationError> {
        match self.platform {
            Platform::Linux => self.capture_linux_exact(),
            Platform::Win => {
                let writer = self.windows_registry_writer.as_ref().ok_or_else(|| {
                    SystemIntegrationError::proxy(
                        "Windows exact proxy capture requires the native registry writer",
                    )
                })?;
                let snapshot = writer.capture().map_err(SystemIntegrationError::from)?;
                Ok(ProxyTransactionSnapshot {
                    projection: Some(windows_registry_projection(&snapshot)),
                    windows_registry: Some(snapshot),
                    ..Default::default()
                })
            }
            Platform::Mac => {
                #[cfg(target_os = "macos")]
                if self.uses_native_macos() {
                    let mac_services =
                        crate::macos_proxy::capture_all().map_err(SystemIntegrationError::proxy)?;
                    crate::proxy::validate_mac_proxy_snapshots(&mac_services, None)
                        .map_err(SystemIntegrationError::proxy)?;
                    return Ok(ProxyTransactionSnapshot {
                        projection: Some(
                            mac_services
                                .first()
                                .map(|service| service.status.clone())
                                .unwrap_or_default(),
                        ),
                        mac_services,
                        ..Default::default()
                    });
                }
                SystemProxyOps::capture_transaction_snapshot(self)
            }
            Platform::Other => Err(SystemIntegrationError::UnsupportedPlatform(
                "system proxy transaction".into(),
            )),
        }
    }

    fn build_applied_snapshot(
        &self,
        req: &ProxyEnableRequest,
        _apply_base: &ProxyTransactionSnapshot,
    ) -> Result<ProxyTransactionSnapshot, SystemIntegrationError> {
        match self.platform {
            Platform::Linux => Ok(ProxyTransactionSnapshot {
                projection: Some(SystemProxyStatus {
                    enabled: true,
                    http_proxy: Some(req.our_host_port()),
                    https_proxy: Some(req.our_host_port()),
                    socks_proxy: Some(format!("{}:{}", req.address, req.socks_port)),
                    bypass_domains: Some(req.bypass_list.clone()),
                }),
                linux_gsettings: Some(
                    linux_applied_snapshot(req).map_err(SystemIntegrationError::proxy)?,
                ),
                ..Default::default()
            }),
            Platform::Win => {
                let values = windows_enable_values(req);
                let projection = SystemProxyStatus {
                    enabled: true,
                    http_proxy: Some(req.our_host_port()),
                    https_proxy: Some(req.our_host_port()),
                    socks_proxy: None,
                    bypass_domains: Some(req.bypass_list.clone()),
                };
                Ok(ProxyTransactionSnapshot {
                    projection: Some(projection),
                    windows_registry: Some(WindowsProxyRegistrySnapshot {
                        proxy_server: if values.proxy_server.is_empty() {
                            WindowsRegistryStringValue::PresentEmpty
                        } else {
                            WindowsRegistryStringValue::PresentValue(values.proxy_server)
                        },
                        proxy_override: if values.proxy_override.is_empty() {
                            WindowsRegistryStringValue::PresentEmpty
                        } else {
                            WindowsRegistryStringValue::PresentValue(values.proxy_override)
                        },
                        proxy_enable: WindowsRegistryDwordValue::PresentValue(values.proxy_enable),
                    }),
                    ..Default::default()
                })
            }
            Platform::Mac => {
                #[cfg(target_os = "macos")]
                if self.uses_native_macos() {
                    let mac_services =
                        crate::macos_proxy::build_applied_snapshots(req, &_apply_base.mac_services)
                            .map_err(SystemIntegrationError::proxy)?;
                    crate::proxy::validate_mac_proxy_snapshots(
                        &_apply_base.mac_services,
                        Some(&mac_services),
                    )
                    .map_err(SystemIntegrationError::proxy)?;
                    return Ok(ProxyTransactionSnapshot {
                        projection: Some(SystemProxyStatus {
                            enabled: true,
                            http_proxy: Some(req.our_host_port()),
                            https_proxy: Some(req.our_host_port()),
                            socks_proxy: Some(format!("{}:{}", req.address, req.socks_port)),
                            bypass_domains: Some(req.bypass_list.clone()),
                        }),
                        mac_services,
                        ..Default::default()
                    });
                }
                SystemProxyOps::build_applied_snapshot(self, req, _apply_base)
            }
            Platform::Other => Err(SystemIntegrationError::UnsupportedPlatform(
                "system proxy transaction".into(),
            )),
        }
    }

    fn apply_transaction(
        &self,
        req: &ProxyEnableRequest,
        apply_base: &ProxyTransactionSnapshot,
    ) -> Result<(), SystemIntegrationError> {
        let _transaction_guard = lock_exact_proxy_transaction();
        match self.platform {
            Platform::Linux => {
                let expected = apply_base.linux_gsettings.as_ref().ok_or_else(|| {
                    SystemIntegrationError::proxy("Linux exact apply_base snapshot missing")
                })?;
                let desired = linux_applied_snapshot(req).map_err(SystemIntegrationError::proxy)?;
                let commands = linux_exact_restore_commands(&desired)
                    .map_err(SystemIntegrationError::proxy)?;
                retry_op(
                    &LINUX_ENABLE_RETRY,
                    || {
                        let actual = self.capture_linux_exact()?;
                        if actual.linux_gsettings.as_ref() != Some(expected) {
                            return Err(ownership_lost("Linux", "apply", "apply_base"));
                        }
                        self.run_all(&commands)
                    },
                    self.sleeper,
                )
            }
            Platform::Win => {
                let expected = apply_base.windows_registry.as_ref().ok_or_else(|| {
                    SystemIntegrationError::proxy("Windows exact apply_base snapshot missing")
                })?;
                let writer = self.windows_registry_writer.as_ref().ok_or_else(|| {
                    SystemIntegrationError::proxy(
                        "Windows exact proxy apply requires the native registry writer",
                    )
                })?;
                retry_op(
                    &WIN_ENABLE_RETRY,
                    || {
                        let actual = writer.capture().map_err(SystemIntegrationError::from)?;
                        if &actual != expected {
                            return Err(ownership_lost("Windows", "apply", "apply_base"));
                        }
                        self.apply_windows_attempt(req)
                    },
                    self.sleeper,
                )
            }
            Platform::Mac => {
                #[cfg(target_os = "macos")]
                if self.uses_native_macos() {
                    let desired =
                        crate::macos_proxy::build_applied_snapshots(req, &apply_base.mac_services)
                            .map_err(SystemIntegrationError::proxy)?;
                    let payload = crate::macos_proxy::enable_transaction_payload_v2(
                        req,
                        &apply_base.mac_services,
                        &desired,
                    )
                    .map_err(SystemIntegrationError::proxy)?;
                    return self.execute_macos_exact_transaction(&payload);
                }
                SystemProxyOps::apply_transaction(self, req, apply_base)
            }
            Platform::Other => Err(SystemIntegrationError::UnsupportedPlatform(
                "system proxy transaction".into(),
            )),
        }
    }

    fn restore_transaction(
        &self,
        original: &ProxyTransactionSnapshot,
        current: &ProxyTransactionSnapshot,
    ) -> Result<(), SystemIntegrationError> {
        let _transaction_guard = lock_exact_proxy_transaction();
        match self.platform {
            Platform::Linux => {
                let snapshot = original.linux_gsettings.as_ref().ok_or_else(|| {
                    SystemIntegrationError::proxy("Linux exact original snapshot missing")
                })?;
                let expected = current.linux_gsettings.as_ref().ok_or_else(|| {
                    SystemIntegrationError::proxy("Linux exact current snapshot missing")
                })?;
                let actual = self.capture_linux_exact()?;
                if actual.linux_gsettings.as_ref() != Some(expected) {
                    return Err(ownership_lost("Linux", "restore", "expected current"));
                }
                let commands = linux_exact_restore_commands(snapshot)
                    .map_err(SystemIntegrationError::proxy)?;
                self.run_all(&commands)
            }
            Platform::Win => {
                let snapshot = original.windows_registry.as_ref().ok_or_else(|| {
                    SystemIntegrationError::proxy("Windows exact original snapshot missing")
                })?;
                let writer = self.windows_registry_writer.as_ref().ok_or_else(|| {
                    SystemIntegrationError::proxy(
                        "Windows exact proxy restore requires the native registry writer",
                    )
                })?;
                let expected = current.windows_registry.as_ref().ok_or_else(|| {
                    SystemIntegrationError::proxy("Windows exact current snapshot missing")
                })?;
                let actual = writer.capture().map_err(SystemIntegrationError::from)?;
                if &actual != expected {
                    return Err(ownership_lost("Windows", "restore", "expected current"));
                }
                let _ = self.run_with_timeout(
                    &windows_clear_quic_command(&self.netsh_exe),
                    WINDOWS_QUIC_CLEANUP_TIMEOUT,
                );
                writer
                    .restore(snapshot)
                    .map_err(SystemIntegrationError::from)?;
                writer
                    .notify_settings_changed()
                    .map_err(SystemIntegrationError::from)
            }
            Platform::Mac => {
                #[cfg(target_os = "macos")]
                if self.uses_native_macos() {
                    let payload = crate::macos_proxy::restore_transaction_payload_v2(
                        &original.mac_services,
                        &current.mac_services,
                    )
                    .map_err(SystemIntegrationError::proxy)?;
                    return self.execute_macos_exact_transaction(&payload);
                }
                SystemProxyOps::restore_transaction(self, original, current)
            }
            Platform::Other => Err(SystemIntegrationError::UnsupportedPlatform(
                "system proxy transaction".into(),
            )),
        }
    }

    fn snapshot_relation(
        &self,
        from: &ProxyTransactionSnapshot,
        to: &ProxyTransactionSnapshot,
        current: &ProxyTransactionSnapshot,
    ) -> ProxySnapshotRelation {
        match self.platform {
            Platform::Linux => match (
                from.linux_gsettings.as_ref(),
                to.linux_gsettings.as_ref(),
                current.linux_gsettings.as_ref(),
            ) {
                (Some(from), Some(to), Some(current)) => ordered_prefix_relation(
                    &from.raw_values(),
                    &to.raw_values(),
                    &current.raw_values(),
                ),
                _ => ProxySnapshotRelation::Foreign,
            },
            Platform::Win => match (
                from.windows_registry.as_ref(),
                to.windows_registry.as_ref(),
                current.windows_registry.as_ref(),
            ) {
                (Some(from), Some(to), Some(current)) => {
                    windows_snapshot_relation(from, to, current)
                }
                _ => ProxySnapshotRelation::Foreign,
            },
            Platform::Mac => {
                #[cfg(target_os = "macos")]
                if self.uses_native_macos() {
                    return mac_snapshot_relation(
                        &from.mac_services,
                        &to.mac_services,
                        &current.mac_services,
                    );
                }
                if !from.mac_services.is_empty()
                    || !to.mac_services.is_empty()
                    || !current.mac_services.is_empty()
                {
                    return mac_snapshot_relation(
                        &from.mac_services,
                        &to.mac_services,
                        &current.mac_services,
                    );
                }
                SystemProxyOps::snapshot_relation(self, from, to, current)
            }
            Platform::Other => ProxySnapshotRelation::Foreign,
        }
    }
}
