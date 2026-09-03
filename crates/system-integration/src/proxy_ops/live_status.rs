//! 活态查询腿：此刻 OS 代理是否仍指向本进程的 mixed 入站。
//!
//! 与 `ops.rs` 的两个读法（残留检测 / 回写目标捕获）口径不同，分工见下方表格。
//! 独立成模块的既有证据：测试面早已按此域分好（`tests/live_status_tests.rs`）。

use super::linux::{
    linux_gsettings_get_command, linux_gsettings_mode_get_command, parse_gsettings_host,
    parse_gsettings_mode, parse_gsettings_port,
};
use super::macos_cli::{
    mac_default_route_command, mac_list_service_order_command, mac_read_proxy_command,
    parse_mac_bypass_domains, parse_mac_service_order, parse_mac_service_proxy,
    MAC_BYPASS_READ_SUB, MAC_PROXY_READ_SUBS,
};
use super::model::{points_to_mixed_inbound, SystemProxyLiveStatus};
use super::ops::{SystemProxyOps, SystemProxyOpsImpl};
use super::windows::{parse_win_proxy_enable, parse_win_proxy_server, windows_query_command};
use crate::error::SystemIntegrationError;
use crate::exec::CommandRunner;
use crate::proxy::SystemProxyStatus;
use polaris_helper_proto::Platform;

// ── 活态查询：当前 OS 代理是否仍指向本进程的 mixed 入站 ─────────────────────────────────
//
// # 这是本 crate 里关于系统代理的**第三个**问题（前两个见 `SystemProxyOps::get_proxy_status` /
// `capture_original_status` 的文档）
//
// | 谁 | 问的是 | macOS 读取面 | Linux 读 mode |
// |---|---|---|---|
// | `get_proxy_status` | 系统里**还有没有**代理残留（清理门控） | **全部**服务，任一有即返 | 否（残值也要清） |
// | `capture_original_status` | 待会儿要往**哪**回写、回写**什么** | `services[0]`（= 回写目标） | 否 |
// | `read_active_proxy`（本节） | **此刻流量实际会不会走我们** | **primary service**（默认路由出接口所属服务），查不到才回落 `services[0]` | **是**（mode≠manual 即不生效） |
//
// 三者合用一个实现必然让其中两个错：残留检测漏扫非首服务 = 误判「无残留」；活态查询扫全部服务
// 则会在「用户把主服务的代理关了、某个闲置服务上还留着指向我们的值」时谎报「仍生效」——
// 那正是本查询要抓的漏报形态。
//
// 活态查询与另两个的 macOS 读取面**也不同**：`capture_original_status` 问的是「回写目标」，那由
// `restore_proxy` 的写入口径（`services[0]`）定义，二者必须同源；活态查询问的是「流量走哪」，
// 那由**默认路由**定义。`-listallnetworkservices` 的顺序是配置优先级、`*` 只标停用不标未连接，
// 拿它当「在用服务」会在「雷电桥/USB 网卡排在 Wi-Fi 前」这种寻常配置上直接漏报（见
// `read_active_proxy` 的 Mac 分支注释）。
//
// # 为什么必须有活态查询（前端 `connection-state.ts` 的 DESIGN-REVIEW 两条漏报腿）
//
// 起核那一刻的 `SYSTEM_PROXY_FAILED` 只能证明「本轮 enable 失败」。它测不出：
//  1. **运行期**用户在系统设置里手动关掉/改掉代理（起核时是成功的，错误码干净）；
//  2. `error_code` 是单槽，起核后再来一条非终态错误会把 `SYSTEM_PROXY_FAILED` 覆盖掉。
// 两条都朝**漏报**（绿灯 + 明文直连）。活态查询直接读 OS、与本进程 mixed 入站比对，是这两条的
// 共同根治：它不是「历史上某一刻的记录」，而是**此刻的地面真相**。

impl<R: CommandRunner> SystemProxyOpsImpl<R> {
    /// **活态读**：此刻流量实际会走的 OS 代理设置。口径与另两个读法的分工见本节顶部表格。
    ///
    /// 与 `get_proxy_status` 的另一处刻意差异：**读失败一律 `Err`，绝不折成「未启用」**。
    /// `get_proxy_status` 把读失败折成 `default()`（对清理门控是安全方向：读不到就别动手）；
    /// 活态查询若也这么折，非 GNOME 桌面（`gsettings` 无该 schema）、PATH 缺 `reg.exe` 等
    /// 环境会被稳定判成「系统代理未生效」→ 每次都亮降级黄灯。**读不到 ≠ 没生效**，
    /// 让 `Err` 出栈、由调用方折成「未知」并回落既有信号，才是诚实的。
    ///
    /// # 已知盲区：PAC / 自动代理配置（**朝漏报**，与本查询原有方向一致）
    ///
    /// 本方法只读**静态代理**设置。若用户另开了 PAC（mac `networksetup -getautoproxyurl`、
    /// Windows `AutoConfigURL`、Linux `mode='auto'`），实际选路由 PAC 脚本决定 ——
    /// Windows/mac 上「静态代理指向我们」与「PAC 把流量导去别处」可以并存，此时本方法会回
    /// `points_to_us=true` 而流量其实没经核。Linux 无此洞（`mode='auto'` 已被 mode 闸门判非 manual）。
    /// 未补是因为判读 PAC 需要**执行** JS 脚本才能得出实际选路，那不是查询该干的事；
    /// 记在这里而不是假装覆盖了。要补的话应在此新增一路「PAC 已启用」信号交前端另行提示。
    pub fn read_active_proxy(&self) -> Result<SystemProxyStatus, SystemIntegrationError> {
        #[cfg(target_os = "macos")]
        if self.uses_native_macos() {
            return crate::macos_proxy::read_primary_status()
                .map_err(SystemIntegrationError::proxy);
        }
        match self.platform {
            Platform::Win => {
                // 注册表是全局设置，无逐服务概念 → 与 get_proxy_status 同一读法，只是失败不折。
                let enable_out = self.run(&windows_query_command(&self.reg_exe, "ProxyEnable"))?;
                if !parse_win_proxy_enable(&enable_out.stdout) {
                    return Ok(SystemProxyStatus::default());
                }
                let server_out = self.run(&windows_query_command(&self.reg_exe, "ProxyServer"))?;
                Ok(parse_win_proxy_server(&server_out.stdout))
            }
            Platform::Mac => {
                // 读**主服务**（primary service = 默认路由出接口所属的网络服务），不是
                // `-listallnetworkservices` 的首项。
                //
                // 为什么首项是错的（这是修掉的真实缺陷）：`-listallnetworkservices` 的顺序是
                // **服务优先级配置序**，不是「谁在承载流量」。它列出的是「配置里排第几」，
                // 而 `*` 前缀只标**停用**（disabled），**不标未连接**（inactive）—— 一块插着线但没插
                // 网线的 USB 网卡 / 雷电桥 / 虚拟网卡完全可以排在 Wi-Fi 前面且不带 `*`。
                //
                // 后果是双向的，且都指向本查询存在的理由：
                //  - **漏报**（危险方向）：Wi-Fi 实际承载流量、用户在 Wi-Fi 上手关了代理，而首项是没插线的
                //    雷电桥、上面还留着我们 enable 时写的值（`set_proxy` 写的是**全部**服务，见 `:1069`）
                //    → `points_to_us=true` → 绿灯 + 明文直连，正是这条查询要抓的形态；
                //  - **误报**：反过来首项没设、主服务设了 → 稳定误亮降级黄灯。
                //
                // 判不出主服务时（无默认路由 / `route` 不可用 / 设备名映射不上）**回落首项** ——
                // 那是改动前的行为，不比它差；读不出来一律不谎报「未生效」（见方法文档）。
                let primary = self.mac_primary_service();
                let services;
                let target = match &primary {
                    Some(svc) => svc.as_str(),
                    None => {
                        services = self.list_network_services()?;
                        match services.first() {
                            Some(f) => f.as_str(),
                            // 无可用网络服务 → 读不出「流量会走哪」，按读失败处理（不谎报未生效）。
                            None => {
                                return Err(SystemIntegrationError::proxy(
                                    "无可用网络服务，无法判定系统代理是否生效",
                                ))
                            }
                        }
                    }
                };
                self.mac_read_service_strict(target)
            }
            Platform::Linux => {
                // **必须先读 mode**：mode=none/auto 时 GNOME 不下发代理，而 http/https/socks 的
                // host/port 残值仍在 —— 只读 host/port 会把「用户已关代理」判成「仍指向我们」，
                // 正是本查询要抓的漏报形态。
                let mode_out = self.run(&linux_gsettings_mode_get_command())?;
                if parse_gsettings_mode(&mode_out.stdout) != "manual" {
                    return Ok(SystemProxyStatus::default());
                }
                let http_proxy = self.linux_collect_schema_strict("http")?;
                let https_proxy = self.linux_collect_schema_strict("https")?;
                let socks_proxy = self.linux_collect_schema_strict("socks")?;
                if http_proxy.is_none() && https_proxy.is_none() && socks_proxy.is_none() {
                    return Ok(SystemProxyStatus::default());
                }
                Ok(SystemProxyStatus {
                    enabled: true,
                    http_proxy,
                    https_proxy,
                    socks_proxy,
                    // Linux（gsettings）没有 per-service bypass 清单这个概念。
                    bypass_domains: None,
                })
            }
            Platform::Other => Err(SystemIntegrationError::UnsupportedPlatform(
                "system proxy".into(),
            )),
        }
    }

    /// 活态查询完整入口：读 OS 设置 + 与 `address:mixed_port` 比对。
    pub fn live_status(
        &self,
        address: &str,
        mixed_port: u16,
    ) -> Result<SystemProxyLiveStatus, SystemIntegrationError> {
        let status = self.read_active_proxy()?;
        let points_to_us = points_to_mixed_inbound(&status, address, mixed_port);
        Ok(SystemProxyLiveStatus {
            status,
            points_to_us,
            expected: format!("{address}:{mixed_port}"),
        })
    }

    /// macOS：**主服务**（primary service）—— 默认路由出接口所属的网络服务名。
    ///
    /// 两跳纯 argv 查询：`route -n get default` 取出接口 BSD 名（`en0`）→
    /// `networksetup -listnetworkserviceorder` 建「设备名 → 服务名」映射反查。
    /// 任一跳失败 / 无默认路由 / 设备名不在映射里 → `None`（调用方回落 `services[0]`，见
    /// [`Self::read_active_proxy`] 的 Mac 分支）。
    ///
    /// **best-effort 且只读**：本方法一律不 `Err` 出栈 —— 它是「更准的目标选择」，不是新的失败面；
    /// 让它能 Err 会把「查不到主服务」升级成「活态查询失败」，比回落首项更糟。
    fn mac_primary_service(&self) -> Option<String> {
        let dev_out = self.run(&mac_default_route_command()).ok()?;
        let device = crate::route_ops::parse_mac_route_get_interface(&dev_out.stdout)?;
        let order_out = self.run(&mac_list_service_order_command()).ok()?;
        parse_mac_service_order(&order_out.stdout)
            .into_iter()
            .find(|(_, dev)| *dev == device)
            .map(|(svc, _)| svc)
    }

    /// macOS：读单服务三协议代理，**任一读失败即 Err**（对照 best-effort 的 `mac_read_service`）。
    ///
    /// `mac_read_service` 把单协议读失败当「未设」，那对残留检测是可接受的降级；活态查询里
    /// 三条腿全读失败会得到 `enabled=false` → 谎报「系统代理未生效」→ 稳定误亮降级黄灯。
    fn mac_read_service_strict(
        &self,
        service: &str,
    ) -> Result<SystemProxyStatus, SystemIntegrationError> {
        let read = |sub: &str| -> Result<Option<String>, SystemIntegrationError> {
            let out = self.run(&mac_read_proxy_command(sub, service))?;
            Ok(parse_mac_service_proxy(&out.stdout))
        };
        let mut st = SystemProxyStatus {
            http_proxy: read(MAC_PROXY_READ_SUBS[0])?,
            https_proxy: read(MAC_PROXY_READ_SUBS[1])?,
            socks_proxy: read(MAC_PROXY_READ_SUBS[2])?,
            enabled: false,
            // 严格版同样要捕获 —— 少了它，走这条路径拿到的快照 restore 时还不回 bypass。
            // 这里读失败按严格语义上抛（与三协议同）。
            bypass_domains: Some(parse_mac_bypass_domains(
                &self
                    .run(&mac_read_proxy_command(MAC_BYPASS_READ_SUB, service))?
                    .stdout,
            )),
        };
        st.enabled = st.has_any_proxy();
        Ok(st)
    }

    /// Linux：读单 schema 的 `host:port`，**命令失败即 Err**（对照吞错的 `linux_collect_schema`）。
    /// host 为空 → `Ok(None)`（该协议真的没设，不是读失败）。
    fn linux_collect_schema_strict(
        &self,
        schema: &str,
    ) -> Result<Option<String>, SystemIntegrationError> {
        let host_out = self.run(&linux_gsettings_get_command(schema, "host"))?;
        let Some(host) = parse_gsettings_host(&host_out.stdout) else {
            return Ok(None);
        };
        let port_out = self.run(&linux_gsettings_get_command(schema, "port"))?;
        let port = parse_gsettings_port(&port_out.stdout);
        Ok(Some(format!("{host}:{port}")))
    }
}
