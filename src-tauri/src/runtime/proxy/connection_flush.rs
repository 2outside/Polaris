//! TUN 起核就绪后的连接 flush（逼旧连接重连，落到代理链上）。

use std::sync::Arc;
use std::time::Duration;

use polaris_config_engine::user_config::ProxyModeType;
use polaris_singbox_grpc::{Endpoint, SingBoxApiClient};

use super::ProxyRuntime;

/// [`ProxyRuntime::flush_connections_once`] 的结果。
///
/// 做成返回值而不是「内部日志了事」，是为了让两条守卫**可被单测直接断言**：跳过与开枪在日志里
/// 长得一样，只看日志的测试分不出「守卫拦下了」和「压根没走到」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FlushOutcome {
    /// 守卫①拦下：非 TUN 模式。
    SkippedNotTun,
    /// 守卫②拦下：世代已被 stop / 重启接管。
    SkippedSuperseded,
    /// 守卫②拦下：核已停。
    SkippedCoreStopped,
    /// 管理 API 连不上。
    ConnectFailed(String),
    /// `CloseAllConnections` 调用失败。
    CallFailed(String),
    /// 已 RST 全部连接。
    Flushed,
}

/// **#9**：TUN 起核后那一次连接 flush 的延迟（对齐 上游 `CONNECTION_FLUSH_DELAY_MS`）。
///
/// 留这段窗口是给「app 早于 TUN 建立的旧连接」经 TUN 重新进入 sing-box 连接表的时间 ——
/// 就绪那一刻立刻 flush，够不着还没进表的连接，等于白开一枪。
const CONNECTION_FLUSH_DELAY_MS: u64 = 1500;

impl ProxyRuntime {
    /// **#9**：TUN 起核就绪后延迟一次连接 flush（`spawn_crash_monitor` 的世代范式）。
    ///
    /// 为什么需要：app 在 TUN 建立**之前**发起的连接已经泄漏成真实 IP，起核后它们的后续包仍走物理
    /// 网卡直出 —— 用户看到「已连接」，实际那几条连接从未进过代理。延迟一小段后 `CloseAllConnections`
    /// 把它们 RST 掉，逼 app 重连、DNS 经 FakeIP 重新反查，从而落到代理链上。**不重启内核**
    /// （与切节点的 `interruptConnectionsOnSwitch` 开关正交，那条管的是热切换）。
    ///
    /// 代价是无差别 RST 也会重置 flush 之前用户新建的正确连接（app 自行重连、短暂抖动）——
    /// 属「启用代理即断开现有连接」的固有代价，用单次短窗口把误伤面压到最小。
    ///
    /// **两条守卫都在 [`flush_connections_once`](Self::flush_connections_once) 里**，本方法只负责
    /// 「等一段时间再问一次」。刻意不在这里预先判 TUN 早退：判据留在**单一决策点**上，才能被单测直接
    /// 覆盖到；非 TUN 时多出的那个 sleep 任务在 1.5s 后自行退场，代价可忽略。
    ///
    /// 世代守卫替代了 上游的 `clearTimeout` 取消腿：本仓 stop/restart 一律先 bump 世代，
    /// 到点的回调自查即让位，无需再维护一个可取消的 timer 句柄。
    pub(super) fn schedule_connection_flush(
        self: &Arc<Self>,
        mode: ProxyModeType,
        my_gen: u64,
        api_port: u16,
    ) {
        let me = Arc::clone(self);
        // 与 ReassertSettledGuard 的 guard 重叠接棒：本行先 +1，前者随后 Drop -1，门全程不归零。
        let network_settle = mode
            .is_tun()
            .then(|| self.network_settle.begin("tun-post-start-flush"));
        tokio::spawn(async move {
            let _network_settle = network_settle;
            tokio::time::sleep(Duration::from_millis(CONNECTION_FLUSH_DELAY_MS)).await;
            match me.flush_connections_once(mode, my_gen, api_port).await {
                FlushOutcome::Flushed => {
                    log::info!("TUN 起核连接 flush：CloseAllConnections → ok（旧连接已 RST）");
                }
                // best-effort：flush 与起核成功正交，失败只记日志，绝不反向影响已就绪的核。
                FlushOutcome::ConnectFailed(e) => {
                    log::warn!("TUN 起核连接 flush：管理 API 连接失败（apiPort={api_port}）: {e}");
                }
                FlushOutcome::CallFailed(e) => {
                    log::warn!("TUN 起核连接 flush：CloseAllConnections 失败: {e}");
                }
                // 三条跳过腿都是正常形态（非 TUN / 已被接管 / 核已停）→ debug 级，不进用户可见日志。
                skipped => log::debug!("TUN 起核连接 flush 跳过：{skipped:?}"),
            }
        });
    }

    /// [`schedule_connection_flush`](Self::schedule_connection_flush) 的**单一决策点**：两条守卫 + 开枪。
    ///
    /// 守卫漏任何一条都是新 bug，不是「少一层防御」：
    /// 1. **仅 TUN**：`systemProxy` / `manual` 的旧连接多在 sing-box 连接表之外，无差别 RST 够不着
    ///    它们，却会误伤已经过代理的连接 —— 净负收益；
    /// 2. **世代 + 核在跑**：延迟窗口内可能已被 stop / 重启接管，这一枪会打到**已经换掉的核**上，
    ///    把新核刚建立的连接全 RST 掉。`connect` 本身是 await 点，故其后再复查一次。
    pub(super) async fn flush_connections_once(
        &self,
        mode: ProxyModeType,
        my_gen: u64,
        api_port: u16,
    ) -> FlushOutcome {
        if !mode.is_tun() {
            return FlushOutcome::SkippedNotTun;
        }
        if self.gate.generation() != my_gen {
            return FlushOutcome::SkippedSuperseded;
        }
        if !self.status().running {
            return FlushOutcome::SkippedCoreStopped;
        }
        let secret = self.clash_api_secret();
        let client =
            match SingBoxApiClient::connect(Endpoint::new("127.0.0.1", api_port), secret).await {
                Ok(c) => c,
                Err(e) => return FlushOutcome::ConnectFailed(e.to_string()),
            };
        // 建连是 await 点：期间可能被接管 —— 复查过世代才真开枪。
        if self.gate.generation() != my_gen {
            return FlushOutcome::SkippedSuperseded;
        }
        match client.close_all_connections().await {
            Ok(()) => FlushOutcome::Flushed,
            Err(e) => FlushOutcome::CallFailed(e.to_string()),
        }
    }
}
