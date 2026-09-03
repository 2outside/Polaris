#!/usr/bin/env python3
"""把一份 Polaris `config.json` 打成某个验收场景的形态。

纯函数：stdin 读原配置、stdout 写新配置，不碰文件系统、不联网。**只做补丁不做重建**——
默认配置有 57 个键，重建必然漏字段，而漏掉的那个会在真机上表现成别的故障。

场景名即判据名。每个场景写清「选中什么 / 期望心跳跑不跑 / 为什么」，因为这几条正是
2026-09-03 那批修复的回归面：`auto_switch_blocked_for_generation` 只该拦「不承载公网」的
组网出口，拦多了就是它自己要消灭的那种盲区。
"""

import json
import sys

# 不可路由：TEST-NET-2（RFC 5737）。用它制造「出口必然不通」，全程不碰宿主网络。
DEAD = "198.51.100.1"

# 全零 32 字节的 base64。wireguard 的必填面是**三项**（`store::validate::protocol_requirement_ok`）：
# privateKey + peerPublicKey + 非空 localAddress。少任何一项 `sanitize_servers` 都会把整条节点
# 剔掉，而落盘的 config.json 里它还在 —— 起核时只报一句「Selected server not found」。
WG_FAKE_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def _plain(node_id: str, name: str, address: str, port: int = 1080) -> dict:
    """普通代理节点（socks，字段最少 ⇒ 最不容易因缺字段被判无效而改变判据）。"""
    return {
        "id": node_id,
        "name": name,
        "protocol": "socks",
        "address": address,
        "port": port,
    }


def _wg(node_id: str, name: str, *, allow_internet, always_route_subnets, subnets) -> dict:
    """WG 组网节点。

    **段填 `wireguardSettings.allowedIPs`，不是顶层 `meshRoutes`**：
    `endpoint_forced_route_cidrs` 对 wireguard 读的是 `allowedIPs`（剥掉 catch-all 后），
    顶层 `meshRoutes` 只对 Openconnect / OpenvpnClient 生效。填错字段不会报错，只会让
    `sel_only_forces_subnets` 恒假 —— 于是「候选被热切守卫全剔」那条链根本不被走到，
    而日志里 `需重启=0` 看着像通过。踩过一次。
    """
    n = {
        "id": node_id,
        "name": name,
        "protocol": "wireguard",
        "address": DEAD,
        "port": 51820,
        # `store::validate::protocol_requirement_ok` 对 wireguard **必填** privateKey +
        # peerPublicKey，缺了 `sanitize_servers` 会把整个节点剔掉，生成期只报一句
        # 「Selected server not found」—— 排查时看不出是被清洗掉的。踩过一次。
        # 这里用全零 32 字节的 base64：结构合法、明显伪造、不连任何东西。
        "wireguardSettings": {
            "privateKey": WG_FAKE_KEY,
            "peerPublicKey": WG_FAKE_KEY,
            "localAddress": ["10.9.0.2/32"],
        },
    }
    if allow_internet is not None:
        n["wireguardSettings"]["allowInternet"] = allow_internet
    if always_route_subnets is not None:
        n["wireguardSettings"]["alwaysRouteSubnets"] = always_route_subnets
    if subnets:
        n["wireguardSettings"]["allowedIPs"] = list(subnets)
    return n


def _ts(node_id: str, name: str, *, exit_node) -> dict:
    n = {"id": node_id, "name": name, "protocol": "tailscale", "tailscaleSettings": {}}
    if exit_node is not None:
        n["tailscaleSettings"]["exitNode"] = exit_node
    return n


# 两个 clean 候选。地址同样不可路由 —— 本 harness 判的是「心跳跑不跑 / 报不报」，
# 不是「切过去通不通」；候选真能连反而会让「触发后的行为」不稳定。
_CANDIDATES = [_plain("cand-1", "候选一", DEAD, 1081), _plain("cand-2", "候选二", DEAD, 1082)]


def scenario_plain_broken() -> tuple[list, str]:
    """正向对照：普通节点 + 出口不通 ⇒ 心跳**必须**响。

    这条是全部「静默」结论的对照组。没有它，「没观测到失败日志」既可能是守卫生效，
    也可能是心跳压根没挂上，两者不可分辨。
    """
    return [_plain("sel", "选中·普通节点", DEAD, 1080)] + _CANDIDATES, "sel"


def scenario_ts_no_exit() -> tuple[list, str]:
    """TS 未配 exit node ⇒ `mesh_allows_internet` = false ⇒ 停摆原因① 命中，心跳**必须静默**。

    这就是 A4-a 那条「结构性无解、每 90 秒空转一次」的形态，修复后应当一次都不空转。
    """
    return [_ts("sel", "选中·TS 无出口", exit_node=None)] + _CANDIDATES, "sel"


def scenario_wg_intranet_only() -> tuple[list, str]:
    """WG 显式关掉「允许访问外网」⇒ 只走内网 ⇒ 停摆原因① 命中，心跳**必须静默**。"""
    nodes = [
        _wg("sel", "选中·WG 只走内网", allow_internet=False,
            always_route_subnets=None, subnets=["10.9.0.0/24"])
    ]
    return nodes + _CANDIDATES, "sel"


def scenario_wg_fulltunnel_subnets() -> tuple[list, str]:
    """**H1 回归位**：WG 全隧道（allowInternet=true）+ 不恒发段 + 有段。

    撤销前的停摆原因② 会命中这个形态并把心跳整条静音 —— 而它承载公网，探针路径就是
    用户路径，隧道死了用户就断网。故此处心跳**必须响**；触发后热切守卫会把全部候选
    剔掉（进出该形态要增删段规则 ⇒ 只能重启），于是应当看到「需手动切换」那条上报。
    """
    nodes = [
        _wg("sel", "选中·WG 全隧道带段", allow_internet=True,
            always_route_subnets=False, subnets=["10.9.0.0/24"])
    ]
    return nodes + _CANDIDATES, "sel"


def scenario_ts_exit_no_daemon() -> tuple[list, str]:
    """TS 配了 exit node 但**尚未登录** ⇒ `mesh_allows_internet` = true，心跳照常上场。

    **这不是 A4-b。** A4-b 是「已登录、但 exit node 失效」，需要真的接进一个 tailnet 才造得出来，
    可弃 VM 上造不出。本场景实际走的是**登录期出口让位**（`runtime/proxy/login_fallback.rs`）：
    组网出口未登录时默认路由主动让给直连，好让用户去完成登录。于是探针走直连、探得通，
    而用户流量也在直连上 —— 探针路径 == 用户路径，**不构成盲区**，故不期望出现连通性失败。
    本场景验的是「心跳该上场时确实上场了，且没有被误判成停摆」。
    """
    return [_ts("sel", "选中·TS 有出口无守护进程", exit_node="exit-peer")] + _CANDIDATES, "sel"


SCENARIOS = {
    "plain-broken": scenario_plain_broken,
    "ts-no-exit": scenario_ts_no_exit,
    "wg-intranet-only": scenario_wg_intranet_only,
    "wg-fulltunnel-subnets": scenario_wg_fulltunnel_subnets,
    "ts-exit-no-daemon": scenario_ts_exit_no_daemon,
}


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in SCENARIOS:
        print("用法: scenario.py <场景名>  < config.json > new.json", file=sys.stderr)
        print("场景: " + " ".join(sorted(SCENARIOS)), file=sys.stderr)
        return 2
    cfg = json.load(sys.stdin)
    servers, selected = SCENARIOS[sys.argv[1]]()
    cfg["servers"] = servers
    cfg["selectedServerId"] = selected
    cfg["autoSwitchNode"] = True
    # 全程不建 TUN：接管模式钉 `manual`（不接管），路由表与系统代理设置一动不动 ——
    # 心跳探针直连 mixed 端口，不依赖任何接管。合法值只有 systemProxy / tun / manual
    # （`config-engine/src/user_config/proxy_mode.rs:28`），写错整份配置会被校验拒掉并**静默
    # 回落默认配置**，于是场景根本没应用而日志看起来一切正常 —— 踩过，见 assert.py 的 G0。
    cfg["proxyModeType"] = "manual"
    # **必须自动连接**：`decide_tick` 第三道闸就是 `!core_running` ⇒ 跳过并复位失败计数。
    # 核不起，心跳一次都不会跑，那么任何「静默」结论都是无信息量的 —— 分不清是守卫生效
    # 还是心跳压根没上场。
    cfg["autoConnect"] = True
    cfg["desktopNotifications"] = True
    cfg["logLevel"] = "info"
    json.dump(cfg, sys.stdout, ensure_ascii=False, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
