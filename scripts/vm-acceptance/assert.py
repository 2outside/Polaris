#!/usr/bin/env python3
"""判定一个验收场景的证据包。用法：assert.py <证据包目录>

判据写在这里而不是 runbook 里：文档里的判定表对执行没有强制力，同一张表在不同天会被
执行成不同结果。这里退出码即结论（0=通过，1=不通过，2=证据不可用）。

**每条「必须没有」都配一条「必须有」**：否则「没观测到」既可能是守卫生效、也可能是心跳
压根没上场，两者不可分辨。`plain-broken` 是全部静默结论的对照组，必须与它同批跑。
"""

import pathlib
import re
import sys

# 心跳在起核处对本世代求一次值、只打一行（`runtime/proxy/auto_switch.rs`）。
BLOCKED = "自动换节点本世代不工作"
ENABLED = "自动换节点已启用"
PROBE_FAIL = "连通性检测失败"
TRIGGERED = "连续 3 次失败"
# Fix 3：触发了、候选也规划出来了，但都要整核重启才切得过去。
NEEDS_RESTART = "需要重启内核才能切换过去"
# 登录期出口让位：组网出口未登录 ⇒ 默认路由主动让给直连（runtime/proxy/login_fallback.rs）。
LOGIN_FALLBACK = "登录期默认路由让位直连"
# 组网兜底：外网回退直连（config-engine 生成期 WARN）。
MESH_FALLBACK = "外网流量已回退直连"
# §6.1 门③ 修的误报：兜底直连是设计语义，不该报「实际出口为直连」。
EXIT_MISMATCH = "实际出口为直连"

# 每个场景：(必须出现, 必须不出现, 一句话说明这条在验什么)
EXPECT = {
    "plain-broken": (
        [ENABLED, PROBE_FAIL, TRIGGERED],
        [BLOCKED],
        "正向对照：普通节点出口不通 ⇒ 心跳必须响。它红了，所有『静默』结论都作废。",
    ),
    "ts-no-exit": (
        [BLOCKED, MESH_FALLBACK],
        [PROBE_FAIL, EXIT_MISMATCH],
        "TS 未配 exit node ⇒ 不承载公网 ⇒ 停摆并只播报一行；且门③ 不得误报直连出口。",
    ),
    "wg-intranet-only": (
        [BLOCKED, MESH_FALLBACK],
        [PROBE_FAIL, EXIT_MISMATCH],
        "WG 显式关掉『允许访问外网』⇒ 同上。",
    ),
    "wg-fulltunnel-subnets": (
        [ENABLED, PROBE_FAIL, TRIGGERED, NEEDS_RESTART],
        [BLOCKED],
        "H1 回归位：全隧道带段的 WG 承载公网 ⇒ 心跳必须响；候选被热切守卫全剔 ⇒ 必须上报需手动切换。",
    ),
    "ts-exit-no-daemon": (
        [ENABLED, LOGIN_FALLBACK],
        [BLOCKED],
        "TS 配了 exit node 但未登录 ⇒ 承载公网 ⇒ 心跳必须上场；走的是登录期让位直连，"
        "探针与用户流量同在直连上，故**不**期望连通性失败。（这不是 A4-b，A4-b 需真 tailnet。）",
    ),
}


def check(evidence: pathlib.Path) -> int:
    scen = evidence.name
    if scen not in EXPECT:
        print(f"未知场景 {scen}", file=sys.stderr)
        return 2
    log_path = evidence / "polaris.log"
    timeline = evidence / "timeline.tsv"
    if not log_path.exists() or not timeline.exists():
        print(f"证据不全：{evidence}", file=sys.stderr)
        return 2
    log = log_path.read_text(errors="replace")

    # ── 先过三道证据可用性闸；任一不过则本场景**无结论**，不是「通过」也不是「不通过」──
    if "config validation failed" in log or "config load fallback" in log:
        print(f"[{scen}] 证据不可用：配置被拒 ⇒ 场景未生效")
        return 2
    if "sing-box 已就绪" not in log:
        print(f"[{scen}] 证据不可用：内核未启动 ⇒ 心跳不可能跑")
        return 2
    shots = len(list(evidence.glob("t*.png")))
    if shots < 4:
        print(f"[{scen}] 证据不可用：只采到 {shots} 个时间点 ⇒ 观测窗被截断")
        return 2

    must, must_not, why = EXPECT[scen]
    bad = []
    for m in must:
        if m not in log:
            bad.append(f"缺少必须出现的「{m}」")
    for m in must_not:
        if m in log:
            n = log.count(m)
            bad.append(f"出现了不该有的「{m}」×{n}")
    # 停摆播报是世代常量，多打就是每 tick 在刷
    if BLOCKED in must and log.count(BLOCKED) != 1:
        bad.append(f"停摆播报出现 {log.count(BLOCKED)} 次，应恰好 1 次（世代常量）")
    # 空转判据：触发次数 > 1 说明在反复重来
    spins = len(re.findall(TRIGGERED, log))
    print(f"[{scen}] {why}")
    print(f"    触发次数={spins} 探测失败={log.count(PROBE_FAIL)} 停摆播报={log.count(BLOCKED)} 采样点={shots}")
    if bad:
        for b in bad:
            print(f"    FAIL: {b}")
        return 1
    print("    PASS")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: assert.py <证据包目录> [更多目录...]", file=sys.stderr)
        return 2
    rc = 0
    for d in sys.argv[1:]:
        rc = max(rc, check(pathlib.Path(d).resolve()))
    return rc


if __name__ == "__main__":
    sys.exit(main())
