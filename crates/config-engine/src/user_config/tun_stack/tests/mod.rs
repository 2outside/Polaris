use super::*;

#[test]
fn auto_resolves_to_platform_default() {
    assert_eq!(resolve_tun_stack(None, "darwin"), ConcreteTunStack::Gvisor);
    assert_eq!(
        resolve_tun_stack(Some(TunStack::Auto), "linux"),
        ConcreteTunStack::System
    );
    // 🔴 Windows auto → gvisor（2026-08-05 起）。改回 system 会同时踩两处：
    // 默认 MTU 掉到 4064（放弃 §0.6 实测的 919 Mbps 那格），且 system 栈永远吃不下大 MTU。
    assert_eq!(
        resolve_tun_stack(Some(TunStack::Auto), "win32"),
        ConcreteTunStack::Gvisor
    );
}

/// 🔴 默认 MTU 的三条判据各锁一格，值来自实测（见 `default_mtu_for` 文档注释）。
///
/// 变异锁：把 65535 写成 9000（或反过来）→ 第一/第二条同时红；把 4064 写成 1350 →
/// 第三条红，且那正是三平台各自复现过的「system 栈丢 1400B UDP 数据报」那个值。
#[test]
fn default_mtu_by_stack_and_platform() {
    // gvisor + Windows：全矩阵最高格（919 Mbps）。
    assert_eq!(default_mtu_for(ConcreteTunStack::Gvisor, "win32"), 65535);
    // gvisor + mac/linux：两平台吞吐实验均无区分力 → 不照搬 65535，取证据最强的 9000。
    assert_eq!(default_mtu_for(ConcreteTunStack::Gvisor, "darwin"), 9000);
    assert_eq!(default_mtu_for(ConcreteTunStack::Gvisor, "linux"), 9000);
    // system / mixed：三平台同值。上界（65535 塌到 11 Mbps）与下界（1350 丢 UDP）之间。
    for p in ["win32", "darwin", "linux"] {
        assert_eq!(default_mtu_for(ConcreteTunStack::System, p), 4064);
        assert_eq!(default_mtu_for(ConcreteTunStack::Mixed, p), 4064);
    }
}

/// 未知平台不得掉进 Windows 那格：65535 只在 wintun + gvisor 上被实测过，
/// 拿它当未知平台的默认是把一个单平台结论外推成通则。
#[test]
fn unknown_platform_gvisor_takes_conservative_mtu() {
    assert_eq!(default_mtu_for(ConcreteTunStack::Gvisor, "freebsd"), 9000);
}

#[test]
fn explicit_honored_all_platforms() {
    // 显式选择全平台 honor，零强制回退（含 mac 选 system）。
    assert_eq!(
        resolve_tun_stack(Some(TunStack::System), "darwin"),
        ConcreteTunStack::System
    );
    assert_eq!(
        resolve_tun_stack(Some(TunStack::Gvisor), "linux"),
        ConcreteTunStack::Gvisor
    );
    assert_eq!(
        resolve_tun_stack(Some(TunStack::Mixed), "win32"),
        ConcreteTunStack::Mixed
    );
}

#[test]
fn unknown_platform_falls_back_system() {
    assert_eq!(resolve_tun_stack(None, "freebsd"), ConcreteTunStack::System);
}
