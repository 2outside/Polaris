use super::super::{mesh_login_fallback_should_engage, MeshLoginFallbackInput};

/// 让位应生效的基线输入：账号制 TS 全隧道出口、开关开、非 direct、无 authKey、未就绪。
fn engage_baseline() -> MeshLoginFallbackInput {
    MeshLoginFallbackInput {
        fallback_enabled: true,
        proxy_mode_direct: false,
        selected_exit_falls_back_direct: false,
        selected_is_tailscale: true,
        selected_has_auth_key: false,
        selected_tunnel_ready: false,
    }
}

#[test]
fn baseline_engages() {
    assert!(mesh_login_fallback_should_engage(&engage_baseline()));
}

/// 逐一翻转 6 个入参 → 结果必翻假。每个 case = 一条独立逃逸路径（删对应 `&&` 项即某 case 转绿→红）。
#[test]
fn each_condition_flip_disengages() {
    // (标签, 变异闭包)
    type Mutator = fn(&mut MeshLoginFallbackInput);
    let mutators: [(&str, Mutator); 6] = [
        ("fallback_enabled=false", |i| i.fallback_enabled = false),
        ("proxy_mode_direct=true", |i| i.proxy_mode_direct = true),
        ("falls_back_direct=true", |i| {
            i.selected_exit_falls_back_direct = true
        }),
        ("not_tailscale", |i| i.selected_is_tailscale = false),
        ("has_auth_key=true", |i| i.selected_has_auth_key = true),
        ("tunnel_ready=true", |i| i.selected_tunnel_ready = true),
    ];
    for (label, mutate) in mutators {
        let mut input = engage_baseline();
        mutate(&mut input);
        assert!(
            !mesh_login_fallback_should_engage(&input),
            "翻转「{label}」后必须不让位（该条件是死锁形态的必要项）"
        );
    }
}
