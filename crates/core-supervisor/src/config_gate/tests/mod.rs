use super::*;

fn rej(raw: &str) -> Option<KernelRejection> {
    parse_kernel_rejection(raw)
}

/// 🔴 **变异锁：decode 阶段的下标必须解出来**。
///
/// 样本逐字取自随包 `resources/linux/sing-box`（1.14.0-beta.7）对构造坏 config 的真实 stderr
/// （`--disable-color`，故无 ANSI）。变异：把 `match_array_segment` 的 `"outbounds["` 改成别的串，
/// 或让 `parse_kernel_rejection` 恒返 None ⇒ 本条全断。
#[test]
fn decode_phase_rejection_carries_index() {
    let r = rej("FATAL[0000] decode config at t.json: outbounds[7]: unknown outbound type: nonexistent-proto")
        .expect("decode 期诊断必须解出下标");
    assert_eq!(r.array, RejectedArray::Outbounds);
    assert_eq!(r.index, 7);
    assert!(
        r.detail.starts_with("outbounds[7]:"),
        "detail 从数组 token 起"
    );

    let r = rej("FATAL[0000] decode config at t.json: endpoints[1]: unknown endpoint type: nope")
        .expect("endpoints 腿");
    assert_eq!(r.array, RejectedArray::Endpoints);
    assert_eq!(r.index, 1);
}

/// 🔴 **变异锁：子键路径（`outbounds[0].obfs`）不得因为 token 后面不是 `:` 就被丢掉**。
///
/// 这类是 custom 透传最常见的坏法（用户 JSON 里某个子块的枚举值写错）。变异：把 `tail.starts_with('.')`
/// 那一支删掉 ⇒ 本条断在 `expect`。
#[test]
fn decode_phase_subkey_path_still_attributes_to_the_node() {
    for (raw, idx) in [
        ("FATAL[0000] decode config at t.json: outbounds[0].obfs: unknown obfs type: bogus", 0),
        ("FATAL[0000] decode config at t.json: outbounds[12].transport: unknown transport type: nope", 12),
        (r#"FATAL[0000] decode config at t.json: outbounds[3].unknown_key: json: unknown field "unknown_key""#, 3),
    ] {
        let r = rej(raw).unwrap_or_else(|| panic!("子键路径也必须归因：{raw}"));
        assert_eq!(r.array, RejectedArray::Outbounds);
        assert_eq!(r.index, idx);
    }
}

/// 🔴 **变异锁：initialize 阶段用的是单数 `outbound[N]`，两种用词都得认**。
///
/// 变异：只留复数前缀 ⇒ 本条断。这条腿覆盖的是「JSON 结构合法但构造期语义不过」的一大类
/// （`unknown method` / `TLS required` / `decode private key` 实测均走此格式）。
#[test]
fn initialize_phase_uses_singular_form() {
    let r =
        rej("FATAL[0000] initialize outbound[3]: unknown method: bad-a").expect("单数 outbound");
    assert_eq!((r.array, r.index), (RejectedArray::Outbounds, 3));
    let r = rej("FATAL[0000] initialize endpoint[1]: decode private key: illegal base64 data at input byte 3")
        .expect("单数 endpoint");
    assert_eq!((r.array, r.index), (RejectedArray::Endpoints, 1));
    let r =
        rej("FATAL[0000] initialize outbound[0]: TLS required").expect("hysteria2 缺 TLS 实测样本");
    assert_eq!(r.index, 0);
}

/// 🔴 **变异锁：拆不出下标的三类真实诊断，一个都不许被归因**。
///
/// 错误归因会剥掉一个本来能用的节点，且用户无从察觉 —— 比不归因坏得多。
#[test]
fn non_node_diagnostics_are_never_attributed() {
    for raw in [
        "FATAL[0000] decode config at t.json: duplicate outbound/endpoint tag: d",
        "FATAL[0000] decode config at t.json: route.rules[0]: unknown rule action: nope",
        "FATAL[0000] initialize router: parse rule-set[0]: open /x/geosite-cn.srs: no such file or directory",
        "FATAL[0000] decode config at t.json: json: cannot unmarshal string into Go value",
        "",
        "   ",
    ] {
        assert_eq!(rej(raw), None, "不得归因：{raw}");
    }
}

/// 🔴 **变异锁：路径必须从 marker 处紧邻锚定，不能在整行里搜同名 token**。
///
/// # 这条锁的是 `strip_prefix`，且它**独立于**上面那道 `tail` 判据
///
/// 两道守卫有重叠：`duplicate outbound/endpoint tag: outbounds[9]` 这类回显，`tail` 判据
/// （token 后须紧跟 `.`/`:`）就已经挡住了。真正只有 `strip_prefix` 挡得住的，是**同名 token
/// 后面恰好也跟着 `.` 或 `:`** 的那一类 —— 下面两条即是（实测：改成 `find` 后它们分别被解成
/// 下标 1 与 5，而正确答案是「这行说的根本不是某个 outbound」）。
///
/// # 第一条现场是用户可达的，不是凑的
///
/// `initialize router: parse rule-set[0]: open <path>: no such file or directory` 是**实测样本**
/// （只是路径不同）。而那个 `<path>` 里有用户控制的成分：自定义规则文件名由用户起
/// （`custom_rules_dir` 下），数据目录路径含用户名。于是只要有一个规则文件叫 `outbounds[1].srs`，
/// 松匹配就会从**文件名**里读出下标 1，然后把第 1 个 outbound —— 一个毫不相干、本来能用的节点
/// —— 静默剥掉。用户看到「我的节点无缘无故没了」，而日志里说的是规则文件的事。
///
/// 第二条（`inbound[0]: … outbound[5]: …` 嵌套主语）是**构造形状**，未在 1.14.0-beta.7 观测到，
/// 按已验证的分隔符规律手工构造，作防御性覆盖（同 `commands/proxy.rs::parse_probe_diagnostic`
/// 对 Windows 路径那一段的取法）。
#[test]
fn array_token_deeper_in_the_message_is_not_a_key_path() {
    for raw in [
        "FATAL[0000] initialize router: parse rule-set[0]: open outbounds[1].srs: no such file or directory",
        "FATAL[0000] initialize inbound[0]: bad outbound[5]: nope",
    ] {
        assert_eq!(
            rej(raw),
            None,
            "非紧邻 marker 的同名 token 不是键路径，据它剥节点会剥掉一个无关的好节点：{raw}"
        );
    }
}

/// 🔴 **变异锁：token 后面必须紧跟 `]` + `.`/`:`，散文里的同名字样不算**。
///
/// 变异：删掉 `tail.starts_with` 那道判据，或把 `body[..close].parse()` 换成宽松解析 ⇒ 本条断。
#[test]
fn malformed_index_tokens_are_rejected() {
    for raw in [
        // 下标非数字 / 为空 / 带符号
        "FATAL[0000] initialize outbound[abc]: x",
        "FATAL[0000] initialize outbound[]: x",
        "FATAL[0000] initialize outbound[+1]: x",
        "FATAL[0000] initialize outbound[ 1]: x",
        // 有下标但后面既不是 `.` 也不是 `:`（= 这不是键路径，是一句话）
        "FATAL[0000] initialize outbound[1] failed for some reason",
        // 没有闭合括号
        "FATAL[0000] initialize outbound[1 : x",
    ] {
        assert_eq!(rej(raw), None, "不得归因：{raw}");
    }
}

/// 取最后一条非空行（Go `log.Fatal` 语义：终止进程的那行永远在最后）。
#[test]
fn picks_last_non_empty_line() {
    let raw =
        "WARN[0000] something noisy\n\nFATAL[0000] initialize outbound[9]: unknown method: x\n\n";
    assert_eq!(rej(raw).expect("取最后一条非空行").index, 9);
}

/// 🔴 **变异锁：健康路径放行；三条非 Rejected 腿全部 fail-open（不阻断起核）**。
///
/// 变异：把 `Unavailable`/`Unattributable` 任一支改成阻断（返回 Peel 或让调用方 Err）⇒ 本条断。
/// 这一条钉的是「核临时读不到 ≠ 一个节点都不能用」这个口径本身。
#[test]
fn only_attributable_rejection_peels_everything_else_fails_open() {
    let zero = Duration::ZERO;
    let b = PEEL_TIME_BUDGET;
    assert_eq!(
        decide_peel(&ConfigCheckVerdict::Accepted, zero, b),
        PeelStep::Proceed
    );
    assert!(matches!(
        decide_peel(&ConfigCheckVerdict::Unavailable("核不存在".into()), zero, b),
        PeelStep::Stop(_)
    ));
    assert!(matches!(
        decide_peel(
            &ConfigCheckVerdict::Unattributable("route.rules[0]".into()),
            zero,
            b
        ),
        PeelStep::Stop(_)
    ));
    let r = KernelRejection {
        array: RejectedArray::Outbounds,
        index: 2,
        detail: "outbounds[2]: unknown outbound type: zzz".into(),
    };
    assert_eq!(
        decide_peel(&ConfigCheckVerdict::Rejected(r.clone()), zero, b),
        PeelStep::Peel(r)
    );
}

/// 🔴 **变异锁：预算耗尽必须停下来放行，而不是继续剥到天荒地老**。
///
/// 变异：删掉 `elapsed >= budget` 那一支 ⇒ 本条断（会返回 Peel）。
/// 同时钉住「预算只拦 Rejected」：Accepted 即使超预算也照样放行（超预算不是失败）。
#[test]
fn budget_exhaustion_stops_peeling_but_never_blocks_a_healthy_config() {
    let r = KernelRejection {
        array: RejectedArray::Outbounds,
        index: 0,
        detail: "outbounds[0]: x".into(),
    };
    let budget = Duration::from_millis(100);
    assert!(matches!(
        decide_peel(
            &ConfigCheckVerdict::Rejected(r),
            Duration::from_millis(100),
            budget
        ),
        PeelStep::Stop(_)
    ));
    assert_eq!(
        decide_peel(
            &ConfigCheckVerdict::Accepted,
            Duration::from_secs(99),
            budget
        ),
        PeelStep::Proceed
    );
}
