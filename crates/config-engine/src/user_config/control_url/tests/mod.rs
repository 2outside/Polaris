use super::ControlUrlReject::*;
use super::*;

/// 阳性：内核实测 panic 的每一种形态都必须被判非法。
///
/// 表里每一行都在 2026-07-31 用本机 `resources/linux/sing-box`（1.14.0-beta.3）跑过
/// `sing-box check`，结论逐条对齐（panic → 这里必 `Some`）。
///
/// **这条实测断言只覆盖标了「实测」的行**。核**接受**但我们仍拦的形态一律归
/// [`intentionally_stricter_than_upstream`]，不许混进来 —— 混进来会让「panic ⟺ 这里 Some」
/// 这个双向对齐变成单向，日后有人「对齐上游」时就分不清哪些能放、哪些放了会炸。
/// （`//hs.example.com` 曾被误归本表，2026-07-31 实测证否后已移走。）
///
/// **变异实测**：把 `tailscale_control_url_reject` 里的 `if is_ip_host(host)` 那条删掉
/// ⇒ 本测 10 条 IP 形态全红。
#[test]
fn ip_literal_forms_all_rejected() {
    for url in [
        "http://192.168.1.10:8080",         // 实测 PANIC
        "http://192.168.1.10",              // 无端口，实测 PANIC
        "https://192.168.1.10:8080",        // scheme 无关，实测 PANIC
        "http://192.168.1.10:8080/key",     // 带 path，实测 PANIC
        "http://user:pw@192.168.1.10:8080", // 带 userinfo，实测 PANIC
        "http://127.0.0.1:39824",           // 陈先生原始复现样本
        "https://127.0.0.1:39824",          // 同上，https
        "http://0.0.0.0:8080",              // 实测 PANIC
        "https://203.0.113.9",              // 公网 IP，实测 PANIC
        "ws://192.168.1.10:8080",           // 非 http scheme 照样 PANIC
    ] {
        assert_eq!(
            tailscale_control_url_reject(url),
            Some(IpLiteral),
            "IPv4 形态未被判为 IP 字面量: {url}"
        );
    }
}

/// 阳性：IPv6 各形态（方括号 / 带端口 / zone / v4-mapped / 大写）实测同样 panic。
///
/// **变异实测**：删掉 `is_ip_host` 里的 `h.split('%').next()` zone 截断
/// ⇒ `[fe80::1%25eth0]` 一条转红（Rust `IpAddr` 不认 zone，会漏判成域名 = fail-open）。
#[test]
fn ipv6_forms_all_rejected() {
    for url in [
        "http://[fd7a:115c:a1e0::1]:8080",    // 实测 PANIC
        "http://[::1]",                       // 无端口，实测 PANIC
        "http://[::1]:39824",                 // 实测 PANIC
        "http://[::ffff:192.168.1.10]:8080",  // v4-mapped，实测 PANIC
        "http://[2001:db8:0:0:0:0:0:1]:8080", // 全展开，实测 PANIC
        "http://[FD7A:115C::1]:8080",         // 大写 hex，实测 PANIC
        "http://[fe80::1%25eth0]:8080",       // 带 zone id，实测 PANIC
    ] {
        assert_eq!(
            tailscale_control_url_reject(url),
            Some(IpLiteral),
            "IPv6 形态未被判为 IP 字面量: {url}"
        );
    }
}

/// 阳性：缺 scheme —— 与填 IP 是**同一处** panic，且是更常见的手滑。
///
/// **变异实测**：把 `let Some(pos) = s.find("://") else { ... }` 改成 `.unwrap_or(0)` 之类的放行写法
/// ⇒ 本测全红。
#[test]
fn missing_scheme_rejected() {
    for url in [
        "hs.example.com",    // 实测 PANIC（url.Parse 成功但 Host 为空）
        "not-a-url",         // 实测 PANIC
        "192.168.1.10:8080", // 无 scheme 的 IP 写法
        "mailto:a@b.com",    // 有冒号但无 `://`
    ] {
        assert_eq!(
            tailscale_control_url_reject(url),
            Some(MissingScheme),
            "缺 scheme 未被拦: {url}"
        );
    }
}

/// 阳性：有 scheme 但 host 缺失 —— 实测同样 panic。
#[test]
fn empty_host_rejected() {
    assert_eq!(tailscale_control_url_reject("http://"), Some(NoHost));
    assert_eq!(tailscale_control_url_reject("http://:8080"), Some(NoHost));
    assert_eq!(tailscale_control_url_reject("http:///path"), Some(NoHost));
}

/// 阳性：畸形 host。内核这几条是 `parse control URL` FATAL（不是 panic），但 FATAL 会拖垮**整个核**
/// （所有节点一起断），比丢掉一个节点更糟 → 一样拦。
#[test]
fn malformed_host_rejected() {
    // 内嵌空白：实测 `parse control URL` FATAL。
    assert_eq!(
        tailscale_control_url_reject("http://192.168.1.10 :8080"),
        Some(Malformed)
    );
    // 方括号不配平。
    assert_eq!(tailscale_control_url_reject("http://[::1"), Some(Malformed));
    // 裸 IPv6（无方括号）：上游当域名放行，但它永远解析不出去。
    assert_eq!(
        tailscale_control_url_reject("http://fd7a::1"),
        Some(Malformed)
    );
    // 方括号里塞 IPv4：内核 `parse control URL` FATAL；本模块给更有用的「别填 IP」。
    assert_eq!(
        tailscale_control_url_reject("http://[192.168.1.10]:8080"),
        Some(IpLiteral)
    );
}

/// **阴性对照（最重要的一条）**：合法域名写法一个都不许被误伤。
///
/// 这里每一条也都实测 `sing-box check` **通过**。少了这条对照，把判据写成「一律拒」也能让上面
/// 五条阳性全绿 —— 那样的门只是把 panic 换成了「谁都连不上」。
///
/// `localhost` 归**合法**侧：上游 `M.ParseSocksaddr("localhost").IsDomain()` 为 true
/// ⇒ 走 resolveDialer 分支 ⇒ 实测 check 通过、不 panic。自建 headscale 用 `http://localhost:8080`
/// 是常见写法，拦它属于纯误伤。
///
/// **变异实测**：把 `is_ip_host` 改成恒 `true` ⇒ 本测全红（而五条阳性仍全绿）。
#[test]
fn domain_forms_never_rejected() {
    for url in [
        "https://hs.example.com",             // 实测 PASS
        "http://example.invalid",             // 实测 PASS
        "https://headscale.local:8080",       // 实测 PASS
        "http://localhost:8080",              // 实测 PASS —— 不是 IP，不许拦
        "http://localhost",                   // 实测 PASS
        "https://controlplane.tailscale.com", // 官方默认值
        "https://hs.example.com.:8080",       // 尾点 FQDN，实测 PASS
        "http://1.2.3.4.5:8080",              // 五段 → 不是 IPv4，实测 PASS
        "http://12345",                       // 纯数字但非 IP，实测 PASS
        "HTTPS://HS.EXAMPLE.COM",             // 大写 scheme，实测 PASS
        "https://hs.example.com/key/path",    // 带 path
        "https://用户.example.com",           // IDN：白名单式 host 校验会误伤，故只列否定字符
    ] {
        assert_eq!(
            tailscale_control_url_reject(url),
            None,
            "合法域名写法被误伤: {url}"
        );
    }
}

/// 未填 = 合法（内核走 `remoteIsDomain = true` 的 else 分支）。
#[test]
fn empty_is_allowed() {
    assert_eq!(tailscale_control_url_reject(""), None);
    assert_eq!(tailscale_control_url_reject("   "), None);
    assert_eq!(tailscale_control_url_reject("\t\n"), None);
    // 两侧空白会被发射面 trim 掉，等价于已 trim 的值。
    assert_eq!(
        tailscale_control_url_reject("  https://hs.example.com  "),
        None
    );
}

/// 与上游判据的**刻意偏严**：钉住方向，防有人「对齐上游」时把它改回 fail-open。
#[test]
fn intentionally_stricter_than_upstream() {
    // 前导零点分四段：Go netip 拒前导零 ⇒ 上游当域名放行（实测 PASS，不 panic）。
    // 我们判 IP：它 DNS 也解析不出去，给「要填域名」比让核静默连不上有用。
    assert_eq!(
        tailscale_control_url_reject("http://192.168.001.010:8080"),
        Some(IpLiteral),
        "前导零 IPv4 应按 IP 拦（刻意偏严，见模块头注 #1）"
    );
    // 协议相对 URL：**核实测 `sing-box check` 通过，不 panic**（Go `url.Parse("//host")` 给出的
    // Host 是 `host` 而非空——此前本行被误归在 `missing_scheme_rejected` 里、注释写「Go 侧同样
    // Host 为空」，是推理错误，2026-07-31 实测证否后移到这里）。
    //
    // 我们仍然拦，理由与前导零那条同类：① 用户写 `//host` 几乎必然是想写 `https://host` 的手滑；
    // ② check 通过只说明 schema 与初始化那一步不炸，tsnet 后续拿它拼请求是否可用**未验**。
    // 给「请填完整 URL」比让核带着一个可疑控制面静默跑下去有用。
    assert_eq!(
        tailscale_control_url_reject("//hs.example.com"),
        Some(MissingScheme),
        "协议相对 URL 应按缺 scheme 拦（刻意偏严：核接受，我们不接受）"
    );
}

/// token 映射稳定（前端 i18n 映射表按它取键）。
#[test]
fn tokens_are_stable() {
    assert_eq!(reject_token(IpLiteral), "control-url-ip");
    assert_eq!(reject_token(MissingScheme), "control-url-scheme");
    assert_eq!(reject_token(NoHost), "control-url-invalid");
    assert_eq!(reject_token(Malformed), "control-url-invalid");
}
