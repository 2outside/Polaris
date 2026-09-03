use super::*;
use crate::commands::guard_scan::top_level_fn_body;
use crate::test_support::crate_code;

fn rules(ids: &[&str]) -> Vec<Value> {
    ids.iter()
            .map(|id| json!({ "id": id, "type": "domain", "values": ["x"], "action": "proxy", "enabled": true }))
            .collect()
}

fn ids_of(rules: &[Value]) -> Vec<&str> {
    rules
        .iter()
        .filter_map(|r| r.get("id").and_then(Value::as_str))
        .collect()
}

fn want(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn plane_writes_keep_schema_v4_and_dns_out_of_traffic_projection() {
    let traffic = rules(&["route-a"]);
    let dns = rules(&["dns-a"]);
    let mut cfg = json!({ "customRules": traffic, "configSchemaVersion": 3 });

    write_plane_rules(&mut cfg, "dnsRules", dns.clone());
    assert_eq!(cfg["configSchemaVersion"], 4);
    assert_eq!(cfg["dnsRules"], Value::Array(dns));
    assert_eq!(
        ids_of(cfg["customRules"].as_array().unwrap()),
        vec!["route-a"]
    );

    let next_traffic = rules(&["route-b"]);
    write_plane_rules(&mut cfg, "trafficRules", next_traffic);
    for key in ["trafficRules", "policyRules", "customRules"] {
        assert_eq!(
            ids_of(cfg[key].as_array().unwrap()),
            vec!["route-b"],
            "流量投影 {key} 未同步"
        );
    }
}

#[test]
fn traffic_plane_rejects_every_dns_ownership_field() {
    let route = |extra: Value| {
        json!({
            "id": "route-a",
            "type": "domain",
            "values": ["example.com"],
            "action": "direct",
            "enabled": true,
            "effects": { "route": extra }
        })
    };

    assert!(validate_rule_plane(&route(json!({ "action": "direct" })), "route").is_ok());
    assert!(validate_rule_plane(
        &route(json!({
            "action": "direct",
            "destinationResolution": { "mode": "dnsRules" }
        })),
        "route"
    )
    .is_err());
    assert!(validate_rule_plane(
        &route(json!({ "action": "direct", "resolutionOnly": true })),
        "route"
    )
    .is_err());

    let mut legacy_bypass = route(json!({ "action": "direct" }));
    legacy_bypass["bypassFakeIP"] = json!(true);
    assert!(validate_rule_plane(&legacy_bypass, "route").is_err());

    let mut mixed = route(json!({ "action": "direct" }));
    mixed["effects"]["dns"] = json!({ "enabled": true, "action": { "type": "fakeIp" } });
    assert!(validate_rule_plane(&mixed, "route").is_err());
}

/// 真变化 → 按 orderedIds 逐位重排（规则体随 id 一起搬，不只是搬 id）。
#[test]
fn real_permutation_reorders_bodies() {
    let cur = rules(&["a", "b", "c"]);
    let out = plan_reorder(&cur, &want(&["c", "a", "b"]))
        .expect("合法排列")
        .expect("顺序真变了，须返回新序列");
    assert_eq!(ids_of(&out), vec!["c", "a", "b"]);
    // 搬的是整条规则不是裸 id。
    assert_eq!(out[0]["type"], "domain");
}

/// **净零序 → `Ok(None)`（跳过 save + 广播）**，契约 §Rules「净零序跳过 save」。
///
/// **变异锁**：把 `plan_reorder` 里的 `if unchanged { return Ok(None) }` 删掉（= 退回「恒 save」）
/// → 本断言拿到 `Some(..)` 转红。仅断言「排列合法」不足以杀掉这个变异，故必须断言 `is_none`。
#[test]
fn identical_order_is_net_zero_and_skips_save() {
    let cur = rules(&["a", "b", "c"]);
    assert!(
        plan_reorder(&cur, &want(&["a", "b", "c"]))
            .expect("合法排列")
            .is_none(),
        "逐位相同的顺序必须短路，不得落盘"
    );
    // 空规则集 + 空请求也是净零序（前端在空列表上误发一次 reorder 不该触发整核评估）。
    assert!(plan_reorder(&[], &[]).expect("空集合法").is_none());
}

/// 只挪了一位也算真变化（净零判据是**逐位序列相等**，不是集合相等 —— 集合恒相等）。
///
/// **变异锁**：把净零判据写成「集合相等」→ 本断言会拿到 `None` 转红。
#[test]
fn single_swap_is_not_net_zero() {
    let cur = rules(&["a", "b"]);
    let out = plan_reorder(&cur, &want(&["b", "a"]))
        .expect("合法排列")
        .expect("换位 = 真变化，必须落盘");
    assert_eq!(ids_of(&out), vec!["b", "a"]);
}

/// 非法入参三态：长度不符 / 有重复 / 含未知 id —— 都 Err，且**不得**被净零短路吞掉。
#[test]
fn rejects_non_permutations() {
    let cur = rules(&["a", "b", "c"]);
    assert!(plan_reorder(&cur, &want(&["a", "b"])).is_err(), "长度不符");
    assert!(
        plan_reorder(&cur, &want(&["a", "a", "b"])).is_err(),
        "有重复 id"
    );
    assert!(
        plan_reorder(&cur, &want(&["a", "b", "ghost"])).is_err(),
        "含未知 id"
    );
}

/// 现序里有畸形条目（缺 `id`）时不得误判净零 —— 否则那条坏数据永远修不回来。
#[test]
fn malformed_current_entry_is_not_net_zero() {
    let mut cur = rules(&["a", "b"]);
    cur[0] = json!({ "type": "domain" }); // 缺 id
                                          // 长度仍为 2，但 by_id 只认得 "b" → "a" 属未知 id。
    assert!(plan_reorder(&cur, &want(&["a", "b"])).is_err());
}

/// **接线变异锁**（测方法体 ≠ 测接线）：上面全部断言测的是 `plan_reorder` 这个纯函数。
/// 把命令壳里的 `Ok(None) => return ok_void()` 改回「照常 save + 广播」，它们**一条都不会红**
/// —— 而那正是本条 review 点名的假绿：净零序短路的收益（省一轮整核评估 + 一次全量 config 广播）
/// 全在命令壳那一行上。
///
/// 命令壳带 `State<AppRuntime>`、本仓未引 `tauri::test` → 按本仓既有源码扫描门钉调用点
/// （同 `runtime/rule_resource_scheduler::catalog_leg_cannot_short_circuit_the_resource_leg`）。
#[test]
fn command_shell_short_circuits_on_net_zero_order() {
    // 取材面 = `crud.rs` 全文的**剥注释面**里 `rules_reorder` 自己的函数体。
    //
    // 测试实体外移到 `crud/tests/` 之后，`crud.rs` 里已经不再有任何测试代码，于是「生产正文」
    // 就是全文 —— 此前那行按 `mod reorder_tests {` 切片、用来避开自指命中的写法不再需要。
    //
    // 切片器换成共用的 `top_level_fn_body`，换掉手写那份的两处放水：
    // ① `find("\n}")` 找不到时 `map_or(body.len(), ..)` **静默切到文件尾** ——
    //    守卫失去封顶却不转红，下面两条 `find` 的先后就由别的函数替 `rules_reorder` 作证；
    // ② 锚点缩进不校验（拿它切 `impl` 方法会一路切到整个 impl 块结束）。
    //
    // 取材再过 `crate_code`（剥注释、保留字符串字面量）：本条三条针全是**正面** `find` /
    // `contains`，把 `Ok(None) => return Decision::Skip(Ok(()))` 整行注释掉，注释里那份副本
    // 照样喂饱它们，而净零短路已经没了。
    let body = top_level_fn_body(
        &crate_code("commands/rules/crud.rs"),
        "pub fn rules_reorder(",
    );
    let body = body.as_str();
    let short = body
        .find("Ok(None) => return Decision::Skip(Ok(()))")
        .expect("净零序必须在原子事务闭包中返回 Skip");
    let write = body
        .find("Decision::Write(Ok(()))")
        .expect("真实重排仍须提交事务");
    assert!(short < write, "净零短路必须排在 Write 之前");
    assert!(
        body.contains("Ok((Ok(()), None)) => ok_void()"),
        "Skip 腿必须直接成功且不广播"
    );
}
