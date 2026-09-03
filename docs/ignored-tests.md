# 默认不跑的测试（`#[ignore]`）——它们是什么、怎么跑

本仓有一批测试标了 `#[ignore]`：`cargo test` 默认**不执行**它们，报告里显式打 `ignored`。

先说清楚为什么是这个形态。另一种常见写法是「前置条件不满足就 `return`」——那样 cargo 报的是
**ok**：一条从没跑过的测试冒充通过，是假绿。`#[ignore]` 不冒充：它在报告里是独立的一档，
且带理由串。而且被 ignore 的测试**仍然参与编译**，不会烂成编不过的死代码。

代价是另一面：**默认不跑 = 默认没有覆盖**。所以这份文档存在，并且由
`src-tauri/tests/ignored_tests_registry.rs` 强制：每一处 `#[ignore]` 必须登记在那道门的
`REGISTRY` 里、必须带理由、理由必须与类别一致、条目过期即红。**不许有人靠随手加一个
`#[ignore]` 把碍事的测试变哑而全仓仍绿。**

---

## 四个类别

| 类别 | 为什么默认不跑 | 谁来跑 |
|---|---|---|
| **RealCore** | 需要 `POLARIS_SINGBOX_PATH` 指向**真实的 sing-box 二进制**，会真起进程、真占端口 | 真机验收环节，人在场 |
| **PublicNetwork** | 需要公网连通性。CI 与本机开发环境都不保证，且本仓禁止在默认门里碰网络 | 手动，确认网络可用时 |
| **LiveHostState** | 会读或**改写宿主机的真实状态**（路由表 / 系统代理）。跑错机器会把开发机的网络配置改掉 | 专用测试机，人在场 |
| **NotAGate** | 根本不是测试，是打印工具（如逃生门清单）。用 `#[ignore]` 只是为了不进默认门 | 需要那份清单时随手跑 |

---

## 怎么跑

### RealCore

```bash
# 1) 准备一个真实 sing-box 二进制（随包核即可）
export POLARIS_SINGBOX_PATH=/绝对路径/sing-box
# 2) speedtest 那条还需要一个真实网卡名
export POLARIS_TEST_INTERFACE=eth0

# 3) 跑（--ignored 只跑被忽略的那些；--test-threads=1 因为它们抢同一把跨模块真核锁）
cargo test --bin polaris -- --ignored --test-threads=1 real_core_
```

> `real_core_crash_loop_gives_up_without_infinite_restart` 内含 2+5+15s 的退避，单条就要半分钟以上，
> 这是它被单独标注的原因。

**这些测试会真的起停 sing-box 进程。** 不要在正在用代理的机器上跑。

### PublicNetwork

```bash
cargo test --bin polaris -- --ignored real_https_get_handshakes_and_returns_body
```

### LiveHostState

**跑之前先读这一段。** 这一类里 macOS 的两条会**改写宿主机的系统代理设置**；虽然它们自称
「事务后恢复」，但那正是被测对象本身——它坏了就不会恢复。只在可以随手重置网络配置的专用
测试机上跑，且人在场。

```bash
# 路由表（只读，安全）
cargo test --bin polaris -- --ignored live_route_planner_returns_a_real_interface

# Windows 路由（只读，安全；只在 Windows 上编译）
cargo test -p polaris-helper -- --ignored live_best_route_interface_alias_supports_both_families

# macOS 系统代理（**会改写宿主机状态**；只在 macOS 上编译）
cargo test -p polaris-system-integration -- --ignored production_macos_native_proxy_
```

### NotAGate

```bash
cargo test -p polaris --test release_escape_hatches -- --ignored --nocapture inventory
```

---

## 完整清单（18 条）

`src-tauri/tests/ignored_tests_registry.rs` 的 `REGISTRY` 是真值源；本表由它逐条对应，
**每个测试名都必须在本文档里逐字出现**（那道门会逐条核对，前缀兜底已被去掉——它会让 2/3 的条目失守）。

| 测试 | 文件 | 类别 |
|---|---|---|
| `real_core_full_lifecycle` | `src-tauri/src/runtime/proxy/tests/lifecycle.rs` | RealCore |
| `real_core_lifecycle_race_start_then_immediate_stop` | `src-tauri/src/runtime/proxy/tests/lifecycle.rs` | RealCore |
| `real_core_hot_switch_keeps_pid` | `src-tauri/src/runtime/proxy/tests/hot_switch.rs` | RealCore |
| `real_core_auto_failover_attests_without_applying_saved_debt` | `src-tauri/src/runtime/proxy/tests/hot_switch.rs` | RealCore |
| `real_core_hot_switch_failure_falls_back_to_restart` | `src-tauri/src/runtime/proxy/tests/hot_switch.rs` | RealCore |
| `real_core_crash_triggers_auto_restart` | `src-tauri/src/runtime/proxy/tests/recovery.rs` | RealCore |
| `real_core_crash_feeds_diagnostic_restart_axis` | `src-tauri/src/runtime/proxy/tests/recovery.rs` | RealCore |
| `real_core_intentional_stop_does_not_restart` | `src-tauri/src/runtime/proxy/tests/recovery.rs` | RealCore |
| `real_core_crash_loop_gives_up_without_infinite_restart` | `src-tauri/src/runtime/proxy/tests/recovery.rs` | RealCore（含 2+5+15s 退避） |
| `real_core_stale_cleanup_kills_own_orphan_spares_foreign` | `src-tauri/src/runtime/proxy/tests/process_supervision.rs` | RealCore |
| `real_core_accepts_bound_shadow_tls_temp_config` | `src-tauri/src/runtime/speedtest/tests/mod.rs` | RealCore（另需 `POLARIS_TEST_INTERFACE`） |
| `real_core_aggregate_relay_emits_real_frames` | `src-tauri/src/runtime/stats/tests/real_core_tests.rs` | RealCore |
| `real_https_get_handshakes_and_returns_body` | `src-tauri/src/runtime/http/tests/mod.rs` | PublicNetwork |
| `live_route_planner_returns_a_real_interface` | `src-tauri/src/runtime/route_binding/tests/mod.rs` | LiveHostState（只读） |
| `live_best_route_interface_alias_supports_both_families` | `crates/helper/src/platform/windows/wintun/tests/mod.rs` | LiveHostState（只读，Windows-only） |
| `production_macos_native_proxy_transaction_restores_after_takeover` | `crates/system-integration/src/tests/mod.rs` | LiveHostState（**写宿主机**，macOS-only） |
| `production_macos_native_proxy_recovers_across_process_sessions` | 同上 | LiveHostState（**写宿主机**，macOS-only） |
| `inventory` | `src-tauri/tests/release_escape_hatches.rs` | NotAGate |

---

## 平台差异：`ignored` 的数字是平台相关的

源码里共 **18 处** `#[ignore]`，但 `cargo test` 报告里的数字按平台不同：

| 平台 | 报告里的 ignored | 差在哪 |
|---|---|---|
| Linux | 15 | 少了 1 条 Windows-only、2 条 macOS-only（它们被 cfg 掉、不编译） |
| Windows | 16 | 少了 2 条 macOS-only |
| macOS | 17 | 少了 1 条 Windows-only |

所以 `ignored_tests_registry.rs` 数的是**源码里的 18**，不是运行时报告数——前者是平台无关的事实，
后者会在不同 CI 腿上给出不同答案，写死任何一个都会在别的腿上假红。
