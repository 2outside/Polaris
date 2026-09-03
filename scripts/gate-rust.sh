#!/usr/bin/env bash
# gate-rust.sh —— .github/workflows/ci.yml 里 Rust 门（lint-and-test job）的本机镜像。
#
# 起因（2026-09-02）：本机手跑门时用的命令比 CI 弱，本机全绿但取材面比 CI 窄——
# 具体漏了 clippy 的 `--workspace`/`RUSTFLAGS="-D warnings"`，doc 门漏了
# `--bins --lib --document-private-items` 与四个 `-D rustdoc::*`。这份清单不该靠人记，
# 该由脚本逐字镜像 ci.yml。**改 CI 就要改这里**——两边由 gate-rust-ci-parity.test.mjs 钉死一致，
# 改一边不改另一边，那条测试会红。
#
# 为什么 doc 门不能省 `--bins --lib`（照抄 ci.yml「Rustdoc documentation invariants」步骤的
# 头注，用自己的话说一遍）：
#   - `src-tauri` 是 bin crate（没有 lib.rs）。`cargo doc` 不加 `--bins` 时，它的
#     `runtime`/`commands` 等模块整体不进 rustdoc 默认取材面——门读不到，坏链接照样 rc=0。
#   - 反过来只给 `--bins`、不给 `--lib`，会把 `--workspace` 的目标种类收窄成只剩 bin：
#     workspace 里一堆纯 lib 的 crate（`crates/*` 里没有 `[[bin]]` 的那些）被整批排除出取材面，
#     而不是被判「零断链」。
#   两个 flag 互不包含、互不能替代，必须同时给。
#
# 已知噪声（非缺陷）：`cargo doc` 会打两条 cargo#6313 的 warning——workspace 里的 bin crate 与
# lib crate 生成同名产物时的已知上游提示。rc 仍是 0，出现属正常，不代表本门失效。
#
# 资源占位（本脚本不做，只在失败时提示）：`resources/{linux,dashboard,win,mac-arm64,mac-x64}`
# 被 .gitignore 排除，裸 checkout/worktree 下本机通常没有这些目录，tauri 的 build.rs 会在
# build script 阶段报 "resource path doesn't exist" 而让 build 门失败。CI 用同名步骤
# （见 ci.yml「Create resource placeholder dirs」）建空占位目录 + .keep 文件。那是构建前置，
# 不是门本身要做的事，本脚本不替用户建——build 门失败时会打印怎么建。
#
# 硬约束：每条门单独取退出码（不经管道，`cmd | tail` 拿到的 $? 是 tail 的不是 cmd 的），
# 全部跑完再汇总，不因某一条失败就提前退出——故不用 `set -e`。跑法与 ci.yml 里
# 「Cross-target exemptions must still be necessary」步骤同一惯用法：`set -uo pipefail`
# （不含 -e），未绑定变量仍会报错，管道里非末尾命令失败仍会被 pipefail 捕获。
set -uo pipefail
cd "$(dirname "$0")/.."

# --with-cross：额外跑 ci.yml 里那两条**只在 Linux 跑、且需要联网**的跨目标门。
# 默认关闭的理由不是它们不重要，恰恰相反——它们守的是本机根本不编译的代码
# （`#[cfg(windows)]` / `#[cfg(target_os = "macos")]` 块里的错误在本机编译取材面之外）。
# 关掉是因为首次运行要 `rustup target add` 下载目标工具链，而本机门的默认口径不碰网络。
# 目标已装时零下载，跑一次约多花一两分钟。
WITH_CROSS=0
for arg in "$@"; do
  case "$arg" in
    --with-cross) WITH_CROSS=1 ;;
    -h|--help)
      cat <<'USAGE'
用法: scripts/gate-rust.sh [--with-cross]

  默认        跑 ci.yml 的 5 条常规 Rust 门（不联网）
  --with-cross 额外跑两条跨目标门：对 x86_64-pc-windows-msvc 与 x86_64-apple-darwin
               跑 clippy，并检查 scripts/cross-target-exempt.json 的豁免有没有腐烂。
               首次运行会 `rustup target add` 下载目标工具链（联网）。
USAGE
      exit 0 ;;
    *) echo "未知参数: $arg（用 --help 看用法）" >&2; exit 2 ;;
  esac
done

gate_names=()
gate_rcs=()

run_gate() {
  local name="$1"
  shift
  echo
  echo "── ${name} ──"
  "$@"
  local rc=$?
  gate_names+=("$name")
  gate_rcs+=("$rc")
  echo "${name} rc=${rc}"
}

run_gate fmt cargo fmt --all -- --check
run_gate clippy env RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets -- -D warnings
run_gate rustdoc env RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D rustdoc::invalid_html_tags -D rustdoc::private_intra_doc_links -D rustdoc::redundant_explicit_links" cargo doc --no-deps --workspace --bins --lib --document-private-items
run_gate build cargo build --workspace --verbose
run_gate test cargo test --workspace --no-fail-fast

if [ "$WITH_CROSS" = 1 ]; then
  run_gate cross-clippy bash -c '
    set -euo pipefail
    rustup target add x86_64-pc-windows-msvc x86_64-apple-darwin
    # 覆盖面从 workspace 成员**推导**再减去豁免表，不手写清单——新建 crate 默认被覆盖。
    mapfile -t EXEMPT < <(jq -r "keys[]" scripts/cross-target-exempt.json)
    mapfile -t ALL < <(cargo metadata --no-deps --format-version 1 | jq -r ".packages[].name" | sort)
    TARGETS=()
    for p in "${ALL[@]}"; do
      skip=0
      for e in "${EXEMPT[@]}"; do [ "$p" = "$e" ] && skip=1; done
      [ "$skip" = 0 ] && TARGETS+=("-p" "$p")
    done
    echo "cross-check 覆盖 $(( ${#TARGETS[@]} / 2 )) 个包"
    # 「静默零执行」自曝：派生坏掉 / 豁免写宽了在这里红，而不是循环跑 0 个包也绿。
    test "$(( ${#TARGETS[@]} / 2 ))" -ge 16
    # 判据是 clippy -D warnings 不是 cargo check：实测同一份带 field_reassign_with_default 的
    # cfg(windows) 代码，cargo check 同 target rc=0（绿）而 clippy rc=101。
    for t in x86_64-pc-windows-msvc x86_64-apple-darwin; do
      cargo clippy --target "$t" --all-targets "${TARGETS[@]}" -- -D warnings
    done
  '
  run_gate cross-exempt bash -c '
    set -uo pipefail
    rot=0
    for e in $(jq -r "keys[]" scripts/cross-target-exempt.json); do
      for t in $(jq -r --arg e "$e" ".[\$e].targets[]" scripts/cross-target-exempt.json); do
        if cargo clippy --target "$t" --all-targets -p "$e" -- -D warnings >/dev/null 2>&1; then
          echo "豁免已腐烂：$e 现在能过 $t —— 从 scripts/cross-target-exempt.json 删掉它" >&2
          rot=1
        fi
      done
    done
    exit $rot
  '
fi

build_rc=0
for i in "${!gate_names[@]}"; do
  [ "${gate_names[$i]}" = build ] && build_rc="${gate_rcs[$i]}"
done
if [ "$build_rc" -ne 0 ]; then
  cat >&2 <<'EOF'

build 门失败：如果报错含 "resource path doesn't exist"，是本机缺 .gitignore 排除的
resources/{linux,dashboard,win,mac-arm64,mac-x64} 占位目录（不是代码问题）。建齐后重跑：
  for d in dashboard linux win mac-arm64 mac-x64; do mkdir -p "resources/$d" && touch "resources/$d/.keep"; done
EOF
fi

echo
echo "===== gate-rust 汇总 ====="
overall_rc=0
for i in "${!gate_names[@]}"; do
  printf '%-8s rc=%s\n' "${gate_names[$i]}" "${gate_rcs[$i]}"
  [ "${gate_rcs[$i]}" -ne 0 ] && overall_rc=1
done
exit "$overall_rc"
