#!/usr/bin/env bash
# gate-node-test.sh —— 跑 scripts/ 下的 node --test 用例并自证「确有其事」。
#
# 起因（2026-08-31 全量门规格三修 F3）：`node --test scripts/` 指向空目录、或目标文件
# 被改名/移走、或在错误 cwd 执行时，Node 的 test runner 都是 rc=0（0 tests / 0 pass / 0
# fail），与「全部用例真的跑过且通过」在 shell 层完全不可区分——门会静默判绿。
# 实测：`node --test /空目录/` → rc=0，tests 0 / pass 0 / fail 0。
#
# 分类器与 Cronet 合同是 release-risk 的独立承重面，故先固定要求这些文件存在：目录自动发现不能守住
# 「某一承重文件被删/改名」的情况。执行仍传整个 scripts/ 目录，未来新增 *.test.mjs 也会自动纳入。
#
# AppImage 后处理合同同列必需（2026-09-04）：`appImageRuntimeViolations` 既是**修复方**
# （postprocess-appimage.mjs 重封前自检）又是**判分方**（verify-packaging.mjs payload 门 import
# 同一个函数），两侧共用一份判据 ⇒ 谓词退化成恒绿时没有任何别的门会红。那组用例的承重面是把
# 2026-08-24 真机上那个坏 AppDir 的形态原样回放、断言必须报满 5 项，即这条链路唯一的反向对照。
#
# CI（.github/workflows/release-risk.yml）与本机全量门单（vault SoT §12.3c）都调用本脚本，
# 而不是各自重复一份 `node --test scripts/`，以免两处判据将来各自漂移。
set -euo pipefail
cd "$(dirname "$0")/.."

required_tests=(
  scripts/classify-ci-impact.test.mjs
  scripts/fetch-cronet.test.mjs
  scripts/postprocess-appimage.test.mjs
)
for file in "${required_tests[@]}"; do
  [ -f "$file" ] || {
    echo "::error::gate-node-test: 必需测试文件缺失：$file" >&2
    exit 1
  }
done

out="$(node --test --test-reporter=tap scripts/ 2>&1)"
printf '%s\n' "$out"

pass="$(printf '%s\n' "$out" | grep -E '^# pass [0-9]+$' | awk '{print $3}')"
if [ -z "${pass:-}" ]; then
  echo "::error::gate-node-test: 未能从输出里解析出 '# pass N' 行，TAP 格式可能变了" >&2
  exit 1
fi
if [ "$pass" -lt 40 ]; then
  echo "::error::gate-node-test: 只 pass 了 $pass 条（当前固定合同共 40 条；下限 40）—— 必需合同测试是否被误删/改名/漏跑？" >&2
  exit 1
fi
