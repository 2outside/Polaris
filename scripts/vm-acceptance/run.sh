#!/bin/bash
# 在可弃 Linux VM 上跑一个自动故障切换验收场景，产出证据包（不做判定——判定见 assert.py）。
#
# 用法：run.sh <场景名> <观测秒数>
#
# 硬约束（写进脚本而不是文档，因为文档对执行没有强制力）：
#   - 接管模式钉死 system、不建 TUN ⇒ 全程不改路由表，SSH 控制通道不可能断。
#   - 应用生命周期由 `timeout` 界定，脚本不对任何 pid 发信号。
#   - 冷启到首帧实测约 60s（软件渲染的 VM），预热不足会把「还没画」误判成「起不来」。
set -u

SCEN=${1:?缺场景名}
OBS=${2:?缺观测秒数}
APPDIR=/root/.config/com.polaris.app/polaris
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=/var/tmp/polaris-acceptance/$SCEN
WARMUP=75          # > 实测 60s 首帧，留余量
# 每轮用**独占**的 display：复用上一轮的 Xvfb 会继承上一轮的 timeout 预算，
# 那个预算短于本轮时，X server 到期 ⇒ 应用失去 X 连接跟着死 ⇒ 观测窗被悄悄截断，
# 而 timeline 看起来只是「早退」，不会说是 X 没了。踩过一次，代价是一轮 6 分钟白跑。
DISP=$((90 + RANDOM % 60))
export DISPLAY=:$DISP HOME=/root

rm -rf "$OUT"; mkdir -p "$OUT"

# ── 配置：补丁而非重建，保留默认配置的全部 57 个键 ──
python3 "$HERE/scenario.py" "$SCEN" < "$APPDIR/config.json" > "$OUT/config.json" || exit 1
cp "$OUT/config.json" "$APPDIR/config.json"
: > "$APPDIR/logs/polaris.log"
: > "$APPDIR/logs/singbox.log"

# ── Xvfb：本轮独占，预算 = 本轮预算 + 余量（严格长于应用的 timeout）──
setsid timeout $((WARMUP + OBS + 120)) Xvfb :$DISP -screen 0 1400x900x24 -nolisten tcp \
  > "$OUT/xvfb.log" 2>&1 &
for _ in $(seq 1 15); do sleep 1; xdpyinfo -display :$DISP >/dev/null 2>&1 && break; done
xdpyinfo -display :$DISP >/dev/null 2>&1 || { echo "FATAL: Xvfb 起不来 (:$DISP)"; exit 1; }

# ── 应用：生命周期由 timeout 界定 ──
env WEBKIT_DISABLE_COMPOSITING_MODE=1 WEBKIT_DISABLE_DMABUF_RENDERER=1 LIBGL_ALWAYS_SOFTWARE=1 \
  timeout $((WARMUP + OBS)) /usr/bin/polaris > "$OUT/stdout.log" 2>&1 &
APP=$!

echo "场景=$SCEN 预热=${WARMUP}s 观测=${OBS}s 起于 $(date -Is)"
: > "$OUT/timeline.tsv"
printf 't\twebproc\twindow\tcolors\tlog_lines\n' >> "$OUT/timeline.tsv"

t=0
while [ $t -lt $((WARMUP + OBS)) ]; do
  sleep 15; t=$((t + 15))
  [ -d /proc/$APP ] || { echo "应用在 t=${t}s 退出"; break; }
  # pgrep -c 无匹配时**既打印 0 又退非零** ⇒ `|| echo 0` 会追加第二个 0 把 TSV 撑成两行。
  wp=$(pgrep -c -f WebKitWebProcess 2>/dev/null); wp=${wp:-0}
  win=$(xwininfo -root -tree 2>/dev/null | grep -oE '"Polaris":.*' | grep -oE '[0-9]+x[0-9]+\+[0-9-]+\+[0-9-]+' | head -1)
  import -window root "$OUT/t${t}.png" 2>/dev/null
  col=$(identify -format '%k' "$OUT/t${t}.png" 2>/dev/null)
  ll=$(wc -l < "$APPDIR/logs/polaris.log")
  printf '%s\t%s\t%s\t%s\t%s\n' "$t" "$wp" "${win:-none}" "${col:-0}" "$ll" >> "$OUT/timeline.tsv"
  # 首帧之前的截图恒为纯色（占位窗 10x10），不是故障 —— 见 WARMUP 注释。
done

wait $APP 2>/dev/null
cp "$APPDIR/logs/polaris.log" "$OUT/polaris.log" 2>/dev/null
cp "$APPDIR/logs/singbox.log" "$OUT/singbox.log" 2>/dev/null
# ── G0 自曝闸：配置被校验拒掉会**静默回落默认配置**，场景根本没应用而日志一切正常。
# 这是「自动化必须让『没执行』自曝」那条要防的形态，故做成硬失败而不是让人去日志里找。
if grep -q "config validation failed\|config load fallback" "$APPDIR/logs/polaris.log"; then
  echo "G0 FAIL: 配置被拒，本场景未生效（下面这条是原因）"
  grep -m1 "config validation failed" "$APPDIR/logs/polaris.log"
  G0=fail
else
  G0=ok
fi
# ── G1 自曝闸：核没起 ⇒ decide_tick 在 core_running 那道就跳过 ⇒ 任何「静默」结论无信息量。
# 判据必须是「核真的就绪」而不是「走过起核路径」——`起核耗时：孤儿核清扫` 那条在起核
# **失败**时也照打，用它当判据会把「配置生成失败、核压根没起」判成证据可用。踩过一次：
# 一个缺必填字段的节点被 store 清洗掉 ⇒ `Selected server not found` ⇒ 核未起，而 G1 判绿。
if grep -q "sing-box 已就绪" "$APPDIR/logs/polaris.log"; then G1=ok; else
  echo "G1 FAIL: 日志无「sing-box 已就绪」⇒ 内核未启动 ⇒ 心跳不可能跑，本场景的静默/响动都不算数"
  grep -m1 -E "配置生成失败|自动连接失败" "$APPDIR/logs/polaris.log" || true
  G1=fail
fi
# ── G2 自曝闸：观测窗被截断（应用没活满）⇒ 任何「N 秒内没发生 X」的结论都不成立。
LIVED=$(($(ls "$OUT"/t*.png 2>/dev/null | wc -l) * 15))
if [ $LIVED -lt $((WARMUP + OBS - 15)) ]; then
  echo "G2 FAIL: 应用只活了约 ${LIVED}s（预期 $((WARMUP + OBS))s）⇒ 观测窗被截断，禁止据此下「未发生」结论"
  G2=fail
else
  G2=ok
fi
echo "G0(配置生效)=$G0  G1(内核已起)=$G1  G2(观测窗完整)=$G2"

echo "=== 证据包 $OUT ==="
cat "$OUT/timeline.tsv"
echo "--- polaris.log ($(wc -l < "$OUT/polaris.log") 行) ---"
cat "$OUT/polaris.log"
