#!/bin/sh
# Polaris macOS 真机内存采样：只统计显式给定的 GUI 主进程 / 主窗口 WebContent PID；sing-box
# 仅作「代理在整个采样窗内持续运行」的存活门，不混入 app/web 内存。

set -eu

usage() {
  echo "usage: $0 APP_PID [WEB_PID|-] [DURATION_SECS] [INTERVAL_SECS] [STAGE] [OUTPUT_CSV] [CORE_PID|-] [VMMAP_EVERY_SAMPLES]" >&2
  exit 2
}

[ "$(uname -s)" = "Darwin" ] || {
  echo "macos-memory-sample.sh 只能在 macOS 上运行" >&2
  exit 1
}

app_pid=${1:-}
web_pid=${2:--}
duration_secs=${3:-1800}
interval_secs=${4:-60}
stage=${5:-soak}
output_csv=${6:-/tmp/polaris-memory-$(date -u +%Y%m%dT%H%M%SZ).csv}
core_pid=${7:--}
vmmap_every_samples=${8:-0}

for numeric_value in "$app_pid" "$duration_secs" "$interval_secs" "$vmmap_every_samples"; do
  case "$numeric_value" in
    ''|*[!0-9]*) usage ;;
  esac
done
for optional_pid in "$web_pid" "$core_pid"; do
case "$optional_pid" in
  -) ;;
  ''|*[!0-9]*) usage ;;
esac
done
[ "$duration_secs" -ge 0 ] 2>/dev/null || usage
[ "$interval_secs" -gt 0 ] 2>/dev/null || usage
[ "$vmmap_every_samples" -ge 0 ] 2>/dev/null || usage

core_process_alive() {
  sample_pid=$1
  if [ "$sample_pid" = "-" ] || ! kill -0 "$sample_pid" 2>/dev/null; then
    echo 0
    return
  fi
  core_comm=$(ps -o comm= -p "$sample_pid" 2>/dev/null |
    awk 'NR == 1 { sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, ""); print; exit }')
  if [ -n "$core_comm" ] && [ "$(basename "$core_comm")" = "sing-box" ]; then
    echo 1
  else
    echo 0
  fi
}

kill -0 "$app_pid" 2>/dev/null || {
  echo "Polaris APP_PID $app_pid 不存在" >&2
  exit 1
}
if [ "$core_pid" != "-" ] && [ "$(core_process_alive "$core_pid")" -ne 1 ]; then
  echo "CORE_PID $core_pid 不存在或不是 sing-box；代理开启走屏验收不得以停核/错进程样本起跑" >&2
  exit 1
fi
if [ "$vmmap_every_samples" -gt 0 ] && [ "$web_pid" = "-" ]; then
  echo "启用 vmmap 原始旁证时必须显式传 WEB_PID" >&2
  exit 2
fi
[ ! -e "$output_csv" ] || {
  echo "输出文件已存在，不覆盖：$output_csv" >&2
  exit 1
}

vmmap_dir=
if [ "$vmmap_every_samples" -gt 0 ]; then
  vmmap_dir=${output_csv}.vmmap
  [ ! -e "$vmmap_dir" ] || {
    echo "vmmap 输出目录已存在，不覆盖：$vmmap_dir" >&2
    exit 1
  }
  mkdir -p "$vmmap_dir"
fi

process_alive() {
  sample_pid=$1
  if [ "$sample_pid" != "-" ] && kill -0 "$sample_pid" 2>/dev/null; then
    echo 1
  else
    echo 0
  fi
}

footprint_field() {
  sample_pid=$1
  sample_field=$2
  if [ "$sample_pid" = "-" ] || ! kill -0 "$sample_pid" 2>/dev/null; then
    echo 0
    return
  fi
  footprint -f bytes --noCategories -p "$sample_pid" 2>/dev/null |
    awk -v field="$sample_field" '$1 == field ":" { print $2; found=1; exit } END { if (!found) print 0 }'
}

rss_bytes() {
  sample_pid=$1
  if [ "$sample_pid" = "-" ] || ! kill -0 "$sample_pid" 2>/dev/null; then
    echo 0
    return
  fi
  rss_kib=$(ps -o rss= -p "$sample_pid" 2>/dev/null |
    awk 'NR == 1 && $1 ~ /^[0-9]+$/ { print $1; found=1 } END { if (!found) print 0 }')
  echo $((rss_kib * 1024))
}

echo "timestamp_utc,stage,app_pid,app_alive,app_phys_bytes,app_peak_bytes,app_rss_bytes,web_pid,web_alive,web_phys_bytes,web_peak_bytes,web_rss_bytes,core_pid,core_alive" > "$output_csv"
started_at=$(date +%s)
sample_index=0
while :; do
  now=$(date +%s)
  elapsed=$((now - started_at))
  [ "$elapsed" -le "$duration_secs" ] || break

  app_alive=$(process_alive "$app_pid")
  web_alive=$(process_alive "$web_pid")
  core_alive=$(core_process_alive "$core_pid")
  app_phys=$(footprint_field "$app_pid" phys_footprint)
  app_peak=$(footprint_field "$app_pid" phys_footprint_peak)
  app_rss=$(rss_bytes "$app_pid")
  web_phys=$(footprint_field "$web_pid" phys_footprint)
  web_peak=$(footprint_field "$web_pid" phys_footprint_peak)
  web_rss=$(rss_bytes "$web_pid")
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$stage" "$app_pid" "$app_alive" \
    "$app_phys" "$app_peak" "$app_rss" "$web_pid" "$web_alive" "$web_phys" \
    "$web_peak" "$web_rss" "$core_pid" "$core_alive" >> "$output_csv"

  # vmmap 会暂停目标并有观测成本，故只按调用方指定的低频样本间隔保留原始 summary；不把不稳定的
  # category 文本强行解析进 CSV。原文件同时保存 region/category/dirty 明细，验收时可按目标 macOS
  # 版本的真实字段读取，避免跨版本列名变化被脚本悄悄记成 0。
  if [ "$vmmap_every_samples" -gt 0 ] && \
     [ $((sample_index % vmmap_every_samples)) -eq 0 ] && [ "$web_alive" -eq 1 ]; then
    vmmap_file=$(printf '%s/%06d.txt' "$vmmap_dir" "$sample_index")
    if ! vmmap -summary "$web_pid" > "$vmmap_file" 2>&1; then
      echo "vmmap -summary 失败（WEB_PID=$web_pid）" >> "$vmmap_file"
    fi
  fi

  if [ "$app_alive" -ne 1 ]; then
    echo "Polaris APP_PID $app_pid 在采样期间退出；CSV 已保留到失败点" >&2
    exit 3
  fi
  if [ "$core_pid" != "-" ] && [ "$core_alive" -ne 1 ]; then
    echo "sing-box CORE_PID $core_pid 在采样期间退出；代理开启走屏样本无效" >&2
    exit 3
  fi

  [ "$elapsed" -eq "$duration_secs" ] && break
  sample_index=$((sample_index + 1))
  sleep "$interval_secs"
done

echo "$output_csv"
[ -z "$vmmap_dir" ] || echo "$vmmap_dir"
