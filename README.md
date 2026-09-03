# Polaris

<div align="center">

**简体中文** · [English](README.en.md) · [繁體中文](README.zh-TW.md) · [Русский](README.ru.md) · [فارسی](README.fa.md)

[![release](https://img.shields.io/github/v/release/2outside/Polaris?style=flat-square&color=0E98A4&label=release)](https://github.com/2outside/Polaris/releases/latest)
[![sing-box](https://img.shields.io/badge/sing--box-1.14-0E98A4?style=flat-square)](https://github.com/SagerNet/sing-box)
[![platform](https://img.shields.io/badge/platform-Windows%20%C2%B7%20macOS%20%C2%B7%20Linux-0E98A4?style=flat-square)](#安装)
[![license](https://img.shields.io/badge/license-MIT-0E98A4?style=flat-square)](LICENSE)
[![stars](https://img.shields.io/github/stars/2outside/Polaris?style=flat-square&color=0E98A4)](https://github.com/2outside/Polaris/stargazers)

</div>

**北极星** — 基于 sing-box 的跨平台网络代理客户端。Tauri 2（Rust + React）。

![主页](docs/screenshots/home.png)

## 功能

| 领域 | 能力 |
|---|---|
| 接管方式 | TUN · 系统代理 · 本地端口 |
| 分流 | 智能 / 全局 / 直连 · 自定义规则 · 应用分流 · 地区分流（含回国） |
| 协议 | VLESS · VMess · Trojan · Hysteria 2 / 1 · TUIC · Shadowsocks · AnyTLS · Naive · Snell · SOCKS · HTTP · SSH · Tor · OpenConnect · OpenVPN |
| 组网 | WireGuard · Tailscale · WARP；OpenConnect / OpenVPN 声明了内网段后同样归入 |
| DNS | FakeIP · DoH / DoT · 解析竞速 · IPv6 策略 · 泄漏防护 |
| 诊断 | 连接拓扑 · 实时日志 · 节点测速 · 流媒体与 AI 解锁检测 |
| 运维 | 订阅管理 · 内核在线更新 · 配置备份恢复 · 隐私锁 · 托盘驻留 |
| 应用更新 | 正式版 / 测试版通道 · 可重新下载当前版本 · 安装包摘要校验 |
| 内存优化 | 界面隐藏或最小化 10 分钟后自动释放主 WebView；统计、连接与日志按需订阅 |

<table>
<tr>
<td width="50%"><img src="docs/screenshots/nodes.png" alt="节点"><br><sub>节点管理与测速</sub></td>
<td width="50%"><img src="docs/screenshots/rules.png" alt="规则"><br><sub>自定义分流规则</sub></td>
</tr>
<tr>
<td><img src="docs/screenshots/connections.png" alt="连接"><br><sub>实时连接</sub></td>
<td><img src="docs/screenshots/settings.png" alt="设置"><br><sub>设置</sub></td>
</tr>
</table>

## 安装

从 [Releases](https://github.com/2outside/Polaris/releases) 下载对应平台安装包。

| 平台 | 文件 |
|---|---|
| macOS | `*-mac-arm64.dmg` / `*-mac-x64.dmg` |
| Windows | `*-win-setup.exe`；免安装用 `polaris-portable-*.zip` |
| Linux | `*.deb` / `*.AppImage` |

安装包当前不做付费代码签名，首次启动需按平台放行。

Windows 安装器不内嵌 WebView2 Runtime；系统缺失时会联网获取。精简版 / LTSC 或便携版用户若缺少
Runtime，请先从微软官方下载并安装 [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/)。
Polaris 不提供离线 WebView2 安装包。

### macOS 首次安装

1. 打开 DMG，把 `Polaris.app` 拖到「应用程序（Applications）」；不要直接在 DMG 中运行。
2. 打开「终端」，执行：

   ```bash
   xattr -cr /Applications/Polaris.app
   ```

3. 从「应用程序」启动 Polaris。每次从新下载的 DMG 手动安装或替换应用后执行一次；应用内更新会自行清理隔离属性。

如果 Polaris 安装在其他目录，请把命令中的路径换成实际 `.app` 路径。`xattr -cr` 会递归清除该应用包的
扩展属性，请仅对从本仓库 Releases 下载并确认可信的 Polaris 安装包执行。DMG 根目录的
`README First.txt` 也附有同内容的五语首次打开引导；若只是提示「无法验证开发者」，也可在 Finder 中右键 Polaris →「打开」→ 再次确认。

### Windows 首次安装

SmartScreen 提示时选择「更多信息」→「仍要运行」。

## 构建

需要 Rust stable、Node.js 24+（CI 当前使用 Node 26）、[Tauri CLI 2](https://v2.tauri.app/)。

```bash
node scripts/fetch-core.mjs        # 拉 sing-box 内核（SHA256 钉扎）
node scripts/fetch-cronet.mjs --platform=linux  # 拉与 Linux 核同目录的 libcronet.so
cargo tauri build --config src-tauri/tauri.linux.conf.json
```

内核不入库，打包前必须拉。平台 `--config` 不可省：缺了会打出**没有内核的包**，且构建期零报错，
直到运行期才暴露。完整说明、CI 分工、Windows 安装器与更新器选包契约见
[构建与打包](docs/build-and-package.md)。

开发门禁：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd ui && npx pnpm@11.24.0 test
```

## 架构

```
ui/          React + Zustand + Vite + Tailwind
src-tauri/   Tauri 2 主进程
crates/      17 个 domain crate（config-engine / core-supervisor / helper / updater / …）
resources/   sing-box 内核 + libcronet（构建期拉取，不入库）
```

内核以 sidecar 子进程运行，经 gRPC 管理面通信。需要特权的 TUN 起核与系统接管委托三平台
Rust helper；无需 helper 的 System Proxy 路径由应用侧 `system-integration` 直接管理并负责回滚。

## 文档

| 文件 | 内容 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 当前分层、运行事务、DNS/路由、特权边界与大文件判定准则 |
| [docs/build-and-package.md](docs/build-and-package.md) | 构建、CI、打包不变量、更新器选包契约 |
| [docs/troubleshooting.md](docs/troubleshooting.md) | 不签名说明、白屏 / 花屏 / GPU 崩溃排障 |

截图由 `node scripts/capture-screenshots.mjs` 生成：无头 Chrome 渲染前端构建产物 + 注入桩数据，
不需要装应用或起内核。

## 上游

| 项目 | 用途 |
|---|---|
| [sing-box](https://github.com/SagerNet/sing-box) | 代理内核（sidecar 子进程） |
| [Tauri 2](https://github.com/tauri-apps/tauri) | 桌面运行时 |
| [cronet-go](https://github.com/SagerNet/cronet-go) | NaiveProxy 的 libcronet |
| [sing-box-dashboard](https://github.com/SagerNet/sing-box-dashboard) | 内置面板 |
| [meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) | 规则集与地理数据（`.srs`） |

各组件版权归其作者。以子进程 / 二进制形式集成的组件见 `NOTICE`；链进产物的源码级依赖
（Tauri / React / 数百个 Rust crate）逐包登记在 `THIRD-PARTY-LICENSES.md`。

## 适用范围与免责声明

Polaris 是通用网络代理客户端与诊断工具，不提供、销售或维护代理节点、订阅及网络服务。请仅在遵守
所在地法律法规、服务条款与所在网络管理制度，并已取得必要授权的场景中使用；不得用于未经授权的访问、
侵害他人权益或其它违法滥用。使用者应自行评估配置、节点和第三方资源的可信度，并对使用行为及其后果负责。

本软件按“现状”提供，不承诺网络可用性、匿名性、安全性、特定服务可访问性或数据完整性。TUN、系统代理、
DNS 与路由修改可能暂时影响网络连接；进行重要操作前请备份配置。除适用法律另有强制规定外，维护者与贡献者
不对因使用或无法使用本软件产生的直接或间接损失承担责任。本说明不构成法律或其它专业意见。

## 许可

MIT（见 `LICENSE`）。sing-box（GPLv3）以 sidecar 子进程形式集成（mere aggregation），
不影响本项目许可；第三方组件见 `NOTICE`。

## Star 趋势

<a href="https://www.star-history.com/?repos=2outside%2FPolaris&type=date&legend=top-left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=2outside/Polaris&type=date&theme=dark&legend=top-left&sealed_token=TJg9RA5l3wyd1IgSMMq05QxhNvxS_OcrWbDJxZuwdUwgs-zVIBeoZz2j6swI3y5BxlztkoJMSkkxL6ZbZtw6oyqaRHZSAv0ZS60aVPPuBMdvm8tkxUjyKN1ttiVtPUwJEKObGpBH7BsPhjr6JwFfl_20UYjxgRVOq_V_Q6gKleib6K8LqP3K3nSwPvIJ" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=2outside/Polaris&type=date&legend=top-left&sealed_token=TJg9RA5l3wyd1IgSMMq05QxhNvxS_OcrWbDJxZuwdUwgs-zVIBeoZz2j6swI3y5BxlztkoJMSkkxL6ZbZtw6oyqaRHZSAv0ZS60aVPPuBMdvm8tkxUjyKN1ttiVtPUwJEKObGpBH7BsPhjr6JwFfl_20UYjxgRVOq_V_Q6gKleib6K8LqP3K3nSwPvIJ" />
    <img alt="Polaris Star History Chart" src="https://api.star-history.com/chart?repos=2outside/Polaris&type=date&legend=top-left&sealed_token=TJg9RA5l3wyd1IgSMMq05QxhNvxS_OcrWbDJxZuwdUwgs-zVIBeoZz2j6swI3y5BxlztkoJMSkkxL6ZbZtw6oyqaRHZSAv0ZS60aVPPuBMdvm8tkxUjyKN1ttiVtPUwJEKObGpBH7BsPhjr6JwFfl_20UYjxgRVOq_V_Q6gKleib6K8LqP3K3nSwPvIJ" />
  </picture>
</a>
