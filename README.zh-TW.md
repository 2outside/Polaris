# Polaris

<div align="center">

[简体中文](README.md) · [English](README.en.md) · **繁體中文** · [Русский](README.ru.md) · [فارسی](README.fa.md)

[![release](https://img.shields.io/github/v/release/2outside/Polaris?style=flat-square&color=0E98A4&label=release)](https://github.com/2outside/Polaris/releases/latest)
[![sing-box](https://img.shields.io/badge/sing--box-1.14-0E98A4?style=flat-square)](https://github.com/SagerNet/sing-box)
[![platform](https://img.shields.io/badge/platform-Windows%20%C2%B7%20macOS%20%C2%B7%20Linux-0E98A4?style=flat-square)](#安裝)
[![license](https://img.shields.io/badge/license-MIT-0E98A4?style=flat-square)](LICENSE)
[![stars](https://img.shields.io/github/stars/2outside/Polaris?style=flat-square&color=0E98A4)](https://github.com/2outside/Polaris/stargazers)

</div>

**北極星** — 基於 sing-box 的跨平台網路代理用戶端。Tauri 2（Rust + React）。

![首頁](docs/screenshots/home.png)

## 功能

| 領域 | 能力 |
|---|---|
| 接管方式 | TUN · 系統代理 · 本機連接埠 |
| 分流 | 智慧 / 全域 / 直連 · 自訂規則 · 應用程式分流 · 地區分流（含回國） |
| 通訊協定 | VLESS · VMess · Trojan · Hysteria 2 / 1 · TUIC · Shadowsocks · AnyTLS · Naive · Snell · SOCKS · HTTP · SSH · Tor · OpenConnect · OpenVPN |
| 組網 | WireGuard · Tailscale · WARP；OpenConnect / OpenVPN 宣告了內網網段後同樣歸入 |
| DNS | FakeIP · DoH / DoT · 解析競速 · IPv6 策略 · 洩漏防護 |
| 診斷 | 連線拓撲 · 即時記錄 · 節點測速 · 串流與 AI 解鎖偵測 |
| 維運 | 訂閱管理 · 核心線上更新 · 設定備份還原 · 隱私鎖 · 系統匣常駐 |
| 應用程式更新 | 正式版 / 測試版通道 · 可重新下載目前版本 · 安裝檔摘要驗證 |
| 記憶體最佳化 | 介面隱藏或最小化 10 分鐘後自動釋放主 WebView；統計、連線與記錄按需訂閱 |

<table>
<tr>
<td width="50%"><img src="docs/screenshots/nodes.png" alt="節點"><br><sub>節點管理與測速</sub></td>
<td width="50%"><img src="docs/screenshots/rules.png" alt="規則"><br><sub>自訂分流規則</sub></td>
</tr>
<tr>
<td><img src="docs/screenshots/connections.png" alt="連線"><br><sub>即時連線</sub></td>
<td><img src="docs/screenshots/settings.png" alt="設定"><br><sub>設定</sub></td>
</tr>
</table>

## 安裝

從 [Releases](https://github.com/2outside/Polaris/releases) 下載對應平台的安裝檔。

| 平台 | 檔案 |
|---|---|
| macOS | `*-mac-arm64.dmg` / `*-mac-x64.dmg` |
| Windows | `*-win-setup.exe`；免安裝版用 `polaris-portable-*.zip` |
| Linux | `*.deb` / `*.AppImage` |

安裝檔目前不做付費程式碼簽章，首次啟動需依平台放行。

Windows 安裝程式不內嵌 WebView2 Runtime；系統缺少時會連網取得。精簡版 / LTSC 或免安裝版使用者若缺少
Runtime，請先從微軟官方下載並安裝 [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/)。
Polaris 不提供離線 WebView2 安裝檔。

### macOS 首次安裝

1. 開啟 DMG，把 `Polaris.app` 拖到「應用程式（Applications）」；不要直接在 DMG 中執行。
2. 開啟「終端機」，執行：

   ```bash
   xattr -cr /Applications/Polaris.app
   ```

3. 從「應用程式」啟動 Polaris。每次從新下載的 DMG 手動安裝或替換應用程式後執行一次；應用程式內更新會自行清除隔離屬性。

如果 Polaris 安裝在其他目錄，請把指令中的路徑換成實際的 `.app` 路徑。`xattr -cr` 會遞迴清除該應用程式套件的
擴充屬性，請僅對從本儲存庫 Releases 下載並確認可信的 Polaris 安裝檔執行。DMG 根目錄的
`README First.txt` 也附有同內容的五語首次開啟導引；若只是提示「無法驗證開發者」，也可在 Finder 中按右鍵 Polaris →「打開」→ 再次確認。

### Windows 首次安裝

SmartScreen 提示時選擇「其他資訊」→「仍要執行」。

## 建置

需要 Rust stable、Node.js 24+（CI 目前使用 Node 26）、[Tauri CLI 2](https://v2.tauri.app/)。

```bash
node scripts/fetch-core.mjs        # 拉取 sing-box 核心（SHA256 釘扎）
node scripts/fetch-cronet.mjs      # 拉取 libcronet
cargo tauri build --config src-tauri/tauri.linux.conf.json
```

核心不入庫，打包前必須拉取。平台 `--config` 不可省：缺了會打出**沒有核心的安裝檔**，且建置期零錯誤，
直到執行期才暴露。完整說明、CI 分工、Windows 安裝程式與更新器選檔契約見
[建置與打包](docs/build-and-package.md)。

開發門檻：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd ui && npm test
```

## 架構

```
ui/          React + Zustand + Vite + Tailwind
src-tauri/   Tauri 2 主行程
crates/      17 個 domain crate（config-engine / core-supervisor / helper / updater / …）
resources/   sing-box 核心 + libcronet（建置期拉取，不入庫）
```

核心以 sidecar 子行程執行，經 gRPC 管理面通訊。TUN 與系統代理由三平台特權 helper 承擔
（macOS / Windows / Linux，全 Rust）。

## 文件

| 檔案 | 內容 |
|---|---|
| [docs/build-and-package.md](docs/build-and-package.md) | 建置、CI、打包不變量、更新器選檔契約 |
| [docs/troubleshooting.zh-TW.md](docs/troubleshooting.zh-TW.md) | 不簽章說明、白畫面 / 花屏 / GPU 當機排障 |

截圖由 `node scripts/capture-screenshots.mjs` 產生：無頭 Chrome 算繪前端建置產物 + 注入樁資料，
不需要安裝應用程式或啟動核心。

## 上游

| 專案 | 用途 |
|---|---|
| [sing-box](https://github.com/SagerNet/sing-box) | 代理核心（sidecar 子行程） |
| [Tauri 2](https://github.com/tauri-apps/tauri) | 桌面執行階段 |
| [cronet-go](https://github.com/SagerNet/cronet-go) | NaiveProxy 的 libcronet |
| [sing-box-dashboard](https://github.com/SagerNet/sing-box-dashboard) | 內建面板 |
| [meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) | 規則集與地理資料（`.srs`） |

各元件版權歸其作者。以子行程 / 二進位形式整合的元件見 `NOTICE`；連結進產物的原始碼層相依套件
（Tauri / React / 數百個 Rust crate）逐一登記在 `THIRD-PARTY-LICENSES.md`。

## 適用範圍與免責聲明

Polaris 是通用網路代理用戶端與診斷工具，不提供、銷售或維運代理節點、訂閱及網路服務。請僅在遵守
所在地法律法規、服務條款與所在網路管理制度，並已取得必要授權的情境中使用；不得用於未經授權的存取、
侵害他人權益或其他違法濫用。使用者應自行評估設定、節點與第三方資源的可信度，並對使用行為及其後果負責。

本軟體按「現狀」提供，不承諾網路可用性、匿名性、安全性、特定服務可存取性或資料完整性。TUN、系統代理、
DNS 與路由變更可能暫時影響網路連線；進行重要操作前請備份設定。除適用法律另有強制規定外，維護者與貢獻者
不對因使用或無法使用本軟體所產生的直接或間接損失承擔責任。本說明不構成法律或其他專業意見。

## 授權

MIT（見 `LICENSE`）。sing-box（GPLv3）以 sidecar 子行程形式整合（mere aggregation），
不影響本專案授權；第三方元件見 `NOTICE`。

## Star 趨勢

<a href="https://www.star-history.com/?repos=2outside%2FPolaris&type=date&legend=top-left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=2outside/Polaris&type=date&theme=dark&legend=top-left&sealed_token=TJg9RA5l3wyd1IgSMMq05QxhNvxS_OcrWbDJxZuwdUwgs-zVIBeoZz2j6swI3y5BxlztkoJMSkkxL6ZbZtw6oyqaRHZSAv0ZS60aVPPuBMdvm8tkxUjyKN1ttiVtPUwJEKObGpBH7BsPhjr6JwFfl_20UYjxgRVOq_V_Q6gKleib6K8LqP3K3nSwPvIJ" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=2outside/Polaris&type=date&legend=top-left&sealed_token=TJg9RA5l3wyd1IgSMMq05QxhNvxS_OcrWbDJxZuwdUwgs-zVIBeoZz2j6swI3y5BxlztkoJMSkkxL6ZbZtw6oyqaRHZSAv0ZS60aVPPuBMdvm8tkxUjyKN1ttiVtPUwJEKObGpBH7BsPhjr6JwFfl_20UYjxgRVOq_V_Q6gKleib6K8LqP3K3nSwPvIJ" />
    <img alt="Polaris Star History Chart" src="https://api.star-history.com/chart?repos=2outside/Polaris&type=date&legend=top-left&sealed_token=TJg9RA5l3wyd1IgSMMq05QxhNvxS_OcrWbDJxZuwdUwgs-zVIBeoZz2j6swI3y5BxlztkoJMSkkxL6ZbZtw6oyqaRHZSAv0ZS60aVPPuBMdvm8tkxUjyKN1ttiVtPUwJEKObGpBH7BsPhjr6JwFfl_20UYjxgRVOq_V_Q6gKleib6K8LqP3K3nSwPvIJ" />
  </picture>
</a>
