# 排障

<div align="center">

[简体中文](troubleshooting.md) · [English](troubleshooting.en.md) · **繁體中文** · [Русский](troubleshooting.ru.md) · [فارسی](troubleshooting.fa.md)

</div>

## 不簽章說明（macOS / Windows）

Polaris **不進行程式碼簽章**：

- **macOS**：先把 App 拖入「應用程式」；每次從新下載的 DMG 手動安裝或替換後執行
  `xattr -cr /Applications/Polaris.app`。若只是提示「無法驗證開發者」，也可按右鍵 App →「打開」→ 確認。
  該指令會遞迴清除應用程式套件的擴充屬性，僅應對可信的 Polaris 發佈檔執行；更新程式內建 xattr 清理。
  DMG 內附一份同內容的五語首次開啟導引（`README First.txt`）——
  使用者被 Gatekeeper 擋下時進不了應用程式、也未必看過本檔案，那份導引是他當時唯一能看到的說明。
- **Windows**：SmartScreen「Windows 已保護您的電腦」→「其他資訊」→「仍要執行」。UAC 提權流程
  （helper 安裝 / TUN）照常觸發，僅多一次確認。

簽章會引入憑證成本與簽章清單信任模型，與現有自訂更新管線（VBS / osascript / pkexec 編排）衝突，
故明確不做（見 `updater` crate 說明）。

## 排障：介面白畫面 / 花屏 / GPU 行程反覆當機

多見於 NVIDIA 專有驅動、虛擬機（QEMU 虛擬顯示卡）、遠端桌面（xrdp）等無正常硬體加速的環境 ——
webview 的合成層出不了畫面，但**代理核心本身不受影響**（照常執行與轉發）。

**介面還能操作**（偶發白畫面 / 花屏，重開視窗後能進 UI）→ 設定 → 顯示 →「圖形相容」→ 關掉「硬體加速」→
重新啟動 Polaris。（該區塊在 macOS 不顯示：WKWebView 沒有受支援的停用 GPU 開關。）

**介面完全打不開**（從頭到尾一片空白，點不到設定）→ 下面兩條路都**不需要介面配合**：

### ① 直接編輯 config.json

關掉 Polaris，在設定檔頂層加 `"hardwareAcceleration": false`，再啟動：

| 平台 | 路徑 |
|---|---|
| Linux | `~/.config/com.polaris.app/polaris/config.json` |
| Windows | `%APPDATA%\com.polaris.app\polaris\config.json` |
| macOS | `~/Library/Application Support/com.polaris.app/polaris/config.json` |

```json
{
  "hardwareAcceleration": false
}
```

設定讀取刻意做成容錯優先：檔案損毀 / 欄位型別不對一律回落「預設開」，不會因為這個鍵寫壞而啟動失敗
（判定見 `src-tauri/src/graphics_compat.rs`，建立視窗前直讀原始文字，不依賴 store 組裝成功）。

### ② 平台環境變數（一次性試跑，不改設定）

這些變數由 WebKitGTK / WebView2 **原生讀取，不需要應用程式配合**；Polaris 也刻意不覆寫你已設定的同名變數，
排障時的臨時實驗不會被應用程式打斷。

```bash
# Linux（WebKitGTK）—— DMABUF 是 NVIDIA 白畫面的主要修復，COMPOSITING 兜 resize 當機
WEBKIT_DISABLE_DMABUF_RENDERER=1 WEBKIT_DISABLE_COMPOSITING_MODE=1 polaris
```

```powershell
# Windows（WebView2）
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="--disable-gpu"; .\Polaris.exe
```

macOS 無對應開關（WKWebView 未提供公開 API，WebKit #26651 長期未實作），故 `hardwareAcceleration`
在 mac 上是 no-op（應用程式會如實記一筆 warn 記錄，不謊稱已生效）。mac 上遇到白畫面請提 issue 並附記錄：
`~/Library/Application Support/com.polaris.app/polaris/logs/`（Linux 為 `~/.config/...`、Windows 為
`%APPDATA%\...` 下的同名 `logs/` 目錄）。

> 兩處開關是同一個鍵：`hardwareAcceleration`（正向語義，預設 `true`=開）。改動均需**整個應用程式重新啟動**才生效
> —— 環境變數只在 webview 建立那一刻被讀取。
