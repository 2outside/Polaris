# Troubleshooting

<div align="center">

[简体中文](troubleshooting.md) · **English** · [繁體中文](troubleshooting.zh-TW.md) · [Русский](troubleshooting.ru.md) · [فارسی](troubleshooting.fa.md)

</div>

## About unsigned builds (macOS / Windows)

Polaris is **not code-signed**:

- **macOS**: drag the app into **Applications** first; after each manual install or replacement from a newly downloaded DMG, run
  `xattr -cr /Applications/Polaris.app`. If the prompt only says the developer cannot be verified, you can instead right-click the app → **Open** → confirm.
  That command recursively clears the app bundle's extended attributes, so run it only against a Polaris release you trust; the updater performs the xattr cleanup itself.
  The DMG ships the same five-language first-launch guide (`README First.txt`) — when Gatekeeper blocks a user, they cannot get into the app and may never have seen this file, so that guide is the only instruction available to them at that moment.
- **Windows**: SmartScreen "Windows protected your PC" → **More info** → **Run anyway**. UAC elevation (helper install / TUN) still happens as usual; it is just one extra confirmation.

Signing would add certificate costs plus a signature-manifest trust model that conflicts with the existing custom update pipeline (VBS / osascript / pkexec orchestration), so it is explicitly not done (see the `updater` crate notes).

## White screen / corrupted rendering / repeated GPU process crashes

Most common on NVIDIA proprietary drivers, virtual machines (QEMU virtual GPU), and remote desktops (xrdp) — environments without working hardware acceleration. The webview's compositor cannot produce frames, but **the proxy core itself is unaffected** and keeps running and forwarding.

**The UI is still usable** (occasional white screen or corrupted rendering; reopening the window gets you back in) → Settings → Display → **Graphics compatibility** → turn off **Hardware acceleration** → restart Polaris. (This block is hidden on macOS: WKWebView has no supported switch to disable the GPU.)

**The UI never opens at all** (blank from start, Settings unreachable) → neither path below needs the UI:

### 1. Edit config.json directly

Quit Polaris, add `"hardwareAcceleration": false` at the top level of the config file, then start it again:

| Platform | Path |
|---|---|
| Linux | `~/.config/com.polaris.app/polaris/config.json` |
| Windows | `%APPDATA%\com.polaris.app\polaris\config.json` |
| macOS | `~/Library/Application Support/com.polaris.app/polaris/config.json` |

```json
{
  "hardwareAcceleration": false
}
```

Config reading is deliberately fault-tolerant first: a corrupted file or a wrong field type always falls back to "enabled by default", so a bad value for this key cannot break startup (see `src-tauri/src/graphics_compat.rs` — the raw text is read directly before the window is created, without depending on the store assembling successfully).

### 2. Platform environment variables (one-off test, no config change)

These variables are read **natively** by WebKitGTK / WebView2 and need no cooperation from the app. Polaris also deliberately does not override variables you have already set, so a temporary experiment during triage will not be disturbed by the app.

```bash
# Linux (WebKitGTK) — DMABUF is the main fix for NVIDIA white screens; COMPOSITING covers resize crashes
WEBKIT_DISABLE_DMABUF_RENDERER=1 WEBKIT_DISABLE_COMPOSITING_MODE=1 polaris
```

```powershell
# Windows (WebView2)
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="--disable-gpu"; .\Polaris.exe
```

macOS has no equivalent switch (WKWebView exposes no public API; WebKit #26651 has gone unimplemented for a long time), so `hardwareAcceleration` is a no-op on macOS — the app logs an honest warning instead of claiming it took effect. If you hit a white screen on macOS, please open an issue and attach the logs from
`~/Library/Application Support/com.polaris.app/polaris/logs/` (on Linux `~/.config/...`, on Windows `%APPDATA%\...`, same `logs/` directory name).

> Both switches are the same key: `hardwareAcceleration` (positive semantics, defaults to `true` = enabled). Any change requires **a full application restart** — environment variables are read only at the moment the webview is created.
