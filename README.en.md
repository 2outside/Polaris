# Polaris

<div align="center">

[简体中文](README.md) · **English** · [繁體中文](README.zh-TW.md) · [Русский](README.ru.md) · [فارسی](README.fa.md)

[![release](https://img.shields.io/github/v/release/2outside/Polaris?style=flat-square&color=0E98A4&label=release)](https://github.com/2outside/Polaris/releases/latest)
[![sing-box](https://img.shields.io/badge/sing--box-1.14-0E98A4?style=flat-square)](https://github.com/SagerNet/sing-box)
[![platform](https://img.shields.io/badge/platform-Windows%20%C2%B7%20macOS%20%C2%B7%20Linux-0E98A4?style=flat-square)](#install)
[![license](https://img.shields.io/badge/license-MIT-0E98A4?style=flat-square)](LICENSE)
[![stars](https://img.shields.io/github/stars/2outside/Polaris?style=flat-square&color=0E98A4)](https://github.com/2outside/Polaris/stargazers)

</div>

**Polaris** — a cross-platform network proxy client built on sing-box. Tauri 2 (Rust + React).

![Home](docs/screenshots/home.png)

## Features

| Area | Capabilities |
|---|---|
| Traffic capture | TUN · System proxy · Local port |
| Routing | Smart / Global / Direct · Custom rules · Per-app routing · Region routing (incl. back-to-China) |
| Protocols | VLESS · VMess · Trojan · Hysteria 2 / 1 · TUIC · Shadowsocks · AnyTLS · Naive · Snell · SOCKS · HTTP · SSH · Tor · OpenConnect · OpenVPN |
| Mesh | WireGuard · Tailscale · WARP; OpenConnect / OpenVPN also count once they declare internal subnets |
| DNS | FakeIP · DoH / DoT · Resolver racing · IPv6 strategy · Leak protection |
| Diagnostics | Connection topology · Live logs · Node speed tests · Streaming and AI unlock detection |
| Operations | Subscription management · Online core updates · Config backup and restore · Privacy lock · Tray residency |
| App updates | Stable / Testing channels · Re-download the current version · Installer digest verification |
| Memory optimization | Releases the main WebView after the UI stays hidden or minimized for 10 minutes; stats, connections, and logs subscribe on demand |

<table>
<tr>
<td width="50%"><img src="docs/screenshots/nodes.png" alt="Nodes"><br><sub>Node management and speed tests</sub></td>
<td width="50%"><img src="docs/screenshots/rules.png" alt="Rules"><br><sub>Custom routing rules</sub></td>
</tr>
<tr>
<td><img src="docs/screenshots/connections.png" alt="Connections"><br><sub>Live connections</sub></td>
<td><img src="docs/screenshots/settings.png" alt="Settings"><br><sub>Settings</sub></td>
</tr>
</table>

## Install

Download the package for your platform from [Releases](https://github.com/2outside/Polaris/releases).

| Platform | File |
|---|---|
| macOS | `*-mac-arm64.dmg` / `*-mac-x64.dmg` |
| Windows | `*-win-setup.exe`; portable build: `polaris-portable-*.zip` |
| Linux | `*.deb` / `*.AppImage` |

Packages are not signed with a paid code-signing certificate, so the first launch needs a manual approval step on each platform.

The Windows installer does not bundle the WebView2 Runtime; it is fetched online when the system lacks it. On stripped-down / LTSC images or portable setups without the Runtime, install [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/) from Microsoft first. Polaris does not ship an offline WebView2 installer.

### First install on macOS

1. Open the DMG and drag `Polaris.app` into **Applications**. Do not run it directly from the DMG.
2. Open **Terminal** and run:

   ```bash
   xattr -cr /Applications/Polaris.app
   ```

3. Launch Polaris from **Applications**. Run the command once after each manual install or replacement from a newly downloaded DMG; in-app updates clear the quarantine attribute themselves.

If Polaris is installed elsewhere, replace the path with the actual `.app` path. `xattr -cr` recursively clears extended attributes on that app bundle, so run it only against a Polaris package downloaded from this repository's Releases and verified as trusted. The DMG root also carries the same five-language guide as `README First.txt`. If the prompt only says the developer cannot be verified, you can instead right-click Polaris in Finder → **Open** → confirm again.

### First install on Windows

When SmartScreen appears, choose **More info** → **Run anyway**.

## Build

Requires Rust stable, Node.js 24+ (CI currently uses Node 26), and [Tauri CLI 2](https://v2.tauri.app/).

```bash
node scripts/fetch-core.mjs        # fetch the sing-box core (SHA256 pinned)
node scripts/fetch-cronet.mjs --platform=linux  # fetch libcronet.so beside the Linux core
cargo tauri build --config src-tauri/tauri.linux.conf.json
```

The core is not committed and must be fetched before packaging. The per-platform `--config` is not optional: omitting it produces **a package with no core**, with zero build-time errors — the failure only surfaces at runtime. Full details, CI division of labor, and the Windows installer / updater package-selection contract are in [Build and Package](docs/build-and-package.en.md).

Development gates:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd ui && npm test
```

## Architecture

```
ui/          React + Zustand + Vite + Tailwind
src-tauri/   Tauri 2 main process
crates/      17 domain crates (config-engine / core-supervisor / helper / updater / …)
resources/   sing-box core + libcronet (fetched at build time, not committed)
```

The core runs as a sidecar child process and is managed over a gRPC control plane. TUN and system proxy are handled by privileged helpers on all three platforms (macOS / Windows / Linux, all in Rust).

## Documentation

| File | Contents |
|---|---|
| [docs/build-and-package.en.md](docs/build-and-package.en.md) | Build, CI, packaging invariants, updater package-selection contract |
| [docs/troubleshooting.en.md](docs/troubleshooting.en.md) | Unsigned-build notes, white screen / corrupted rendering / GPU crash triage |

Screenshots are produced by `node scripts/capture-screenshots.mjs`: headless Chrome renders the built frontend with injected stub data — no app install and no running core required.

## Upstream

| Project | Role |
|---|---|
| [sing-box](https://github.com/SagerNet/sing-box) | Proxy core (sidecar child process) |
| [Tauri 2](https://github.com/tauri-apps/tauri) | Desktop runtime |
| [cronet-go](https://github.com/SagerNet/cronet-go) | libcronet for NaiveProxy |
| [sing-box-dashboard](https://github.com/SagerNet/sing-box-dashboard) | Built-in dashboard |
| [meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) | Rule sets and geo data (`.srs`) |

Each component remains under its author's copyright. Components integrated as subprocesses or binaries are listed in `NOTICE`; source-level dependencies linked into the artifacts (Tauri / React / several hundred Rust crates) are itemized in `THIRD-PARTY-LICENSES.md`.

## Scope and Disclaimer

Polaris is a general-purpose network proxy client and diagnostic tool. It does not provide, sell, or operate proxy nodes, subscriptions, or network services. Use it only where you comply with the laws and regulations of your jurisdiction, applicable terms of service, and the policies of the network you are on, and where you hold the necessary authorization. It must not be used for unauthorized access, for infringing on others' rights, or for any other unlawful abuse. Users are responsible for assessing the trustworthiness of their configurations, nodes, and third-party resources, and for their own conduct and its consequences.

This software is provided "as is", with no promise of network availability, anonymity, security, access to any particular service, or data integrity. TUN, system proxy, DNS, and routing changes may temporarily disrupt network connectivity; back up your configuration before any important operation. Except where mandated by applicable law, the maintainers and contributors are not liable for any direct or indirect loss arising from the use of, or inability to use, this software. This notice is not legal or other professional advice.

## License

MIT (see `LICENSE`). sing-box (GPLv3) is integrated as a sidecar child process (mere aggregation) and does not affect this project's license; third-party components are listed in `NOTICE`.

## Star History

<a href="https://www.star-history.com/?repos=2outside%2FPolaris&type=date&legend=top-left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=2outside/Polaris&type=date&theme=dark&legend=top-left&sealed_token=TJg9RA5l3wyd1IgSMMq05QxhNvxS_OcrWbDJxZuwdUwgs-zVIBeoZz2j6swI3y5BxlztkoJMSkkxL6ZbZtw6oyqaRHZSAv0ZS60aVPPuBMdvm8tkxUjyKN1ttiVtPUwJEKObGpBH7BsPhjr6JwFfl_20UYjxgRVOq_V_Q6gKleib6K8LqP3K3nSwPvIJ" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=2outside/Polaris&type=date&legend=top-left&sealed_token=TJg9RA5l3wyd1IgSMMq05QxhNvxS_OcrWbDJxZuwdUwgs-zVIBeoZz2j6swI3y5BxlztkoJMSkkxL6ZbZtw6oyqaRHZSAv0ZS60aVPPuBMdvm8tkxUjyKN1ttiVtPUwJEKObGpBH7BsPhjr6JwFfl_20UYjxgRVOq_V_Q6gKleib6K8LqP3K3nSwPvIJ" />
    <img alt="Polaris Star History Chart" src="https://api.star-history.com/chart?repos=2outside/Polaris&type=date&legend=top-left&sealed_token=TJg9RA5l3wyd1IgSMMq05QxhNvxS_OcrWbDJxZuwdUwgs-zVIBeoZz2j6swI3y5BxlztkoJMSkkxL6ZbZtw6oyqaRHZSAv0ZS60aVPPuBMdvm8tkxUjyKN1ttiVtPUwJEKObGpBH7BsPhjr6JwFfl_20UYjxgRVOq_V_Q6gKleib6K8LqP3K3nSwPvIJ" />
  </picture>
</a>
