# Build and Package

<div align="center">

[简体中文](build-and-package.md) · **English**

</div>

Split out of the README (2026-08-13): this is engineering internals and invariants, written for maintainers, not end users. The README keeps only "how to install, how to use".

## Build

Implementation lands in batches per system design §H (B0 scaffolding → B10 release engineering).

### Toolchain requirements

| Tool | Version | Purpose |
|---|---|---|
| Rust | stable (edition 2021) | Backend + 18 domain crates under `crates/` (plus `source-probe`, which is dev-only: it appears solely in `[dev-dependencies]` and never in a lib/bin dependency graph) |
| Node.js | 24+ (CI pins 26) | Frontend build + fetch scripts |
| pnpm | 11.24.0 (pinned by `ui/package.json`) | Frontend package management (`ui/`) |
| [Tauri CLI 2](https://v2.tauri.app/) | 2.x | `cargo tauri build` packaging (installed as a `ui/` devDependency) |

### System dependencies

**Linux** (Tauri 2 WebKitGTK 4.1 stack, Debian/Ubuntu):

```bash
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
  librsvg2-dev libglib2.0-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev \
  libdbus-1-dev pkg-config
```

**macOS**: 13.0+ (Ventura, required by the three-tier BTM "allow in background" probe), plus Xcode Command Line Tools.
**Windows**: MSVC build tools (Visual Studio Build Tools 2022 + Windows 10/11 SDK).

### Rust workspace (development gates)

```bash
cargo build --workspace        # compile
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace         # unit tests
cargo fmt --all -- --check     # formatting
```

### Frontend toolchain and AST tests

The frontend currently uses React 19, TypeScript 7, Vite 8, Vitest 4, and Tailwind CSS 4.
Install, build, and test with the pnpm 11.24.0 version pinned by `ui/package.json`:

```bash
cd ui
npx pnpm@11.24.0 install --frozen-lockfile
npx pnpm@11.24.0 run build
npx pnpm@11.24.0 test
```

TypeScript 7 no longer uses the legacy
`createSourceFile(..., ScriptTarget, ..., ScriptKind)` test entry point. Structural source tests go
through `ui/src/test/ts-compiler.ts`, backed by the native `typescript/unstable/sync`,
`typescript/unstable/fs`, and `typescript/unstable/ast` APIs. Call sites use only
`parseSourceFile(fileName, text)`; new AST gates must not reintroduce the old compiler call shape or
create a second compatibility layer.

### Fetching assets (sing-box core / cronet / dashboard)

The three resource types have distinct provenance and integrity contracts; they must not be described collectively as “official releases plus manifest SHA”.

- `fetch-core` downloads sing-box GitHub Release archives and verifies `coreArchiveSha256`.
- `fetch-cronet` downloads platform modules from the Go module proxy, then verifies the extracted dynamic library with `cronetLibrarySha256`.
- `fetch-dashboard` fetches the sing-box `gh-pages` dashboard artifact and **currently has no SHA256 pin**.

All are fetched on demand and never committed. **They must be run before packaging** because the Tauri bundle `resources` field references them. A missing core or Cronet pin is a hard failure: native executable resources are never fetched without verification.

```bash
node scripts/fetch-core.mjs       # sing-box cores for four platforms (version = bundledCoreVersion in core-manifest.json; do not re-pin it here)
node scripts/fetch-cronet.mjs     # libcronet (linux/windows only; on macOS it is statically linked into the core)
node scripts/fetch-dashboard.mjs  # sing-box dashboard (gh-pages artifact)
```

Use `node scripts/fetch-cronet.mjs --platform=linux` or `--platform=win` to fetch only the current packaging leg. Versions are always resolved from the `go.mod` of the sing-box tag named by `bundledCoreVersion`; Linux and Windows may use their respective upstream `require` versions. `--check-only` downloads no library, but verifies that the tag is readable, both exact requires exist, and both SHA-256 pins are complete and well-formed.

All three commands above must be run manually: `tauri.conf.json` has **no** `build.beforeBundleCommand`, so `cargo tauri build` does not fetch anything for you. (This section previously described a `beforeBundleCommand` safety net; that key never existed, which made `scripts/verify-dashboard-resources.mjs` an orphan that never ran. The script has been deleted.)

The safety net is now `node scripts/verify-packaging.mjs confs`, which CI runs after the fetch steps and before the Rust build (`.github/workflows/package.yml`). It asserts that every resource path referenced by a conf exists **and has content**: empty directories and zero-byte files both fail the check (existence is not content; a failed fetch or extraction typically leaves exactly those two shapes). It is pure static analysis with no build dependency, so any developer machine can reproduce it.

When upgrading the core, first update `bundledCoreVersion` and its `coreArchiveSha256`, then run `node scripts/fetch-cronet.mjs --check-only`. If upstream `go.mod` changes a Cronet dependency, update only the affected platform's `cronetLibrarySha256`, then re-fetch and verify that platform with `--force --platform=<linux or win>`; never write a second Cronet version into the manifest.

### Producing installers

```bash
# 1) Fetch assets (see above)
# 2) Frontend build + Rust compile + installer (Tauri CLI orchestrates beforeBuildCommand)
#    Run from the **repository root** and pass this platform's config explicitly (see "Per-platform core filtering")
cargo tauri build --config src-tauri/tauri.linux.conf.json          # Linux
cargo tauri build --config src-tauri/tauri.windows.conf.json        # Windows
cargo tauri build --config src-tauri/tauri.macos-arm64.conf.json    # macOS Apple Silicon
cargo tauri build --config src-tauri/tauri.macos-x64.conf.json --target x86_64-apple-darwin  # macOS Intel
```

Artifacts land in `target/release/bundle/` at the **repository root** (this repo is a cargo workspace whose root is the repository root, so **not** `src-tauri/target/`). When `--target <triple>` is passed, they go one level deeper: `target/<triple>/release/bundle/`.

| Platform | Artifact | Form |
|---|---|---|
| Linux | `*.deb` / `*.AppImage` | deb package + AppImage (single file, no install) |
| macOS | `*-mac-arm64.dmg` / `*-mac-x64.dmg` | **One per architecture** (no universal build any more, unsigned). ⚠️ These are **release asset names**, not local artifact names — see below |
| Windows | `*-win-setup.exe` | NSIS installer (WebView2 downloadBootstrapper, Runtime not embedded) |
| Windows | `polaris-portable-*.zip` | Portable build (extract and run; ships its own `resources/` plus a `portable.marker` form marker) |

The portable zip is produced by the Windows leg of `package.yml` from `target/release/polaris.exe` plus `resources/`; running the `cargo tauri build` command above locally does not produce it.

⚠️ **The dmg row is the same story with a different cause**: the `-mac-arm64` / `-mac-x64` arch tag is not produced by Tauri. The `Tag macOS dmg with arch` step in `package.yml` renames `<name>.dmg` to `<name>-<tag>.dmg`, and that step only runs in CI. **Running `cargo tauri build` locally gives you a dmg with Tauri's default name, without the tag.** That tag is a hard requirement of the updater's package-selection contract: `github.rs::find_suitable_update_asset` picks the package by looking for `mac-arm64` / `mac-x64` in the asset name and returns `None` when nothing matches (the "any .dmg" fallback has been removed).

A release contains **exactly one** each of deb / AppImage / mac-arm64 dmg / mac-x64 dmg / win setup / portable zip (six platform deliverables in total, plus `SHA256SUMS`), enforced mechanically by `verify-packaging.mjs assets --label release`.
The two Linux forms are likewise "exactly one", not "at least one": the updater's Linux branch takes the first match (`app_image.first()` / `deb.first()` in `github.rs`), so a duplicate makes the choice depend on asset ordering, exactly as with dmg / setup.

#### Per-platform core filtering (`--config` is not optional)

`bundle.resources` in `src-tauri/tauri.conf.json` **contains no platform core directory at all**; the four platform cores are specified by `tauri.{linux,windows,macos-arm64,macos-x64}.conf.json`. The reasoning and the discipline:

- Bundling all four cores would add roughly 210 MB of dead weight to every package (at runtime only one is selected, by `env::consts::OS/ARCH`).
- Merging follows RFC 7396, where **arrays are replaced wholesale rather than merged**, so any shared resource added to the base config must be mirrored into all four files — otherwise all four packages silently lose it.
- **Do not rely on Tauri's implicit per-platform-name merging**: implicit merging only recognizes fixed file names, so renaming a file silently stops the merge. The package then ships without a core, the bundler still succeeds, and the failure only surfaces on the user's machine as `resolve_core_binary → Err`. With an explicit `--config`, the same rename produces a hard `failed to read configuration file`.
  (The macOS file was originally named `tauri.macos.conf.json`, which would be merged implicitly even though it is arm64-specific — meaning a bare `cargo tauri build` on an Intel Mac would bundle the arm64 core. It has been renamed to `tauri.macos-arm64.conf.json` to remove that implicit default.)

These invariants are enforced mechanically by `node scripts/verify-packaging.mjs confs` (run in CI before every packaging job, reproducible locally). After the build, the `payload` and `assets` modes assert that the artifact contains exactly one core for its own platform and that the artifact name satisfies the updater's package-selection contract.

All of the above ask whether what **should** be there is there. The opposite direction is guarded by a fourth mode, `inventory` — a **package content allow-list**: it enumerates every file in the resource payload tree and reconciles it against an explicitly registered allow-list; **one extra file turns it red**, and every entry must state why it belongs in the package (see `payloadAllowRules()` in `verify-packaging.mjs`).

```bash
node scripts/verify-packaging.mjs inventory --label linux --static                       # no artifact needed: derived from conf x working tree
node scripts/verify-packaging.mjs inventory --label linux --root target/release/bundle   # artifact scope
```

It was added (2026-08-29) after a batch of stowaways that had **already shipped**: `resources/data/README*.md` (developer docs, now moved to `docs/geo-rulesets*.md`), zero-byte `.gitkeep` placeholders, and the dashboard's gh-pages/PWA leftovers (`.nojekyll`, `sw.js`, `registerSW.js`, `workbox-*.js`, `manifest.webmanifest`, now stripped right after extraction in `scripts/fetch-dashboard.mjs`) — none of which turned anything red at the time. The **invariant E** added to `confs` in the same batch closes the config-side entrance of the same class: adding `"../ui/src/"` to all four per-platform confs used to leave `confs` at rc=0, shipping the entire `ui/src` tree inside all four installers.

`inventory` states its reach honestly: it counts what the bundler lays down from `bundle.resources`, not the ELF binaries and host shared libraries that the bundler / linuxdeploy place themselves (those are not controlled by `bundle.resources`); the number of out-of-reach files is printed. On Windows, where NSIS leaves no bundle-side copy, it degrades to a cargo staging count and says so in its output ("staging check, not artifact verification").

## Continuous integration

Two workflows divide the work (`.github/workflows/`):

- **`ci.yml`** — fast gate: `cargo fmt + clippy + build + test` on all three platforms, triggered on every PR and every push to main. Its job is "is the change correct". Setting the three `cargo-test` jobs as required checks is recommended.
- **`package.yml`** — release engineering: a three-platform matrix running fetch + `tauri build` + artifact upload. Triggered by tags (`v*`), manually, or by changes to packaging-related paths on main. Its job is "can we produce a distributable installer".

## Windows installer and WebView2

Tauri 2 depends on the WebView2 Runtime. Windows ships a single **`*-win-setup.exe`** using `downloadBootstrapper` from `tauri.conf.json`: ordinary Windows 10/11 usually has it preinstalled, and when it is missing the installer fetches Microsoft's Runtime online. Polaris neither embeds nor mirrors the WebView2 Runtime, and does not maintain a second Windows installer.

Users on stripped-down / LTSC images or portable setups that lack the Runtime need to install [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/) from Microsoft first. A fully offline device could not download Polaris or fetch a subscription either, so the release pipeline no longer maintains a second installer and its verification workflow for that case.

The naming is not arbitrary. On Windows the updater (`crates/updater/src/github.rs`) splits package selection into **two disjoint rules by runtime form**:

| Runtime form | Selection criteria | Match |
|---|---|---|
| Installed (via NSIS) | `.exe` whose name contains `win` | `*-win-setup.exe` |
| Portable (run from an extracted zip) | `polaris-portable-` prefix + `.zip` | `polaris-portable-*.zip` |

Hence the installer carries `win` explicitly and the portable build is a zip, placing them in disjoint namespaces so each rule is unambiguous. The "exactly one" guarantees are enforced mechanically in CI by `verify-packaging.mjs assets`.

**How the portable form is detected**: the portable zip contains a `portable.marker` file next to `polaris.exe`, which the app reads when checking for updates (`commands/updater::is_portable_layout`). It deliberately does not use environment variables such as `PORTABLE_EXECUTABLE_DIR` — those are injected specifically by electron-builder's portable target (a self-extracting stub), whereas this repo's portable build is a plain zip made with `Compress-Archive` and has no stub, so that variable never exists. After building the zip, `package.yml` opens it back up and verifies the marker really is inside; if it is missing, the whole leg fails hard.

⚠️ **Portable updates are "download and hand off to the OS", not fully automatic**: portable users receive a zip, and `update_install` does not recognize the zip form (it only handles `.exe/.dmg/.AppImage/.deb`), so it falls back to opening the zip with the system handler and the user extracts and overwrites it themselves. This is an intentional honest degradation: the form stays correct, and NSIS will never quietly install a second copy behind the user's back. Automatic extract-and-replace would require pulling in an extraction dependency and has not been done.
⚠️ If a user deletes `portable.marker`, the app goes back to treating itself as an installed build and starts offering the installer instead. **No automated mechanism can guard against this**, so the file itself states that it must not be deleted.
