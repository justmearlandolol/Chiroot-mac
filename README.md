# Chiroot Desktop (macOS)

A lightweight, native-feeling macOS desktop wrapper for **Chiroot Audio Player** (`https://www.chiroot.my.id/Main.html`), built with **Rust** and **Tauri v2**, engineered for minimal RAM/CPU usage and compatibility with **Intel Macs running macOS High Sierra 10.13.6+**.

---

## Features

- **Single-WebView Website Integration**: Loads `https://www.chiroot.my.id/Main.html` directly inside macOS `WKWebView` with zero duplicate WebViews, a lightweight local startup/error fallback (`frontend/index.html`), and automatic external-browser routing for third-party links and downloads.
- **High Sierra 10.13.6 (x86_64) Targeted**:
  - Pinned `minimumSystemVersion: "10.13"` (`LSMinimumSystemVersion` + `MACOSX_DEPLOYMENT_TARGET=10.13`).
  - Uses `ureq` with `rustls` + bundled Mozilla root certificates (`webpki-roots`) for Rust-side HTTPS requests, avoiding High Sierra's outdated system trust store.
  - Release profile optimized for minimal binary size and memory footprint (`opt-level = "s"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`, `strip = true`).
  - Strictly event-driven bridge script (no `setInterval` polling).
- **Native macOS File Importing**:
  - Supports `.json`, `.mp3`, `.png`, `.jpeg`, and `.jpg` via native macOS `NSOpenPanel` (`File → Import Files…` or `⌘O`) with multi-select.
  - Validates extensions, MIME types, and file magic-byte headers before handing off.
  - Streams large files in 512 KB chunks from Rust so files are never unnecessarily duplicated in memory.
- **Audio & Headset Device Discovery**:
  - Declares `NSMicrophoneUsageDescription`, `NSAudioCaptureUsageDescription`, and `NSBluetoothAlwaysUsageDescription` in `Info.plist`.
  - Event-driven `navigator.mediaDevices` (`devicechange`, `enumerateDevices()`, `getUserMedia()`) helper with clear macOS permission hints, plus on-demand macOS audio hardware listing via `system_profiler SPAudioDataType -json`.
- **Supabase Google OAuth (PKCE S256)**:
  - Uses only the public publishable key (never a service-role key).
  - Supports both **System Browser + ephemeral loopback callback** (`http://127.0.0.1:<port>/auth/callback`) and **Custom URL Scheme Deep Link** (`chiroot://auth/callback`).
  - Persists sessions securely in `~/Library/Application Support/id.my.chiroot.desktop/session.json` (`0600` permissions), refreshes tokens automatically, and syncs with Chiroot's `localStorage['chiroot_auth_v1']`.
- **Autoplay Support**:
  - Relies on Tauri/WRY's `WKWebViewConfiguration.mediaTypesRequiringUserActionForPlayback = None` (supported on macOS 10.12+) combined with an event-driven `AudioContext` unlock handler and graceful fallback notification if macOS blocks playback.
- **Custom macOS Branding**:
  - Custom multi-resolution `icons/icon.icns`, `icons/icon.ico`, and PNG icons bundled into `Chiroot Desktop.app` for Dock and Finder display.

---

## Repository Structure

All Rust application logic is centralized in `src/main.rs`:

```text
.
├── .github/
│   └── workflows/
│       └── build.yml          # Automated macOS x86_64 CI build, verification & release
├── capabilities/
│   └── default.json           # Minimal Tauri v2 IPC permissions (local + chiroot.my.id)
├── frontend/
│   └── index.html             # Lightweight loading & offline retry screen
├── icons/
│   ├── 32x32.png
│   ├── 128x128.png
│   ├── 128x128@2x.png
│   ├── icon.icns              # macOS bundle icon
│   ├── icon.ico
│   └── icon.png
├── src/
│   └── main.rs                # Centralized Rust application logic & unit tests
├── build.rs
├── Cargo.toml
├── Info.plist                 # macOS High Sierra metadata, permissions & URL schemes
├── package.json
├── tauri.conf.json
└── README.md
```

---

## Supabase OAuth Redirect Configuration

To allow Google sign-in to return directly from Safari/Chrome back into **Chiroot Desktop**, make sure your Supabase project (**Authentication → URL Configuration → Redirect URLs**) includes:

- `http://127.0.0.1:47821/auth/callback`
- `http://127.0.0.1:*/auth/callback`
- `chiroot://auth/callback`
- `https://www.chiroot.my.id/Main.html`

> **Security Note**: Never put a Supabase `service_role` key in client code or environment files bundled with the app. You may optionally override the public project URL or publishable key at runtime using `CHIROOT_SUPABASE_URL` and `CHIROOT_SUPABASE_KEY`.

---

## Building Locally on macOS

### Prerequisites

- macOS (Intel or Apple Silicon) with Xcode Command Line Tools (`xcode-select --install`)
- [Rust stable](https://rustup.rs/) with the Intel target installed:
  ```bash
  rustup target add x86_64-apple-darwin
  ```
- Node.js 20+ (for `@tauri-apps/cli`)

### Install & Run

```bash
npm install
npm run dev
```

### Build Release Bundle (Intel x86_64, High Sierra 10.13+)

```bash
npm run build:macos-intel
```

Outputs are generated under `target/x86_64-apple-darwin/release/bundle/`:
- `macos/Chiroot Desktop.app`
- `dmg/Chiroot Desktop_1.0.0_x64.dmg`

Verify the binary targets Intel x86_64 and macOS 10.13:

```bash
lipo -info "target/x86_64-apple-darwin/release/bundle/macos/Chiroot Desktop.app/Contents/MacOS/chiroot-desktop"
otool -l "target/x86_64-apple-darwin/release/bundle/macos/Chiroot Desktop.app/Contents/MacOS/chiroot-desktop" | grep -A 4 -E 'LC_BUILD_VERSION|LC_VERSION_MIN_MACOSX'
```

---

## Automated GitHub Actions Releases

`.github/workflows/build.yml` runs on `macos-15-intel` with `MACOSX_DEPLOYMENT_TARGET=10.13` whenever you:

- Push to `main` (or open a PR to `main`),
- Publish a GitHub Release (automatically attaches `.dmg`, `.pkg`, and `.app.tar.gz`), or
- Trigger the workflow manually via **Actions → Build Chiroot Desktop (macOS) → Run workflow**.

The workflow runs `cargo test`, compiles the release binary, asserts `x86_64` architecture, `minos 10.13`, `LSMinimumSystemVersion = 10.13`, and bundle icon presence, and builds both `.dmg` and `.pkg` installers.

---

## macOS High Sierra 10.13.6 Notes & Limitations

- **First Launch (Unsigned Builds)**: Because open-source CI builds are not Apple Developer ID notarized, right-click `Chiroot Desktop.app` → **Open** on first launch (or allow it in **System Preferences → Security & Privacy**).
- **Audio Output Switching (`setSinkId`)**: WebKit / `WKWebView` on macOS (especially High Sierra) does not implement `HTMLMediaElement.setSinkId()`. Audio playback automatically follows your active macOS default output device (including Bluetooth headsets selected in macOS **System Preferences → Sound**).
- **End-to-End Hardware Verification**: Real-hardware validation on a physical macOS High Sierra 10.13.6 Intel Mac (launch, Google OAuth round-trip, MP3/cover/JSON import, Bluetooth headset detection, and RAM/CPU profiling via Activity Monitor) should be performed using the `.dmg`/`.pkg` artifact produced by GitHub Actions.
