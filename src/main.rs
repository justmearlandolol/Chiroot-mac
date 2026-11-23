#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Chiroot Desktop — Lightweight macOS desktop application for Chiroot Audio Player.
//!
//! All Rust application logic is centralized in this single file (`src/main.rs`):
//! - Native single-WebView integration for `https://www.chiroot.my.id/Main.html`
//! - macOS High Sierra 10.13.6+ (x86_64) compatibility & minimal memory footprint
//! - WKWebView autoplay configuration + zero-polling playback unlock bridge
//! - Native macOS file picker & chunked streaming import for `.json`, `.mp3`, `.png`, `.jpeg`, `.jpg`
//! - Audio / Bluetooth headset device discovery helpers and macOS permission diagnostics
//! - Supabase Google OAuth (PKCE S256) via system browser + loopback / `chiroot://` deep-link callback
//! - Persistent secure session storage (`0600`) synchronized with `Main.html`

use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder, WINDOW_SUBMENU_ID};
use tauri::webview::PageLoadEvent;
use tauri::{AppHandle, Emitter, Manager, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder};
use tauri_plugin_deep_link::DeepLinkExt;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;

// =============================================================================
// Constants & Configuration
// =============================================================================

const APP_NAME: &str = "Chiroot Desktop";
const CHIROOT_URL: &str = "https://www.chiroot.my.id/Main.html";
const HOME_HOST: &str = "chiroot.my.id";
const OAUTH_DEEP_LINK_REDIRECT: &str = "chiroot://auth/callback";

/// Public Supabase project URL & publishable (anon) key used by Chiroot Web.
/// Never place a Supabase `service_role` key in client code.
const DEFAULT_SUPABASE_URL: &str = "https://astuagdezahmuuwjoghf.supabase.co";
const DEFAULT_SUPABASE_PUBLISHABLE_KEY: &str =
    "sb_publishable_NXhR-MquEMwYDrCBPAOgAQ_MZ4BXQlT";

/// Standard macOS Safari UA string targeting High Sierra 10.13.6 WebKit compatibility.
const MACOS_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) \
    AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.15";

/// Hard limits for safe, low-RAM file importing.
const MAX_IMPORT_FILE_BYTES: u64 = 100 * 1024 * 1024; // 100 MB
const MAX_STREAM_CHUNK_BYTES: usize = 1024 * 1024; // 1 MB max per chunk read
const MAX_REGISTERED_FILES: usize = 64;

/// OAuth callback server timeout (5 minutes); listener is created lazily on demand
/// and closed immediately when login completes or times out (zero idle overhead).
const OAUTH_TIMEOUT_SECS: u64 = 300;

const DOWNLOAD_EXTENSIONS: &[&str] = &[
    ".dmg", ".pkg", ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".exe", ".msi", ".deb", ".rpm",
    ".appimage", ".apk", ".sh", ".run",
];

/// Lightweight initialization script injected ONLY on `chiroot.my.id`.
/// - Zero `setInterval` polling (strictly event-driven to keep idle CPU ~0%).
/// - Enables smooth audio autoplay & AudioContext resume while keeping user controls intact.
/// - Exposes `window.ChirootDesktop` native helpers (file import, Supabase OAuth, audio devices).
/// - Listens for `devicechange` on `navigator.mediaDevices` and surfaces clear macOS permission hints.
/// - Intercepts `window.open` for external links so they open in the default macOS browser.
const BRIDGE_INIT_JS: &str = r#"(function () {
  var host = (window.location && window.location.hostname || '').toLowerCase();
  if (host !== 'chiroot.my.id' && host.slice(-14) !== '.chiroot.my.id') {
    return;
  }
  if (window.__CHIROOT_DESKTOP_BRIDGE__) return;
  window.__CHIROOT_DESKTOP_BRIDGE__ = true;

  function invoke(cmd, args) {
    if (window.__TAURI__ && window.__TAURI__.core && typeof window.__TAURI__.core.invoke === 'function') {
      return window.__TAURI__.core.invoke(cmd, args || {});
    }
    return Promise.reject(new Error('Chiroot Desktop native bridge unavailable'));
  }

  function showBanner(msg, isError) {
    try {
      var id = '__chiroot_desktop_toast';
      var el = document.getElementById(id);
      if (!el) {
        el = document.createElement('div');
        el.id = id;
        el.setAttribute('role', 'status');
        el.style.cssText = 'position:fixed;bottom:16px;right:16px;z-index:2147483647;' +
          'max-width:360px;padding:10px 14px;border-radius:10px;font-size:12px;line-height:1.4;' +
          'font-family:-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;' +
          'box-shadow:0 4px 16px rgba(0,0,0,0.22);transition:opacity 0.15s ease;';
        document.body && document.body.appendChild(el);
      }
      el.style.background = isError ? '#3b1c1c' : '#1b1d17';
      el.style.color = '#f7f5ee';
      el.style.border = isError ? '1px solid #d96b6b' : '1px solid #d4ec8a';
      el.style.opacity = '1';
      el.textContent = String(msg || '');
      clearTimeout(el.__hideTimer);
      el.__hideTimer = setTimeout(function () {
        el.style.opacity = '0';
      }, 4500);
    } catch (e) {}
  }

  // ---------------------------------------------------------------------------
  // 1. Autoplay & Audio Playback Support (zero polling)
  // ---------------------------------------------------------------------------
  function resumeAudioContexts() {
    try {
      var ctx = window.__ChirootAudioContext;
      if (ctx && ctx.state === 'suspended' && typeof ctx.resume === 'function') {
        ctx.resume().catch(function () {});
      }
    } catch (e) {}
  }

  function patchMediaPlay() {
    try {
      if (window.__chirootDesktopPlayPatched || !window.HTMLMediaElement) return;
      window.__chirootDesktopPlayPatched = true;
      var origPlay = window.HTMLMediaElement.prototype.play;
      window.HTMLMediaElement.prototype.play = function () {
        var el = this;
        var args = arguments;
        resumeAudioContexts();
        var result;
        try {
          result = origPlay.apply(el, args);
        } catch (err) {
          return Promise.reject(err);
        }
        if (result && typeof result.catch === 'function') {
          return result.catch(function (err) {
            if (err && err.name === 'NotAllowedError') {
              showBanner('Click Play once to allow audio playback in macOS WebView.', false);
            }
            throw err;
          });
        }
        return result;
      };
    } catch (e) {}
  }
  patchMediaPlay();

  function onFirstGesture() {
    resumeAudioContexts();
    document.removeEventListener('pointerdown', onFirstGesture, true);
    document.removeEventListener('keydown', onFirstGesture, true);
  }
  document.addEventListener('pointerdown', onFirstGesture, true);
  document.addEventListener('keydown', onFirstGesture, true);

  // ---------------------------------------------------------------------------
  // 2. External link handling for window.open
  // ---------------------------------------------------------------------------
  var origOpen = window.open;
  window.open = function (url) {
    try {
      if (typeof url === 'string' && /^https?:\/\//i.test(url)) {
        var parsed = new URL(url, window.location.href);
        var h = parsed.hostname.toLowerCase();
        var isInternal = h === 'chiroot.my.id' || h.slice(-14) === '.chiroot.my.id';
        if (!isInternal) {
          invoke('open_external_url', { url: parsed.toString() }).catch(function () {});
          return null;
        }
      }
    } catch (e) {}
    return origOpen ? origOpen.apply(window, arguments) : null;
  };

  // ---------------------------------------------------------------------------
  // 3. Audio & Headset Device Discovery Helpers (event-driven, zero polling)
  // ---------------------------------------------------------------------------
  async function enumerateAudioDevicesWithHints() {
    var result = { webDevices: [], macDevices: [], permissionError: null };
    try {
      result.macDevices = await invoke('list_macos_audio_devices');
    } catch (e) {}

    if (!navigator.mediaDevices || typeof navigator.mediaDevices.enumerateDevices !== 'function') {
      result.permissionError = 'WebKit MediaDevices API is unavailable on this macOS version. Audio follows System Preferences > Sound.';
      return result;
    }

    try {
      var list = await navigator.mediaDevices.enumerateDevices();
      var hasLabels = list.some(function (d) { return d && d.label; });
      if (!hasLabels && typeof navigator.mediaDevices.getUserMedia === 'function') {
        try {
          var stream = await navigator.mediaDevices.getUserMedia({ audio: true });
          stream.getTracks().forEach(function (t) { t.stop(); });
          list = await navigator.mediaDevices.enumerateDevices();
        } catch (permErr) {
          if (permErr && permErr.name === 'NotAllowedError') {
            result.permissionError = 'Microphone permission denied. Enable Chiroot Desktop in System Preferences > Security & Privacy > Microphone to view headset labels.';
          } else if (permErr && permErr.name === 'NotFoundError') {
            result.permissionError = 'No audio input device was found.';
          } else {
            result.permissionError = (permErr && permErr.message) || 'Audio device permission unavailable.';
          }
        }
      }
      result.webDevices = list
        .filter(function (d) { return d.kind === 'audioinput' || d.kind === 'audiooutput'; })
        .map(function (d) {
          return { deviceId: d.deviceId, kind: d.kind, label: d.label || '', groupId: d.groupId || '' };
        });
    } catch (err) {
      result.permissionError = (err && err.message) || 'Failed to enumerate audio devices.';
    }
    return result;
  }

  if (navigator.mediaDevices && typeof navigator.mediaDevices.addEventListener === 'function') {
    navigator.mediaDevices.addEventListener('devicechange', function () {
      window.dispatchEvent(new CustomEvent('chiroot:audio-devices-changed'));
    });
  }

  // ---------------------------------------------------------------------------
  // 4. Chunked Native File Import into Chiroot (zero double-buffering in Rust)
  // ---------------------------------------------------------------------------
  async function readDescriptorToFile(desc) {
    var chunkSize = 512 * 1024; // 512 KB streaming chunks
    var parts = [];
    var offset = 0;
    try {
      while (offset < desc.size) {
        var res = await invoke('read_imported_file_chunk', {
          fileId: desc.id,
          offset: offset,
          length: chunkSize
        });
        var bin = atob(res.base64);
        var bytes = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) {
          bytes[i] = bin.charCodeAt(i);
        }
        parts.push(bytes);
        offset += bytes.length;
        if (res.eof || bytes.length === 0) break;
      }
      return new File(parts, desc.name, { type: desc.mimeType });
    } finally {
      invoke('release_imported_file', { fileId: desc.id }).catch(function () {});
    }
  }

  function assignFileToInput(selector, file) {
    var input = document.querySelector(selector);
    if (!input || typeof DataTransfer === 'undefined') return false;
    try {
      var dt = new DataTransfer();
      dt.items.add(file);
      input.files = dt.files;
      input.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    } catch (e) {
      return false;
    }
  }

  async function handleNativeImportedDescriptors(descriptors) {
    if (!Array.isArray(descriptors) || !descriptors.length) return [];
    var imported = [];
    var openedAddModal = false;

    for (var i = 0; i < descriptors.length; i++) {
      var desc = descriptors[i];
      try {
        var file = await readDescriptorToFile(desc);
        imported.push({ descriptor: desc, file: file });

        if (desc.extension === 'mp3') {
          if (!openedAddModal) {
            var addBtn = document.getElementById('btn-add') || document.querySelector('[data-action="add-music"]');
            if (addBtn) { try { addBtn.click(); } catch (e) {} }
            openedAddModal = true;
          }
          assignFileToInput('#input-audio', file);
          showBanner('Loaded MP3: ' + desc.name, false);
        } else if (desc.extension === 'png' || desc.extension === 'jpg' || desc.extension === 'jpeg') {
          assignFileToInput('#input-cover', file);
          showBanner('Loaded cover image: ' + desc.name, false);
        } else if (desc.extension === 'json') {
          var text = await file.text();
          var parsed = JSON.parse(text);
          window.dispatchEvent(new CustomEvent('chiroot:json-imported', {
            detail: { name: desc.name, size: desc.size, data: parsed }
          }));
          showBanner('Validated JSON imported: ' + desc.name, false);
        }
      } catch (err) {
        showBanner('Import failed (' + desc.name + '): ' + (err && err.message ? err.message : err), true);
      }
    }
    return imported;
  }

  // ---------------------------------------------------------------------------
  // 5. Supabase Auth Sync between Main.html and Rust secure session store
  // ---------------------------------------------------------------------------
  function syncWebSessionToRust() {
    try {
      var raw = localStorage.getItem('chiroot_auth_v1');
      invoke('sync_web_session', { sessionJson: raw || null }).catch(function () {});
    } catch (e) {}
  }

  window.addEventListener('storage', function (ev) {
    if (ev && ev.key === 'chiroot_auth_v1') syncWebSessionToRust();
  });
  window.addEventListener('load', function () {
    setTimeout(syncWebSessionToRust, 1200);
  });

  // Public desktop bridge API available to Chiroot web scripts & DevTools
  window.ChirootDesktop = {
    version: '1.0.0',
    notify: showBanner,
    importFiles: async function (filterMode, multiple) {
      var descriptors = await invoke('pick_import_files', {
        filterMode: filterMode || 'all',
        multiple: multiple !== false
      });
      return handleNativeImportedDescriptors(descriptors);
    },
    _receiveMenuImport: handleNativeImportedDescriptors,
    startGoogleAuth: function (useDeepLink) {
      return invoke('start_google_auth', { useDeepLink: !!useDeepLink });
    },
    getAuthSession: function () {
      return invoke('get_auth_session');
    },
    logoutAuth: function () {
      return invoke('logout_auth');
    },
    enumerateAudioDevices: enumerateAudioDevicesWithHints,
    listMacAudioDevices: function () {
      return invoke('list_macos_audio_devices');
    },
    openExternal: function (url) {
      return invoke('open_external_url', { url: url });
    }
  };
})();"#;

// =============================================================================
// Data Types & Application State
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SupabaseUser {
    id: String,
    #[serde(default)]
    email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SupabaseSession {
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    /// Expiration timestamp in Unix milliseconds (matches Chiroot `Main.html`).
    expires_at: u64,
    user: SupabaseUser,
}

#[derive(Debug, Clone)]
struct PendingOAuth {
    verifier: String,
    expected_state: String,
    created_at: Instant,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportedFileDescriptor {
    id: String,
    name: String,
    extension: String,
    mime_type: String,
    size: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FileChunkResponse {
    base64: String,
    offset: u64,
    bytes_read: usize,
    eof: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReachabilityResult {
    reachable: bool,
    status: Option<u16>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MacAudioDevice {
    name: String,
    manufacturer: String,
    transport: String,
    is_default_output: bool,
    is_default_input: bool,
    has_output: bool,
    has_input: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthStartResponse {
    authorize_url: String,
    redirect_uri: String,
    mode: String,
}

struct AppState {
    pending_oauth: Mutex<Option<PendingOAuth>>,
    oauth_server_active: Arc<AtomicBool>,
    imported_files: Mutex<HashMap<String, PathBuf>>,
    next_file_id: AtomicU64,
}

impl AppState {
    fn new() -> Self {
        Self {
            pending_oauth: Mutex::new(None),
            oauth_server_active: Arc::new(AtomicBool::new(false)),
            imported_files: Mutex::new(HashMap::new()),
            next_file_id: AtomicU64::new(1),
        }
    }

    fn register_file(&self, path: PathBuf) -> String {
        let id = format!("f{}", self.next_file_id.fetch_add(1, Ordering::Relaxed));
        if let Ok(mut map) = self.imported_files.lock() {
            if map.len() >= MAX_REGISTERED_FILES {
                if let Some(oldest) = map.keys().next().cloned() {
                    map.remove(&oldest);
                }
            }
            map.insert(id.clone(), path);
        }
        id
    }

    fn lookup_file(&self, id: &str) -> Option<PathBuf> {
        self.imported_files
            .lock()
            .ok()
            .and_then(|map| map.get(id).cloned())
    }

    fn release_file(&self, id: &str) {
        if let Ok(mut map) = self.imported_files.lock() {
            map.remove(id);
        }
    }
}

// =============================================================================
// Environment & URL Helpers
// =============================================================================

fn supabase_url() -> String {
    std::env::var("CHIROOT_SUPABASE_URL")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_SUPABASE_URL.to_string())
}

fn supabase_publishable_key() -> String {
    std::env::var("CHIROOT_SUPABASE_KEY")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_SUPABASE_PUBLISHABLE_KEY.to_string())
}

fn http_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(20))
        .timeout_write(Duration::from_secs(15))
        .user_agent("ChirootDesktop/1.0 (macOS)")
        .build()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn is_download_url(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    let path = lower.split(['?', '#']).next().unwrap_or("");
    DOWNLOAD_EXTENSIONS.iter().any(|ext| path.ends_with(ext))
}

fn is_allowed_webview_url(raw: &str) -> bool {
    if raw.starts_with("tauri://")
        || raw.starts_with("https://tauri.localhost")
        || raw.starts_with("http://tauri.localhost")
        || raw.starts_with("about:")
        || raw.starts_with("blob:")
        || raw.starts_with("data:")
    {
        return true;
    }

    let Ok(parsed) = Url::parse(raw) else {
        return false;
    };
    let scheme = parsed.scheme();
    if scheme != "https" && scheme != "http" {
        return false;
    }

    let Some(host) = parsed.host_str() else {
        return false;
    };
    let h = host.to_ascii_lowercase();

    // Primary Chiroot domain
    if h == HOME_HOST || h.ends_with(&format!(".{HOME_HOST}")) {
        return true;
    }

    // Supabase project & Google OAuth domains (if user initiates in-page OAuth)
    let sb_host = Url::parse(&supabase_url())
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_ascii_lowercase()));
    if sb_host.as_deref() == Some(h.as_str()) {
        return true;
    }

    matches!(
        h.as_str(),
        "accounts.google.com"
            | "accounts.youtube.com"
            | "apis.google.com"
            | "ssl.gstatic.com"
            | "oauth2.googleapis.com"
    ) || h.ends_with(".google.com")
        || h.ends_with(".gstatic.com")
        || h.ends_with(".googleusercontent.com")
}

// =============================================================================
// File Validation & MIME Mapping (.json, .mp3, .png, .jpeg, .jpg)
// =============================================================================

fn allowed_mime_for_extension(ext: &str) -> Option<&'static str> {
    match ext {
        "json" => Some("application/json"),
        "mp3" => Some("audio/mpeg"),
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        _ => None,
    }
}

fn validate_file_header(ext: &str, header: &[u8]) -> Result<(), String> {
    if header.is_empty() {
        return Err("Selected file is empty.".to_string());
    }
    match ext {
        "png" => {
            const PNG_MAGIC: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
            if header.len() < PNG_MAGIC.len() || &header[..PNG_MAGIC.len()] != PNG_MAGIC {
                return Err("File does not have a valid PNG signature.".to_string());
            }
        }
        "jpg" | "jpeg" => {
            if header.len() < 3 || header[0] != 0xFF || header[1] != 0xD8 || header[2] != 0xFF {
                return Err("File does not have a valid JPEG signature.".to_string());
            }
        }
        "mp3" => {
            let is_id3 = header.len() >= 3 && &header[..3] == b"ID3";
            let is_mpeg_frame = header.len() >= 2 && header[0] == 0xFF && (header[1] & 0xE0) == 0xE0;
            // Some MP3 encoders prepend zero padding before the first MPEG sync frame.
            let has_sync_soon = header
                .windows(2)
                .any(|w| w[0] == 0xFF && (w[1] & 0xE0) == 0xE0);
            if !is_id3 && !is_mpeg_frame && !has_sync_soon {
                return Err("File does not appear to be a valid MP3 audio file.".to_string());
            }
        }
        "json" => {
            // Strip optional UTF-8 BOM and leading whitespace, then check valid JSON token start.
            let trimmed = header.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(header);
            let first = trimmed
                .iter()
                .copied()
                .find(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'));
            match first {
                Some(b'{' | b'[' | b'"' | b't' | b'f' | b'n' | b'-' | b'0'..=b'9') => {}
                _ => return Err("File does not start with valid JSON content.".to_string()),
            }
        }
        _ => {
            return Err(format!("Unsupported file extension '.{ext}'."));
        }
    }
    Ok(())
}

fn validate_and_register_file(
    state: &AppState,
    path: PathBuf,
) -> Result<ImportedFileDescriptor, String> {
    let meta = fs::metadata(&path)
        .map_err(|e| format!("Cannot read file metadata ({}): {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("Path is not a regular file: {}", path.display()));
    }
    let size = meta.len();
    if size == 0 {
        return Err(format!("File is empty: {}", path.display()));
    }
    if size > MAX_IMPORT_FILE_BYTES {
        return Err(format!(
            "File '{}' exceeds the {} MB safety limit.",
            path.display(),
            MAX_IMPORT_FILE_BYTES / (1024 * 1024)
        ));
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .ok_or_else(|| format!("File has no extension: {}", path.display()))?;

    let mime_type = allowed_mime_for_extension(&ext).ok_or_else(|| {
        format!(
            "Unsupported file type '.{ext}'. Supported types: .json, .mp3, .png, .jpeg, .jpg."
        )
    })?;

    // Read only the first 512 bytes for header validation (never loads whole file into RAM).
    let mut file = File::open(&path)
        .map_err(|e| format!("Cannot open file '{}': {e}", path.display()))?;
    let mut header = [0u8; 512];
    let n = file
        .read(&mut header)
        .map_err(|e| format!("Failed reading file header: {e}"))?;
    validate_file_header(&ext, &header[..n])?;

    // Full structural JSON validation only for reasonably sized JSON files (<= 16 MB).
    if ext == "json" && size <= 16 * 1024 * 1024 {
        let mut full = File::open(&path)
            .map_err(|e| format!("Cannot re-open JSON file: {e}"))?;
        let mut raw = String::new();
        full.read_to_string(&mut raw)
            .map_err(|e| format!("JSON file is not valid UTF-8: {e}"))?;
        let clean = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
        serde_json::from_str::<serde_json::Value>(clean)
            .map_err(|e| format!("Invalid JSON syntax: {e}"))?;
    }

    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("imported-file")
        .to_string();

    let id = state.register_file(path);
    Ok(ImportedFileDescriptor {
        id,
        name,
        extension: ext,
        mime_type: mime_type.to_string(),
        size,
    })
}

// =============================================================================
// PKCE & Persistent Supabase Session Management
// =============================================================================

fn random_base64url(num_bytes: usize) -> Result<String, String> {
    let mut buf = vec![0u8; num_bytes];
    getrandom::getrandom(&mut buf).map_err(|e| format!("CSPRNG error: {e}"))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

fn pkce_challenge_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn session_file_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to locate app data directory: {e}"))?;
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create app data directory: {e}"))?;
    Ok(dir.join("session.json"))
}

fn save_persisted_session(app: &AppHandle, session: &SupabaseSession) -> Result<(), String> {
    let path = session_file_path(app)?;
    let data = serde_json::to_vec(session).map_err(|e| format!("Serialize session failed: {e}"))?;
    fs::write(&path, data).map_err(|e| format!("Failed to persist session: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn load_persisted_session(app: &AppHandle) -> Option<SupabaseSession> {
    let path = session_file_path(app).ok()?;
    let bytes = fs::read(path).ok()?;
    let session: SupabaseSession = serde_json::from_slice(&bytes).ok()?;
    if session.access_token.is_empty() || session.user.id.is_empty() {
        return None;
    }
    Some(session)
}

fn clear_persisted_session(app: &AppHandle) {
    if let Ok(path) = session_file_path(app) {
        let _ = fs::remove_file(path);
    }
}

fn parse_supabase_token_response(val: &serde_json::Value) -> Result<SupabaseSession, String> {
    let access_token = val
        .get("access_token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Supabase response missing access_token.".to_string())?
        .to_string();

    let refresh_token = val
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let expires_at = if let Some(raw_exp) = val.get("expires_at").and_then(|v| v.as_u64()) {
        // Supabase returns Unix seconds; Main.html stores Unix milliseconds.
        if raw_exp < 10_000_000_000 {
            raw_exp.saturating_mul(1000)
        } else {
            raw_exp
        }
    } else {
        let expires_in = val
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);
        now_unix_ms().saturating_add(expires_in.saturating_mul(1000))
    };

    let user_obj = val
        .get("user")
        .ok_or_else(|| "Supabase response missing user object.".to_string())?;
    let user_id = user_obj
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Supabase response missing user.id.".to_string())?
        .to_string();
    let email = user_obj
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(SupabaseSession {
        access_token,
        refresh_token,
        expires_at,
        user: SupabaseUser { id: user_id, email },
    })
}

fn extract_supabase_error(val: &serde_json::Value, fallback: &str) -> String {
    for key in ["error_description", "msg", "message", "error"] {
        if let Some(s) = val.get(key).and_then(|v| v.as_str()) {
            if !s.trim().is_empty() {
                return s.trim().to_string();
            }
        }
    }
    fallback.to_string()
}

fn exchange_pkce_code(auth_code: &str, code_verifier: &str) -> Result<SupabaseSession, String> {
    let endpoint = format!("{}/auth/v1/token?grant_type=pkce", supabase_url());
    let resp = http_agent()
        .post(&endpoint)
        .set("apikey", &supabase_publishable_key())
        .set("Content-Type", "application/json")
        .send_json(serde_json::json!({
            "auth_code": auth_code,
            "code_verifier": code_verifier
        }));

    match resp {
        Ok(r) => {
            let val: serde_json::Value = r
                .into_json()
                .map_err(|e| format!("Failed parsing Supabase auth JSON: {e}"))?;
            parse_supabase_token_response(&val)
        }
        Err(ureq::Error::Status(code, r)) => {
            let val = r.into_json::<serde_json::Value>().unwrap_or_default();
            Err(extract_supabase_error(
                &val,
                &format!("Supabase PKCE token exchange failed (HTTP {code})."),
            ))
        }
        Err(ureq::Error::Transport(t)) => {
            Err(format!("Network error contacting Supabase Auth: {t}"))
        }
    }
}

fn refresh_supabase_session(refresh_token: &str) -> Result<SupabaseSession, String> {
    let endpoint = format!("{}/auth/v1/token?grant_type=refresh_token", supabase_url());
    let resp = http_agent()
        .post(&endpoint)
        .set("apikey", &supabase_publishable_key())
        .set("Content-Type", "application/json")
        .send_json(serde_json::json!({
            "refresh_token": refresh_token
        }));

    match resp {
        Ok(r) => {
            let val: serde_json::Value = r
                .into_json()
                .map_err(|e| format!("Failed parsing refreshed session JSON: {e}"))?;
            parse_supabase_token_response(&val)
        }
        Err(ureq::Error::Status(code, r)) => {
            let val = r.into_json::<serde_json::Value>().unwrap_or_default();
            Err(extract_supabase_error(
                &val,
                &format!("Supabase token refresh failed (HTTP {code})."),
            ))
        }
        Err(ureq::Error::Transport(t)) => Err(format!("Network error refreshing session: {t}")),
    }
}

fn revoke_supabase_session(access_token: &str) {
    let endpoint = format!("{}/auth/v1/logout", supabase_url());
    let _ = http_agent()
        .post(&endpoint)
        .set("apikey", &supabase_publishable_key())
        .set("Authorization", &format!("Bearer {access_token}"))
        .call();
}

/// Synchronizes a Supabase session into `Main.html`'s `localStorage['chiroot_auth_v1']`.
fn inject_session_into_webview(app: &AppHandle, session: &SupabaseSession, reload_after: bool) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let Ok(session_json) = serde_json::to_string(session) else {
        return;
    };
    let Ok(js_str_literal) = serde_json::to_string(&session_json) else {
        return;
    };
    let reload_js = if reload_after {
        "window.location.replace('https://www.chiroot.my.id/Main.html');"
    } else {
        ""
    };
    let script = format!(
        r#"(function () {{
          try {{
            var h = (window.location.hostname || '').toLowerCase();
            if (h === 'chiroot.my.id' || h.slice(-14) === '.chiroot.my.id') {{
              var incoming = {js_str_literal};
              var existing = localStorage.getItem('chiroot_auth_v1');
              if (existing !== incoming) {{
                localStorage.setItem('chiroot_auth_v1', incoming);
                {reload_js}
              }}
            }}
          }} catch (e) {{}}
        }})();"#,
    );
    let _ = window.eval(&script);
}

fn clear_session_in_webview(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.eval(
            r#"(function () {
              try {
                localStorage.removeItem('chiroot_auth_v1');
                if (window.ChirootAuth) {
                  window.ChirootAuth.session = null;
                  window.ChirootAuth.profile = null;
                }
                window.location.reload();
              } catch (e) {}
            })();"#,
        );
    }
}

fn focus_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn notify_webview(app: &AppHandle, message: &str, is_error: bool) {
    if let Some(window) = app.get_webview_window("main") {
        if let Ok(msg_literal) = serde_json::to_string(message) {
            let js = format!(
                "if (window.ChirootDesktop && window.ChirootDesktop.notify) {{ window.ChirootDesktop.notify({msg_literal}, {is_error}); }}"
            );
            let _ = window.eval(&js);
        }
    }
}

/// Parses an OAuth callback URL (`chiroot://auth/callback?...` or `http://127.0.0.1:PORT/auth/callback?...`).
fn parse_oauth_callback_params(raw_url: &str) -> Result<(Option<String>, Option<String>, Option<String>), String> {
    let parsed = Url::parse(raw_url).map_err(|e| format!("Invalid callback URL: {e}"))?;
    let mut code = None;
    let mut error = None;
    let mut state = None;

    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "error_description" => error = Some(v.into_owned()),
            "error" if error.is_none() => error = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            _ => {}
        }
    }
    Ok((code, error, state))
}

fn complete_oauth_callback(app: &AppHandle, callback_url: &str) -> Result<SupabaseSession, String> {
    let (code_opt, err_opt, state_opt) = parse_oauth_callback_params(callback_url)?;

    let pending = {
        let st = app.state::<AppState>();
        let mut guard = st
            .pending_oauth
            .lock()
            .map_err(|_| "Auth state lock error".to_string())?;
        guard.take()
    };

    if let Some(err_msg) = err_opt {
        notify_webview(app, &format!("Google sign-in failed: {err_msg}"), true);
        let _ = app.emit("chiroot-auth-error", &err_msg);
        return Err(err_msg);
    }

    let code = code_opt.ok_or_else(|| "OAuth callback did not contain an authorization code.".to_string())?;
    let pending = pending.ok_or_else(|| {
        "No pending OAuth login session found. Please start Google sign-in again.".to_string()
    })?;

    if pending.created_at.elapsed() > Duration::from_secs(OAUTH_TIMEOUT_SECS) {
        return Err("OAuth login request expired. Please try signing in again.".to_string());
    }

    if let Some(returned_state) = state_opt {
        if !pending.expected_state.is_empty() && returned_state != pending.expected_state {
            return Err("OAuth state mismatch. Login aborted for security.".to_string());
        }
    }

    let session = exchange_pkce_code(&code, &pending.verifier)?;
    save_persisted_session(app, &session)?;
    focus_main_window(app);
    inject_session_into_webview(app, &session, true);
    notify_webview(app, "Signed in with Google.", false);
    let _ = app.emit("chiroot-auth-updated", &session);
    Ok(session)
}

fn write_loopback_http_response(stream: &mut TcpStream, status: &str, title: &str, body_msg: &str) {
    let html = format!(
        "<!doctype html><html><head><meta charset='utf-8'><title>{title}</title>\
        <style>body{{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#f6f4ee;\
        color:#1d1b18;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}}\
        .box{{background:#fff;border:1px solid #ddd6c8;border-radius:14px;padding:28px 24px;\
        max-width:400px;text-align:center;}}</style></head><body><div class='box'>\
        <h2>{title}</h2><p>{body_msg}</p></div></body></html>"
    );
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html}",
        html.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// Spawns a single-use loopback HTTP listener on `127.0.0.1:<ephemeral-port>` that shuts down
/// immediately after handling the OAuth callback or timing out.
fn spawn_loopback_oauth_listener(app: AppHandle) -> Result<String, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("Failed to bind local OAuth callback port: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed reading local OAuth port: {e}"))?
        .port();
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("Failed setting OAuth socket nonblocking: {e}"))?;

    let active_flag = app.state::<AppState>().oauth_server_active.clone();
    active_flag.store(true, Ordering::SeqCst);

    let redirect_uri = format!("http://127.0.0.1:{port}/auth/callback");
    let base_origin = format!("http://127.0.0.1:{port}");

    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(OAUTH_TIMEOUT_SECS);
        while Instant::now() < deadline && active_flag.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _addr)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path_and_query = req
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");

                    if path_and_query.starts_with("/auth/callback") {
                        let full_url = format!("{base_origin}{path_and_query}");
                        match complete_oauth_callback(&app, &full_url) {
                            Ok(_) => write_loopback_http_response(
                                &mut stream,
                                "200 OK",
                                "Signed in to Chiroot Desktop",
                                "Authentication succeeded. You can close this tab and return to Chiroot Desktop.",
                            ),
                            Err(err) => write_loopback_http_response(
                                &mut stream,
                                "400 Bad Request",
                                "Sign-in Failed",
                                &err,
                            ),
                        }
                        break;
                    } else {
                        write_loopback_http_response(
                            &mut stream,
                            "404 Not Found",
                            "Chiroot Desktop",
                            "Waiting for OAuth callback…",
                        );
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(80));
                }
                Err(_) => break,
            }
        }
        active_flag.store(false, Ordering::SeqCst);
    });

    Ok(redirect_uri)
}

fn begin_google_oauth_flow(app: &AppHandle, use_deep_link: bool) -> Result<AuthStartResponse, String> {
    let verifier = random_base64url(32)?;
    let challenge = pkce_challenge_s256(&verifier);
    let expected_state = random_base64url(16)?;

    let (redirect_uri, mode) = if use_deep_link {
        (OAUTH_DEEP_LINK_REDIRECT.to_string(), "deep-link".to_string())
    } else {
        (spawn_loopback_oauth_listener(app.clone())?, "loopback".to_string())
    };

    {
        let st = app.state::<AppState>();
        let mut guard = st
            .pending_oauth
            .lock()
            .map_err(|_| "Failed locking OAuth state".to_string())?;
        *guard = Some(PendingOAuth {
            verifier,
            expected_state,
            created_at: Instant::now(),
        });
    }

    let mut auth_url = Url::parse(&format!("{}/auth/v1/authorize", supabase_url()))
        .map_err(|e| format!("Invalid Supabase URL: {e}"))?;
    auth_url
        .query_pairs_mut()
        .append_pair("provider", "google")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("redirect_to", &redirect_uri)
        .append_pair("prompt", "select_account");

    let authorize_url = auth_url.to_string();
    app.opener()
        .open_url(&authorize_url, None::<&str>)
        .map_err(|e| format!("Failed opening system browser for Google sign-in: {e}"))?;

    Ok(AuthStartResponse {
        authorize_url,
        redirect_uri,
        mode,
    })
}

// =============================================================================
// macOS Audio Device Discovery (Lazy, On-Demand, Zero Polling)
// =============================================================================

fn query_macos_audio_devices() -> Result<Vec<MacAudioDevice>, String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("/usr/sbin/system_profiler")
            .args(["SPAudioDataType", "-json"])
            .output()
            .map_err(|e| format!("Failed running system_profiler: {e}"))?;
        if !output.status.success() {
            return Err("macOS system_profiler returned an error querying audio hardware.".to_string());
        }
        let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|e| format!("Failed parsing macOS audio JSON: {e}"))?;

        let mut devices = Vec::new();
        if let Some(groups) = parsed.get("SPAudioDataType").and_then(|v| v.as_array()) {
            for group in groups {
                if let Some(items) = group.get("_items").and_then(|v| v.as_array()) {
                    for item in items {
                        let name = item
                            .get("_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Audio Device")
                            .to_string();
                        let manufacturer = item
                            .get("coreaudio_device_manufacturer")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let transport = item
                            .get("coreaudio_device_transport")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let is_default_output = item
                            .get("coreaudio_default_audio_output_device")
                            .and_then(|v| v.as_str())
                            == Some("spaudio_yes");
                        let is_default_input = item
                            .get("coreaudio_default_audio_input_device")
                            .and_then(|v| v.as_str())
                            == Some("spaudio_yes");
                        let has_output = item
                            .get("coreaudio_device_output")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                            > 0;
                        let has_input = item
                            .get("coreaudio_device_input")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                            > 0;

                        devices.push(MacAudioDevice {
                            name,
                            manufacturer,
                            transport,
                            is_default_output,
                            is_default_input,
                            has_output,
                            has_input,
                        });
                    }
                }
            }
        }
        Ok(devices)
    }

    #[cfg(not(target_os = "macos"))]
    {
        Ok(Vec::new())
    }
}

// =============================================================================
// Tauri Commands (Exposed to frontend/index.html & chiroot.my.id)
// =============================================================================

#[tauri::command]
async fn check_chiroot_reachable() -> ReachabilityResult {
    let resp = http_agent().head(CHIROOT_URL).call();
    match resp {
        Ok(r) => ReachabilityResult {
            reachable: true,
            status: Some(r.status()),
            error: None,
        },
        Err(ureq::Error::Status(code, _)) => ReachabilityResult {
            reachable: (200..500).contains(&code),
            status: Some(code),
            error: if code >= 500 {
                Some(format!("Chiroot server returned HTTP {code}."))
            } else {
                None
            },
        },
        Err(ureq::Error::Transport(t)) => ReachabilityResult {
            reachable: false,
            status: None,
            error: Some(format!("Network error: {t}")),
        },
    }
}

#[tauri::command]
fn open_external_url(app: AppHandle, url: String) -> Result<(), String> {
    let parsed = Url::parse(&url).map_err(|e| format!("Invalid URL: {e}"))?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err("Only http/https URLs can be opened externally.".to_string());
    }
    app.opener()
        .open_url(parsed.as_str(), None::<&str>)
        .map_err(|e| format!("Failed opening external URL: {e}"))
}

#[tauri::command]
async fn pick_import_files(
    app: AppHandle,
    filter_mode: Option<String>,
    multiple: Option<bool>,
) -> Result<Vec<ImportedFileDescriptor>, String> {
    let mode = filter_mode.unwrap_or_else(|| "all".to_string());
    let allow_multi = multiple.unwrap_or(true);

    let mut builder = app.dialog().file().set_title("Import Files into Chiroot");
    builder = match mode.as_str() {
        "audio" | "mp3" => builder.add_filter("MP3 Audio", &["mp3"]),
        "image" | "cover" => builder.add_filter("Images (PNG, JPEG)", &["png", "jpg", "jpeg"]),
        "json" => builder.add_filter("JSON Data", &["json"]),
        _ => builder
            .add_filter("Chiroot Supported Files", &["mp3", "json", "png", "jpg", "jpeg"])
            .add_filter("MP3 Audio", &["mp3"])
            .add_filter("Images (PNG, JPEG)", &["png", "jpg", "jpeg"])
            .add_filter("JSON Data", &["json"]),
    };

    let selected_paths: Vec<PathBuf> = if allow_multi {
        match builder.blocking_pick_files() {
            Some(list) => list
                .into_iter()
                .filter_map(|fp| fp.into_path().ok())
                .collect(),
            None => return Ok(Vec::new()),
        }
    } else {
        match builder.blocking_pick_file() {
            Some(fp) => fp.into_path().ok().into_iter().collect(),
            None => return Ok(Vec::new()),
        }
    };

    let state = app.state::<AppState>();
    let mut descriptors = Vec::with_capacity(selected_paths.len());
    let mut errors = Vec::new();

    for path in selected_paths {
        match validate_and_register_file(&state, path) {
            Ok(desc) => descriptors.push(desc),
            Err(err) => errors.push(err),
        }
    }

    if descriptors.is_empty() && !errors.is_empty() {
        return Err(errors.join(" | "));
    }
    if !errors.is_empty() {
        notify_webview(
            &app,
            &format!("Skipped unsupported file(s): {}", errors.join("; ")),
            true,
        );
    }

    Ok(descriptors)
}

#[tauri::command]
async fn read_imported_file_chunk(
    app: AppHandle,
    file_id: String,
    offset: u64,
    length: usize,
) -> Result<FileChunkResponse, String> {
    let state = app.state::<AppState>();
    let path = state
        .lookup_file(&file_id)
        .ok_or_else(|| "Imported file handle not found or already released.".to_string())?;

    let read_len = length.clamp(1, MAX_STREAM_CHUNK_BYTES);
    let mut file = File::open(&path).map_err(|e| format!("Failed opening imported file: {e}"))?;
    let total_len = file
        .metadata()
        .map_err(|e| format!("Failed reading file size: {e}"))?
        .len();

    if offset >= total_len {
        return Ok(FileChunkResponse {
            base64: String::new(),
            offset,
            bytes_read: 0,
            eof: true,
        });
    }

    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed seeking imported file: {e}"))?;
    let mut buf = vec![0u8; read_len.min((total_len - offset) as usize)];
    let n = file
        .read(&mut buf)
        .map_err(|e| format!("Failed reading imported file chunk: {e}"))?;
    buf.truncate(n);

    let eof = offset.saturating_add(n as u64) >= total_len || n == 0;
    Ok(FileChunkResponse {
        base64: BASE64_STANDARD.encode(&buf),
        offset,
        bytes_read: n,
        eof,
    })
}

#[tauri::command]
fn release_imported_file(app: AppHandle, file_id: String) {
    app.state::<AppState>().release_file(&file_id);
}

#[tauri::command]
async fn list_macos_audio_devices() -> Result<Vec<MacAudioDevice>, String> {
    query_macos_audio_devices()
}

#[tauri::command]
async fn start_google_auth(
    app: AppHandle,
    use_deep_link: Option<bool>,
) -> Result<AuthStartResponse, String> {
    begin_google_oauth_flow(&app, use_deep_link.unwrap_or(false))
}

#[tauri::command]
async fn get_auth_session(app: AppHandle) -> Result<Option<SupabaseSession>, String> {
    let Some(session) = load_persisted_session(&app) else {
        return Ok(None);
    };
    let now = now_unix_ms();
    // Auto-refresh token if within 60 seconds of expiry
    if session.expires_at <= now.saturating_add(60_000) && !session.refresh_token.is_empty() {
        match refresh_supabase_session(&session.refresh_token) {
            Ok(refreshed) => {
                save_persisted_session(&app, &refreshed)?;
                inject_session_into_webview(&app, &refreshed, false);
                return Ok(Some(refreshed));
            }
            Err(_) => {
                clear_persisted_session(&app);
                return Ok(None);
            }
        }
    }
    Ok(Some(session))
}

#[tauri::command]
async fn logout_auth(app: AppHandle) -> Result<(), String> {
    if let Some(session) = load_persisted_session(&app) {
        revoke_supabase_session(&session.access_token);
    }
    clear_persisted_session(&app);
    clear_session_in_webview(&app);
    Ok(())
}

#[tauri::command]
fn sync_web_session(app: AppHandle, session_json: Option<String>) -> Result<(), String> {
    match session_json {
        Some(raw) if !raw.trim().is_empty() => {
            if let Ok(session) = serde_json::from_str::<SupabaseSession>(&raw) {
                if !session.access_token.is_empty() && !session.user.id.is_empty() {
                    save_persisted_session(&app, &session)?;
                }
            }
        }
        _ => {
            // Keep persisted session intact unless the user explicitly signs out via logout_auth.
        }
    }
    Ok(())
}

// =============================================================================
// Native macOS Menu Bar
// =============================================================================

fn build_app_menu(app: &AppHandle) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    let app_submenu = SubmenuBuilder::new(app, APP_NAME)
        .about(None)
        .separator()
        .services()
        .separator()
        .hide()
        .hide_others()
        .show_all()
        .separator()
        .quit()
        .build()?;

    let import_all = MenuItemBuilder::with_id("import_all", "Import Files (.mp3, .json, .png, .jpg)…")
        .accelerator("CmdOrCtrl+O")
        .build(app)?;
    let import_mp3 = MenuItemBuilder::with_id("import_mp3", "Import MP3 Audio…").build(app)?;
    let import_cover = MenuItemBuilder::with_id("import_cover", "Import Cover Image…").build(app)?;
    let import_json = MenuItemBuilder::with_id("import_json", "Import JSON Data…").build(app)?;

    let file_submenu = SubmenuBuilder::new(app, "File")
        .item(&import_all)
        .item(&import_mp3)
        .item(&import_cover)
        .item(&import_json)
        .separator()
        .close_window()
        .build()?;

    let edit_submenu = SubmenuBuilder::new(app, "Edit")
        .undo()
        .redo()
        .separator()
        .cut()
        .copy()
        .paste()
        .select_all()
        .build()?;

    let nav_reload = MenuItemBuilder::with_id("nav_reload", "Reload")
        .accelerator("CmdOrCtrl+R")
        .build(app)?;
    let nav_home = MenuItemBuilder::with_id("nav_home", "Go to Chiroot Home")
        .accelerator("CmdOrCtrl+Shift+H")
        .build(app)?;
    let nav_back = MenuItemBuilder::with_id("nav_back", "Back")
        .accelerator("CmdOrCtrl+[")
        .build(app)?;
    let nav_forward = MenuItemBuilder::with_id("nav_forward", "Forward")
        .accelerator("CmdOrCtrl+]")
        .build(app)?;

    let view_submenu = SubmenuBuilder::new(app, "View")
        .item(&nav_reload)
        .item(&nav_home)
        .separator()
        .item(&nav_back)
        .item(&nav_forward)
        .separator()
        .fullscreen()
        .build()?;

    let auth_browser =
        MenuItemBuilder::with_id("auth_google_browser", "Sign in with Google (Browser)…")
            .build(app)?;
    let auth_deeplink =
        MenuItemBuilder::with_id("auth_google_deeplink", "Sign in with Google (Deep Link)…")
            .build(app)?;
    let auth_logout = MenuItemBuilder::with_id("auth_logout", "Sign Out").build(app)?;

    let account_submenu = SubmenuBuilder::new(app, "Account")
        .item(&auth_browser)
        .item(&auth_deeplink)
        .separator()
        .item(&auth_logout)
        .build()?;

    let audio_devices =
        MenuItemBuilder::with_id("audio_devices", "Detect Audio & Headset Devices…").build(app)?;
    let audio_submenu = SubmenuBuilder::new(app, "Audio")
        .item(&audio_devices)
        .build()?;

    let window_submenu = SubmenuBuilder::with_id(app, WINDOW_SUBMENU_ID, "Window")
        .minimize()
        .separator()
        .close_window()
        .build()?;

    MenuBuilder::new(app)
        .items(&[
            &app_submenu,
            &file_submenu,
            &edit_submenu,
            &view_submenu,
            &account_submenu,
            &audio_submenu,
            &window_submenu,
        ])
        .build()
}

fn trigger_menu_import(app: AppHandle, filter_mode: &'static str) {
    let mode = filter_mode.to_string();
    tauri::async_runtime::spawn(async move {
        match pick_import_files(app.clone(), Some(mode), Some(true)).await {
            Ok(descs) if !descs.is_empty() => {
                if let Some(window) = app.get_webview_window("main") {
                    if let Ok(json) = serde_json::to_string(&descs) {
                        let js = format!(
                            "if (window.ChirootDesktop && window.ChirootDesktop._receiveMenuImport) {{ window.ChirootDesktop._receiveMenuImport({json}); }}"
                        );
                        let _ = window.eval(&js);
                    }
                }
            }
            Ok(_) => {}
            Err(err) => notify_webview(&app, &err, true),
        }
    });
}

fn handle_menu_event(app: &AppHandle, id: &str) {
    match id {
        "import_all" => trigger_menu_import(app.clone(), "all"),
        "import_mp3" => trigger_menu_import(app.clone(), "mp3"),
        "import_cover" => trigger_menu_import(app.clone(), "image"),
        "import_json" => trigger_menu_import(app.clone(), "json"),
        "nav_reload" => {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.eval("window.location.reload();");
            }
        }
        "nav_home" => {
            if let Some(w) = app.get_webview_window("main") {
                if let Ok(url) = Url::parse(CHIROOT_URL) {
                    let _ = w.navigate(url);
                }
            }
        }
        "nav_back" => {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.eval("window.history.back();");
            }
        }
        "nav_forward" => {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.eval("window.history.forward();");
            }
        }
        "auth_google_browser" => {
            if let Err(e) = begin_google_oauth_flow(app, false) {
                notify_webview(app, &e, true);
            }
        }
        "auth_google_deeplink" => {
            if let Err(e) = begin_google_oauth_flow(app, true) {
                notify_webview(app, &e, true);
            }
        }
        "auth_logout" => {
            let handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let _ = logout_auth(handle).await;
            });
        }
        "audio_devices" => {
            let handle = app.clone();
            tauri::async_runtime::spawn(async move {
                match query_macos_audio_devices() {
                    Ok(devs) if !devs.is_empty() => {
                        let summary: Vec<String> = devs
                            .iter()
                            .map(|d| {
                                if d.is_default_output {
                                    format!("{} (Default Output)", d.name)
                                } else {
                                    d.name.clone()
                                }
                            })
                            .collect();
                        notify_webview(
                            &handle,
                            &format!("Audio devices: {}", summary.join(", ")),
                            false,
                        );
                    }
                    Ok(_) => notify_webview(
                        &handle,
                        "No macOS audio devices reported. Check System Preferences > Sound.",
                        false,
                    ),
                    Err(e) => notify_webview(&handle, &e, true),
                }
            });
        }
        _ => {}
    }
}

// =============================================================================
// Single-WebView Main Window Builder
// =============================================================================

fn create_main_window(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    let nav_app = app.clone();
    let load_app = app.clone();

    WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title(APP_NAME)
        .inner_size(1200.0, 800.0)
        .min_inner_size(800.0, 560.0)
        .center()
        .resizable(true)
        .user_agent(MACOS_USER_AGENT)
        .initialization_script(BRIDGE_INIT_JS)
        .on_navigation(move |url| {
            let raw = url.as_str();
            if is_download_url(raw) {
                let _ = nav_app.opener().open_url(raw, None::<&str>);
                return false;
            }
            if is_allowed_webview_url(raw) {
                return true;
            }
            if matches!(url.scheme(), "https" | "http") {
                let _ = nav_app.opener().open_url(raw, None::<&str>);
            }
            false
        })
        .on_page_load(move |window, payload| {
            if matches!(payload.event(), PageLoadEvent::Finished) {
                let url_str = payload.url().as_str();
                if url_str.contains("chiroot.my.id") {
                    let _ = window.set_title(APP_NAME);
                    if let Some(session) = load_persisted_session(&load_app) {
                        let now = now_unix_ms();
                        if session.expires_at > now.saturating_add(15_000) {
                            inject_session_into_webview(&load_app, &session, false);
                        }
                    }
                }
            }
        })
        .build()
}

// =============================================================================
// Deep Link Setup (chiroot://auth/callback)
// =============================================================================

fn wire_deep_links(app: &AppHandle) {
    if let Ok(Some(urls)) = app.deep_link().get_current() {
        for url in urls {
            let raw = url.as_str().to_string();
            if raw.starts_with("chiroot://") {
                let handle = app.clone();
                std::thread::spawn(move || {
                    let _ = complete_oauth_callback(&handle, &raw);
                });
            }
        }
    }

    let handle = app.clone();
    app.deep_link().on_open_url(move |event| {
        for url in event.urls() {
            let raw = url.as_str().to_string();
            if raw.starts_with("chiroot://") {
                let app_handle = handle.clone();
                std::thread::spawn(move || {
                    let _ = complete_oauth_callback(&app_handle, &raw);
                });
            }
        }
    });
}

// =============================================================================
// Application Entry Point
// =============================================================================

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_deep_link::init())
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            check_chiroot_reachable,
            open_external_url,
            pick_import_files,
            read_imported_file_chunk,
            release_imported_file,
            list_macos_audio_devices,
            start_google_auth,
            get_auth_session,
            logout_auth,
            sync_web_session,
        ])
        .setup(|app| {
            let handle = app.handle();
            let menu = build_app_menu(handle)?;
            app.set_menu(menu)?;

            create_main_window(handle)?;
            wire_deep_links(handle);

            Ok(())
        })
        .on_menu_event(|app, event| {
            handle_menu_event(app, event.id().as_ref());
        })
        .run(tauri::generate_context!())
        .expect("error while running Chiroot Desktop");
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_matches_rfc7636_test_vector() {
        // RFC 7636 Appendix B test vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(pkce_challenge_s256(verifier), expected);
    }

    #[test]
    fn allowed_mime_types_match_spec() {
        assert_eq!(allowed_mime_for_extension("json"), Some("application/json"));
        assert_eq!(allowed_mime_for_extension("mp3"), Some("audio/mpeg"));
        assert_eq!(allowed_mime_for_extension("png"), Some("image/png"));
        assert_eq!(allowed_mime_for_extension("jpg"), Some("image/jpeg"));
        assert_eq!(allowed_mime_for_extension("jpeg"), Some("image/jpeg"));
        assert_eq!(allowed_mime_for_extension("exe"), None);
        assert_eq!(allowed_mime_for_extension("wav"), None);
    }

    #[test]
    fn header_validation_accepts_valid_and_rejects_corrupt_files() {
        assert!(validate_file_header("png", &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]).is_ok());
        assert!(validate_file_header("png", b"not a png").is_err());

        assert!(validate_file_header("jpg", &[0xFF, 0xD8, 0xFF, 0xE0]).is_ok());
        assert!(validate_file_header("jpeg", &[0xFF, 0xD8, 0xFF, 0xE1]).is_ok());
        assert!(validate_file_header("jpg", b"plain text").is_err());

        assert!(validate_file_header("mp3", b"ID3\x03\x00").is_ok());
        assert!(validate_file_header("mp3", &[0xFF, 0xFB, 0x90, 0x00]).is_ok());
        assert!(validate_file_header("mp3", b"not audio").is_err());

        assert!(validate_file_header("json", b"  {\"ok\": true}").is_ok());
        assert!(validate_file_header("json", b"<html>nope</html>").is_err());
    }

    #[test]
    fn webview_url_allowlist_and_downloads() {
        assert!(is_allowed_webview_url("https://www.chiroot.my.id/Main.html"));
        assert!(is_allowed_webview_url("https://astuagdezahmuuwjoghf.supabase.co/auth/v1/authorize"));
        assert!(is_allowed_webview_url("https://accounts.google.com/o/oauth2/v2/auth"));
        assert!(!is_allowed_webview_url("https://example.com/external"));
        assert!(is_download_url("https://www.chiroot.my.id/Chiroot.dmg"));
        assert!(!is_download_url("https://www.chiroot.my.id/Main.html"));
    }

    #[test]
    fn oauth_callback_parser_extracts_code_and_error() {
        let (code, err, state) = parse_oauth_callback_params(
            "chiroot://auth/callback?code=abc123&state=xyz789",
        )
        .unwrap();
        assert_eq!(code.as_deref(), Some("abc123"));
        assert_eq!(err, None);
        assert_eq!(state.as_deref(), Some("xyz789"));

        let (code2, err2, _) = parse_oauth_callback_params(
            "http://127.0.0.1:43210/auth/callback?error=access_denied&error_description=User+cancelled",
        )
        .unwrap();
        assert_eq!(code2, None);
        assert_eq!(err2.as_deref(), Some("User cancelled"));
    }
}
