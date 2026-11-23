#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Chiroot Desktop — Lightweight macOS desktop application for Chiroot Audio Player.
//!
//! All Rust application logic is centralized in this single file (`src/main.rs`):
//! - Local High Sierra 10.13.6+ compatibility proxy loading live `https://www.chiroot.my.id/Main.html`
//!   over modern Rustls TLS (`webpki-roots`), patching Safari 11–13 JS/CSS gaps on the fly
//!   (optional chaining `?.`, `Blob.arrayBuffer`/`text`, CSS `inset:`, double-stop gradients,
//!   `conic-gradient`, `dvh`, `clamp()`/`min()`/`max()`, flex `gap`) without redesigning the site
//! - Proxying Supabase API/Storage and Google Fonts through Rustls so High Sierra's outdated
//!   root CA trust store never breaks assets, audio streaming (`Range`/`206`), or cloud sync
//! - Single-WebView native window + WKWebView autoplay support + zero-polling playback unlock bridge
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
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Mutex;
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
const CHIROOT_ORIGIN: &str = "https://www.chiroot.my.id";
const CHIROOT_URL: &str = "https://www.chiroot.my.id/Main.html";
const HOME_HOST: &str = "chiroot.my.id";
const OAUTH_DEEP_LINK_REDIRECT: &str = "chiroot://auth/callback";

/// Preferred local port for the High Sierra compatibility proxy so `localStorage`
/// and IndexedDB persist across restarts on a consistent origin (`http://127.0.0.1:47821`).
/// Falls back to an OS-assigned ephemeral port if 47821 is unavailable.
const PREFERRED_PROXY_PORT: u16 = 47821;

/// Public Supabase project URL & publishable (anon) key used by Chiroot Web.
/// Never place a Supabase `service_role` key in client code.
const DEFAULT_SUPABASE_URL: &str = "https://astuagdezahmuuwjoghf.supabase.co";
const DEFAULT_SUPABASE_PUBLISHABLE_KEY: &str =
    "sb_publishable_NXhR-MquEMwYDrCBPAOgAQ_MZ4BXQlT";

/// Standard macOS Safari UA string targeting High Sierra 10.13.6 WebKit compatibility.
const MACOS_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) \
    AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.15";

/// Hard limits for safe, low-RAM file importing and proxy uploads.
const MAX_IMPORT_FILE_BYTES: u64 = 100 * 1024 * 1024; // 100 MB
const MAX_PROXY_REQUEST_BODY: usize = 35 * 1024 * 1024; // 35 MB (MP3/ZIP uploads)
const MAX_STREAM_CHUNK_BYTES: usize = 1024 * 1024; // 1 MB max per chunk read
const PROXY_STREAM_BUF_BYTES: usize = 64 * 1024; // 64 KB proxy streaming buffer
const MAX_REGISTERED_FILES: usize = 64;
const OAUTH_TIMEOUT_SECS: u64 = 300;

const DOWNLOAD_EXTENSIONS: &[&str] = &[
    ".dmg", ".pkg", ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".exe", ".msi", ".deb", ".rpm",
    ".appimage", ".apk", ".sh", ".run",
];

/// Polyfills & config injected at the very top of `<head>` inside `Main.html`
/// so Safari 11 / 12 / 13 on macOS High Sierra 10.13.6 runs all Chiroot features cleanly.
const HIGH_SIERRA_HEAD_SHIM: &str = r#"<script>(function(){
  try {
    window.CHIROOT_CONFIG = window.CHIROOT_CONFIG || {};
    window.CHIROOT_CONFIG.SUPABASE_URL = window.location.origin + '/__supabase';
    window.CHIROOT_CONFIG.SUPABASE_PUBLISHABLE_KEY = '__SUPABASE_KEY__';
  } catch (e) {}

  if (typeof window.globalThis === 'undefined') { window.globalThis = window; }
  if (typeof window.queueMicrotask !== 'function') {
    window.queueMicrotask = function (cb) { Promise.resolve().then(cb); };
  }
  if (!Promise.prototype.finally) {
    Promise.prototype.finally = function (cb) {
      var P = this.constructor;
      return this.then(
        function (v) { return P.resolve(cb()).then(function () { return v; }); },
        function (r) { return P.resolve(cb()).then(function () { throw r; }); }
      );
    };
  }
  if (typeof Blob !== 'undefined') {
    if (!Blob.prototype.arrayBuffer) {
      Blob.prototype.arrayBuffer = function () {
        var self = this;
        return new Promise(function (resolve, reject) {
          var fr = new FileReader();
          fr.onload = function () { resolve(fr.result); };
          fr.onerror = function () { reject(fr.error || new Error('FileReader arrayBuffer error')); };
          fr.readAsArrayBuffer(self);
        });
      };
    }
    if (!Blob.prototype.text) {
      Blob.prototype.text = function () {
        var self = this;
        return new Promise(function (resolve, reject) {
          var fr = new FileReader();
          fr.onload = function () { resolve(String(fr.result || '')); };
          fr.onerror = function () { reject(fr.error || new Error('FileReader text error')); };
          fr.readAsText(self);
        });
      };
    }
  }
  if (window.crypto && typeof window.crypto.randomUUID !== 'function' && typeof window.crypto.getRandomValues === 'function') {
    window.crypto.randomUUID = function () {
      var b = new Uint8Array(16);
      window.crypto.getRandomValues(b);
      b[6] = (b[6] & 0x0f) | 0x40;
      b[8] = (b[8] & 0x3f) | 0x80;
      var h = [];
      for (var i = 0; i < 16; i++) h.push((b[i] + 256).toString(16).slice(1));
      return h[0]+h[1]+h[2]+h[3]+'-'+h[4]+h[5]+'-'+h[6]+h[7]+'-'+h[8]+h[9]+'-'+h[10]+h[11]+h[12]+h[13]+h[14]+h[15];
    };
  }
  if (!String.prototype.replaceAll) {
    String.prototype.replaceAll = function (search, replacement) {
      if (search instanceof RegExp) return this.replace(search, replacement);
      return this.split(String(search)).join(String(replacement));
    };
  }
  if (!Object.fromEntries) {
    Object.fromEntries = function (entries) {
      var obj = {};
      if (!entries) return obj;
      for (var i = 0; i < entries.length; i++) {
        obj[entries[i][0]] = entries[i][1];
      }
      return obj;
    };
  }
  if (!Array.prototype.flat) {
    Array.prototype.flat = function (depth) {
      var d = depth === undefined ? 1 : Number(depth);
      var out = [];
      (function flatten(arr, lvl) {
        for (var i = 0; i < arr.length; i++) {
          if (Array.isArray(arr[i]) && lvl > 0) flatten(arr[i], lvl - 1);
          else out.push(arr[i]);
        }
      })(this, d);
      return out;
    };
  }
  if (typeof window.AbortController !== 'function') {
    window.AbortController = function () {
      this.signal = { aborted: false, addEventListener: function () {}, removeEventListener: function () {} };
      this.abort = function () { this.signal.aborted = true; };
    };
  }
  function detectFlexGap() {
    try {
      if (!document.body) return;
      var flex = document.createElement('div');
      flex.style.display = 'flex';
      flex.style.flexDirection = 'column';
      flex.style.rowGap = '1px';
      flex.appendChild(document.createElement('div'));
      flex.appendChild(document.createElement('div'));
      document.body.appendChild(flex);
      var supported = flex.scrollHeight === 1;
      document.body.removeChild(flex);
      if (!supported) document.documentElement.classList.add('hs-noflexgap');
    } catch (e) {}
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', detectFlexGap);
  } else {
    detectFlexGap();
  }
})();</script>"#;

/// Extra Safari 11–13 Flexbox spacing fallback appended to `css/style.css`
/// (only activates when `html.hs-noflexgap` is detected on macOS < 11.3 / Safari < 14.1).
const HIGH_SIERRA_CSS_FALLBACK: &str = r#"
/* Chiroot Desktop — macOS High Sierra 10.13.6 WebKit compatibility fallbacks */
html.hs-noflexgap .controls > * + *,
html.hs-noflexgap .volume-row > * + *,
html.hs-noflexgap .crate-actions > * + *,
html.hs-noflexgap .topbar-auth > * + *,
html.hs-noflexgap .bluetooth-modal-actions > * + *,
html.hs-noflexgap .modal-actions > * + *,
html.hs-noflexgap .share-actions > * + * {
  margin-left: 10px;
}
html.hs-noflexgap .gate-btn-wrap > * + *,
html.hs-noflexgap .acct-list > * + *,
html.hs-noflexgap .bluetooth-device-list > * + *,
html.hs-noflexgap .top10-list > * + * {
  margin-top: 10px;
}
.modal-overlay,
#auth-overlay {
  top: 0;
  right: 0;
  bottom: 0;
  left: 0;
}
"#;

/// Lightweight initialization script injected on Chiroot pages (both local proxy `127.0.0.1`
/// and `chiroot.my.id`). Written in pure ES2017 (zero `?.` / `??`) for High Sierra 10.13.6!
/// - Zero `setInterval` polling (strictly event-driven to keep idle CPU ~0%).
/// - Intercepts Google Login buttons & `caLoginRedirect` so Google OAuth opens in the user's
///   external system browser (bypassing Google's embedded WebView block on macOS High Sierra).
/// - Unlocks Web Audio / HTMLMediaElement playback while keeping normal controls intact.
/// - Exposes `window.ChirootDesktop` native helpers (file import, OAuth, audio devices).
const BRIDGE_INIT_JS: &str = r#"(function () {
  var host = (window.location && window.location.hostname || '').toLowerCase();
  var isChirootOrigin =
    host === '127.0.0.1' ||
    host === 'localhost' ||
    host === 'chiroot.my.id' ||
    host.slice(-14) === '.chiroot.my.id';
  if (!isChirootOrigin) {
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
          'max-width:380px;padding:10px 14px;border-radius:10px;font-size:12px;line-height:1.45;' +
          'font-family:-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;' +
          'box-shadow:0 4px 16px rgba(0,0,0,0.22);transition:opacity 0.15s ease;';
        if (document.body) document.body.appendChild(el);
      }
      el.style.background = isError ? '#3b1c1c' : '#1b1d17';
      el.style.color = '#f7f5ee';
      el.style.border = isError ? '1px solid #d96b6b' : '1px solid #d4ec8a';
      el.style.opacity = '1';
      el.textContent = String(msg || '');
      clearTimeout(el.__hideTimer);
      el.__hideTimer = setTimeout(function () {
        el.style.opacity = '0';
      }, 5000);
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
    document.removeEventListener('mousedown', onFirstGesture, true);
    document.removeEventListener('keydown', onFirstGesture, true);
  }
  document.addEventListener('pointerdown', onFirstGesture, true);
  document.addEventListener('mousedown', onFirstGesture, true);
  document.addEventListener('keydown', onFirstGesture, true);

  // ---------------------------------------------------------------------------
  // 2. Native Google OAuth via System Browser (bypasses WKWebView block)
  // ---------------------------------------------------------------------------
  function triggerNativeGoogleLogin() {
    showBanner('Opening your browser for Google Sign-In…', false);
    return invoke('start_google_auth', { useDeepLink: false }).catch(function (err) {
      var msg = (err && err.message) ? err.message : String(err || 'Google Sign-In failed');
      showBanner('Google Sign-In error: ' + msg, true);
    });
  }

  document.addEventListener('click', function (ev) {
    try {
      var target = ev.target;
      if (!target || typeof target.closest !== 'function') return;
      var btn = target.closest('#gate-login-btn, #btn-guest-save-login, #acct-add, .google-btn');
      if (!btn || btn.id === 'gate-retry-btn') return;
      var txt = (btn.textContent || '').toLowerCase();
      if (btn.id === 'gate-login-btn' || btn.id === 'btn-guest-save-login' || btn.id === 'acct-add' || txt.indexOf('google') !== -1) {
        ev.preventDefault();
        ev.stopPropagation();
        ev.stopImmediatePropagation();
        triggerNativeGoogleLogin();
      }
    } catch (e) {}
  }, true);

  window.addEventListener('DOMContentLoaded', function () {
    try {
      if (typeof window.caLoginRedirect === 'function') {
        window.caLoginRedirect = function () {
          triggerNativeGoogleLogin();
        };
      }
    } catch (e) {}
  });

  // ---------------------------------------------------------------------------
  // 3. External link handling for window.open
  // ---------------------------------------------------------------------------
  var origOpen = window.open;
  window.open = function (url) {
    try {
      if (typeof url === 'string' && /^https?:\/\//i.test(url)) {
        var parsed = new URL(url, window.location.href);
        var h = parsed.hostname.toLowerCase();
        var isInternal = h === '127.0.0.1' || h === 'localhost' || h === 'chiroot.my.id' || h.slice(-14) === '.chiroot.my.id';
        if (!isInternal) {
          invoke('open_external_url', { url: parsed.toString() }).catch(function () {});
          return null;
        }
      }
    } catch (e) {}
    return origOpen ? origOpen.apply(window, arguments) : null;
  };

  // ---------------------------------------------------------------------------
  // 4. Audio & Headset Device Discovery Helpers (event-driven, zero polling)
  // ---------------------------------------------------------------------------
  function enumerateAudioDevicesWithHints() {
    var result = { webDevices: [], macDevices: [], permissionError: null };
    return invoke('list_macos_audio_devices')
      .then(function (devs) { result.macDevices = devs || []; })
      .catch(function () {})
      .then(function () {
        if (!navigator.mediaDevices || typeof navigator.mediaDevices.enumerateDevices !== 'function') {
          result.permissionError = 'WebKit MediaDevices API is unavailable on this macOS version. Audio follows System Preferences > Sound.';
          return result;
        }
        return navigator.mediaDevices.enumerateDevices().then(function (list) {
          var hasLabels = list.some(function (d) { return d && d.label; });
          if (!hasLabels && typeof navigator.mediaDevices.getUserMedia === 'function') {
            return navigator.mediaDevices.getUserMedia({ audio: true })
              .then(function (stream) {
                stream.getTracks().forEach(function (t) { t.stop(); });
                return navigator.mediaDevices.enumerateDevices();
              })
              .catch(function (permErr) {
                if (permErr && permErr.name === 'NotAllowedError') {
                  result.permissionError = 'Microphone permission denied. Enable Chiroot Desktop in System Preferences > Security & Privacy > Microphone to view headset labels.';
                } else if (permErr && permErr.name === 'NotFoundError') {
                  result.permissionError = 'No audio input device was found.';
                } else {
                  result.permissionError = (permErr && permErr.message) || 'Audio device permission unavailable.';
                }
                return list;
              });
          }
          return list;
        }).then(function (finalList) {
          result.webDevices = finalList
            .filter(function (d) { return d.kind === 'audioinput' || d.kind === 'audiooutput'; })
            .map(function (d) {
              return { deviceId: d.deviceId, kind: d.kind, label: d.label || '', groupId: d.groupId || '' };
            });
          return result;
        }).catch(function (err) {
          result.permissionError = (err && err.message) || 'Failed to enumerate audio devices.';
          return result;
        });
      });
  }

  if (navigator.mediaDevices && typeof navigator.mediaDevices.addEventListener === 'function') {
    navigator.mediaDevices.addEventListener('devicechange', function () {
      window.dispatchEvent(new CustomEvent('chiroot:audio-devices-changed'));
    });
  }

  // ---------------------------------------------------------------------------
  // 5. Chunked Native File Import into Chiroot (zero double-buffering in Rust)
  // ---------------------------------------------------------------------------
  function readDescriptorToFile(desc) {
    var chunkSize = 512 * 1024;
    var parts = [];
    var offset = 0;

    function nextChunk() {
      if (offset >= desc.size) {
        return Promise.resolve(new File(parts, desc.name, { type: desc.mimeType }));
      }
      return invoke('read_imported_file_chunk', {
        fileId: desc.id,
        offset: offset,
        length: chunkSize
      }).then(function (res) {
        var bin = atob(res.base64);
        var bytes = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) {
          bytes[i] = bin.charCodeAt(i);
        }
        parts.push(bytes);
        offset += bytes.length;
        if (res.eof || bytes.length === 0) {
          return new File(parts, desc.name, { type: desc.mimeType });
        }
        return nextChunk();
      });
    }

    return nextChunk().then(
      function (file) {
        invoke('release_imported_file', { fileId: desc.id }).catch(function () {});
        return file;
      },
      function (err) {
        invoke('release_imported_file', { fileId: desc.id }).catch(function () {});
        throw err;
      }
    );
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

  function handleNativeImportedDescriptors(descriptors) {
    if (!Array.isArray(descriptors) || !descriptors.length) return Promise.resolve([]);
    var imported = [];
    var openedAddModal = false;
    var chain = Promise.resolve();

    descriptors.forEach(function (desc) {
      chain = chain.then(function () {
        return readDescriptorToFile(desc).then(function (file) {
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
            return file.text().then(function (text) {
              var parsed = JSON.parse(text);
              window.dispatchEvent(new CustomEvent('chiroot:json-imported', {
                detail: { name: desc.name, size: desc.size, data: parsed }
              }));
              showBanner('Validated JSON imported: ' + desc.name, false);
            });
          }
        }).catch(function (err) {
          showBanner('Import failed (' + desc.name + '): ' + (err && err.message ? err.message : err), true);
        });
      });
    });

    return chain.then(function () { return imported; });
  }

  // ---------------------------------------------------------------------------
  // 6. Supabase Auth Sync between Main.html and Rust secure session store
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

  window.ChirootDesktop = {
    version: '1.0.0',
    notify: showBanner,
    importFiles: function (filterMode, multiple) {
      return invoke('pick_import_files', {
        filterMode: filterMode || 'all',
        multiple: multiple !== false
      }).then(handleNativeImportedDescriptors);
    },
    _receiveMenuImport: handleNativeImportedDescriptors,
    startGoogleAuth: function (useDeepLink) {
      return invoke('start_google_auth', { useDeepLink: !!useDeepLink });
    },
    completeOAuthFromUrl: function (callbackUrl) {
      return invoke('complete_oauth_from_url', { callbackUrl: callbackUrl });
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
struct EntryUrlResult {
    reachable: bool,
    entry_url: Option<String>,
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
    imported_files: Mutex<HashMap<String, PathBuf>>,
    next_file_id: AtomicU64,
    proxy_port: AtomicU16,
}

impl AppState {
    fn new() -> Self {
        Self {
            pending_oauth: Mutex::new(None),
            imported_files: Mutex::new(HashMap::new()),
            next_file_id: AtomicU64::new(1),
            proxy_port: AtomicU16::new(0),
        }
    }

    fn proxy_origin(&self) -> String {
        let port = self.proxy_port.load(Ordering::SeqCst);
        if port > 0 {
            format!("http://127.0.0.1:{port}")
        } else {
            CHIROOT_ORIGIN.to_string()
        }
    }

    fn proxy_main_url(&self) -> String {
        format!("{}/Main.html", self.proxy_origin())
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
        .timeout_read(Duration::from_secs(30))
        .timeout_write(Duration::from_secs(30))
        .user_agent(MACOS_USER_AGENT)
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

    // Local compatibility proxy origin
    if h == "127.0.0.1" || h == "localhost" {
        return true;
    }

    // Primary Chiroot domain
    if h == HOME_HOST || h.ends_with(&format!(".{HOME_HOST}")) {
        return true;
    }

    false
}

// =============================================================================
// High Sierra 10.13.6 WebKit Compatibility Patchers (JS, HTML, CSS)
// =============================================================================

/// Patches JavaScript for macOS High Sierra 10.13.6 WebKit (Safari 11–13.0 JavaScriptCore),
/// eliminating ES2020 optional chaining syntax errors (`?.`) and allowing local proxy Supabase URL.
fn patch_js_for_high_sierra(src: &str) -> String {
    let mut out = src.to_string();

    // Known fatal ES2020 optional chaining occurrences in Main.html (lines 3560 & 4653)
    out = out.replace("w[0]?.toUpperCase()", "(w[0]?w[0].toUpperCase():'')");
    out = out.replace(
        "e.target.closest('.vswatch')?.classList.add('active')",
        "(function(__el){if(__el)__el.classList.add('active');})(e.target.closest('.vswatch'))",
    );

    // Allow http://127.0.0.1:<port>/__supabase inside Main.html's isSupabaseConfigured()
    out = out.replace(
        "return parsedUrl.protocol === 'https:' && publishableKey.length >= 20;",
        "return (parsedUrl.protocol === 'https:' || parsedUrl.hostname === '127.0.0.1' || parsedUrl.hostname === 'localhost') && publishableKey.length >= 20;",
    );

    out
}

/// Patches `Main.html` for macOS High Sierra 10.13.6:
/// - Injects ES2017/Safari-11 polyfills & `CHIROOT_CONFIG` pointing to the Rustls Supabase proxy
/// - Rewrites CSP meta tag to remove `upgrade-insecure-requests` and permit local proxy origin
/// - Routes Google Fonts through `/__fonts_css` so High Sierra's outdated root CAs never fail
/// - Patches optional chaining `?.` so the 121 KB player script executes cleanly
fn patch_html_for_high_sierra(html: &str) -> String {
    let mut out = patch_js_for_high_sierra(html);

    // Replace strict HTTPS-only CSP meta tag (which includes `upgrade-insecure-requests`)
    if let Some(meta_start) = out.find("<meta http-equiv=\"Content-Security-Policy\"") {
        if let Some(rel_end) = out[meta_start..].find('>') {
            let meta_end = meta_start + rel_end + 1;
            let safe_csp = "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self' http://127.0.0.1:* http://localhost:*; script-src 'self' 'unsafe-inline' blob: http://127.0.0.1:* http://localhost:*; worker-src 'self' blob:; style-src 'self' 'unsafe-inline' http://127.0.0.1:* http://localhost:* https://fonts.googleapis.com; font-src 'self' data: http://127.0.0.1:* http://localhost:* https://fonts.gstatic.com; img-src 'self' data: blob: http://127.0.0.1:* http://localhost:* https://www.chiroot.my.id https://i.ytimg.com https://i.scdn.co https://*.scdn.co https://astuagdezahmuuwjoghf.supabase.co; media-src 'self' data: blob: http://127.0.0.1:* http://localhost:* https://www.chiroot.my.id https://astuagdezahmuuwjoghf.supabase.co; connect-src 'self' http://127.0.0.1:* http://localhost:* https://astuagdezahmuuwjoghf.supabase.co wss://astuagdezahmuuwjoghf.supabase.co https://www.googleapis.com https://lrclib.net https://*.scdn.co; object-src 'none'; base-uri 'self'; frame-src 'none'\">";
            out.replace_range(meta_start..meta_end, safe_csp);
        }
    }

    // Proxy Google Fonts CSS via Rustls to avoid High Sierra TLS trust errors
    out = out.replace("https://fonts.googleapis.com", "/__fonts_css");

    // Inject polyfill & CHIROOT_CONFIG immediately after <head>
    let shim = HIGH_SIERRA_HEAD_SHIM.replace("__SUPABASE_KEY__", &supabase_publishable_key());
    if let Some(pos) = out.find("<head>") {
        out.insert_str(pos + "<head>".len(), &shim);
    } else if let Some(pos) = out.find("<HEAD>") {
        out.insert_str(pos + "<HEAD>".len(), &shim);
    } else {
        out.insert_str(0, &shim);
    }

    out
}

/// Expands a CSS `inset` value (`1`, `2`, `3`, or `4` whitespace-separated tokens)
/// into Safari 11-compatible `top; right; bottom; left;` declarations.
fn expand_inset_value(val: &str) -> String {
    let important = val.trim_end().ends_with("!important");
    let clean = if important {
        val.trim_end()
            .trim_end_matches("!important")
            .trim()
    } else {
        val.trim()
    };
    let suffix = if important { " !important" } else { "" };
    let parts: Vec<&str> = clean.split_whitespace().collect();
    let (t, r, b, l) = match parts.as_slice() {
        [a] => (*a, *a, *a, *a),
        [tb, rl] => (*tb, *rl, *tb, *rl),
        [t, rl, b] => (*t, *rl, *b, *rl),
        [t, r, b, l, ..] => (*t, *r, *b, *l),
        _ => return format!("inset:{val}"),
    };
    format!("top:{t}{suffix};right:{r}{suffix};bottom:{b}{suffix};left:{l}{suffix}")
}

/// Expands standalone CSS `inset: ...` properties (Safari < 14.1 ignores `inset:`)
/// without modifying `box-shadow: inset ...`.
fn expand_css_inset_properties(css: &str) -> String {
    let bytes = css.as_bytes();
    let mut out = String::with_capacity(css.len() + 1024);
    let mut i = 0;

    while i < bytes.len() {
        // Check if current position starts with `inset` followed by optional spaces and `:`
        if i + 5 <= bytes.len() && &bytes[i..i + 5] == b"inset" {
            // Look backwards past whitespace to verify property boundary (`{`, `;`, or start)
            let mut prev = i;
            while prev > 0 && bytes[prev - 1].is_ascii_whitespace() {
                prev -= 1;
            }
            let at_prop_start = prev == 0 || matches!(bytes[prev - 1], b'{' | b';' | b'/');

            // Look forward past optional spaces for `:`
            let mut colon = i + 5;
            while colon < bytes.len() && bytes[colon].is_ascii_whitespace() {
                colon += 1;
            }

            if at_prop_start && colon < bytes.len() && bytes[colon] == b':' {
                let val_start = colon + 1;
                let mut val_end = val_start;
                while val_end < bytes.len() && !matches!(bytes[val_end], b';' | b'}') {
                    val_end += 1;
                }
                let val = &css[val_start..val_end];
                out.push_str(&expand_inset_value(val));
                i = val_end;
                continue;
            }
        }
        // Advance one UTF-8 char
        let ch = css[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

/// Patches `css/style.css` for macOS High Sierra 10.13.6 WebKit (Safari 11–13):
/// - Fixes double-position gradient stops (which otherwise make `.record` vinyl transparent!)
/// - Provides Safari 11 fallbacks for `conic-gradient`, `clamp()`, `min()`, `max()`, `dvh`
/// - Expands all 31 `inset:` declarations into `top/right/bottom/left`
/// - Adds `-webkit-backdrop-filter:` prefix alongside `backdrop-filter:`
/// - Converts `:where(...)` / `:focus-visible` selectors that drop rules in Safari < 14
/// - Appends `html.hs-noflexgap` spacing fallbacks for Safari < 14.1
fn patch_css_for_high_sierra(css: &str) -> String {
    let mut out = css.to_string();

    // 1. Expand double-position gradient color stops (Safari < 12.1 treats them as invalid!)
    let gradient_replacements = [
        (
            "#23232b 0 34%, #17171d 35% 100%",
            "#23232b 0%, #23232b 34%, #17171d 35%, #17171d 100%",
        ),
        (
            "var(--vinyl-mid) 0 34%, var(--vinyl-dark) 35% 100%",
            "var(--vinyl-mid) 0%, var(--vinyl-mid) 34%, var(--vinyl-dark) 35%, var(--vinyl-dark) 100%",
        ),
        (
            "#d9b887 0 48%, #b68250 49% 100%",
            "#d9b887 0%, #d9b887 48%, #b68250 49%, #b68250 100%",
        ),
        (
            "rgba(255,255,255,0.035) 0 2px",
            "rgba(255,255,255,0.035) 0px, rgba(255,255,255,0.035) 2px",
        ),
        ("transparent 2px 5px", "transparent 2px, transparent 5px"),
        (
            "rgba(200,170,120,0.07) 0 120px",
            "rgba(200,170,120,0.07) 0px, rgba(200,170,120,0.07) 120px",
        ),
        (
            "rgba(190,150,100,0.06) 0 140px",
            "rgba(190,150,100,0.06) 0px, rgba(190,150,100,0.06) 140px",
        ),
        (
            "rgba(190,150,100,0.05) 0 180px",
            "rgba(190,150,100,0.05) 0px, rgba(190,150,100,0.05) 180px",
        ),
        (
            "rgba(64,42,18,0.012) 0 2px",
            "rgba(64,42,18,0.012) 0px, rgba(64,42,18,0.012) 2px",
        ),
        (
            "rgba(64,42,18,0.008) 0 1px",
            "rgba(64,42,18,0.008) 0px, rgba(64,42,18,0.008) 1px",
        ),
        ("transparent 1px 4px", "transparent 1px, transparent 4px"),
    ];
    for (from, to) in gradient_replacements {
        out = out.replace(from, to);
    }

    // 2. Replace conic-gradient (unsupported in Safari < 12.1) with clean Safari 11 fallback
    out = out.replace(
        "background: conic-gradient(from 210deg, rgba(255,255,255,0.08), transparent 30%, transparent 70%, rgba(255,255,255,0.05));",
        "background: linear-gradient(135deg, rgba(255,255,255,0.08) 0%, transparent 35%, transparent 65%, rgba(255,255,255,0.05) 100%);",
    );
    out = out.replace(
        "background:conic-gradient(red,orange,yellow,green,blue,indigo,violet,red);",
        "background:linear-gradient(135deg,red,orange,yellow,green,blue,indigo,violet);",
    );
    out = out.replace(
        "conic-gradient(from 35deg, #161618 0deg, #252529 38deg, #151517 82deg, #151517 180deg, #26262A 218deg, #151517 262deg, #161618 360deg)",
        "radial-gradient(circle at 50% 50%, #252529 0%, #161618 65%, #151517 100%)",
    );

    // 3. Expand all standalone `inset:` properties into `top/right/bottom/left`
    out = expand_css_inset_properties(&out);

    // 4. Replace modern viewport height units (`dvh`, `svh`, `lvh`) with `vh`
    out = out
        .replace("dvh", "vh")
        .replace("svh", "vh")
        .replace("lvh", "vh");

    // 5. Add Safari 11 cascade fallbacks before `clamp()`, `min()`, `max()`
    let math_fallbacks = [
        (
            "font-size: clamp(34px, 5vw, 52px);",
            "font-size: 44px; font-size: clamp(34px, 5vw, 52px);",
        ),
        (
            "font-size:clamp(24px,4.5vw,32px);",
            "font-size:28px;font-size:clamp(24px,4.5vw,32px);",
        ),
        (
            "font-size: clamp(24px, 4.2vw, 42px);",
            "font-size: 32px; font-size: clamp(24px, 4.2vw, 42px);",
        ),
        (
            "font-size:clamp(14px,2.2vw,17px);",
            "font-size:15px;font-size:clamp(14px,2.2vw,17px);",
        ),
        (
            "font-size: clamp(22px, 6vw, 32px);",
            "font-size: 26px; font-size: clamp(22px, 6vw, 32px);",
        ),
        (
            "font-size: clamp(32px, 5.5vw, 52px);",
            "font-size: 40px; font-size: clamp(32px, 5.5vw, 52px);",
        ),
        (
            "width:min(520px, 92%);",
            "width:92%; max-width:520px; width:min(520px, 92%);",
        ),
        (
            "width:min(92%,640px);",
            "width:92%; max-width:640px; width:min(92%,640px);",
        ),
        (
            "width:min(560px,100%);",
            "width:100%; max-width:560px; width:min(560px,100%);",
        ),
        (
            "min-width:min(262px, calc(100vw - 40px));",
            "min-width:262px; min-width:min(262px, calc(100vw - 40px));",
        ),
        (
            "max-height:min(88vh,640px);",
            "max-height:640px; max-height:min(88vh,640px);",
        ),
        (
            "max-height:min(44vh,320px);",
            "max-height:320px; max-height:min(44vh,320px);",
        ),
        (
            "width:min(540px,100%)!important;",
            "width:100%!important;max-width:540px!important;",
        ),
        (
            "bottom: max(12px, env(safe-area-inset-bottom, 12px));",
            "bottom: 12px; bottom: max(12px, env(safe-area-inset-bottom, 12px));",
        ),
        (
            "margin: 0 auto max(10px, env(safe-area-inset-bottom, 10px));",
            "margin: 0 auto 10px; margin: 0 auto max(10px, env(safe-area-inset-bottom, 10px));",
        ),
        (
            "width: min(214px, 53vw);",
            "width: 214px; width: min(214px, 53vw);",
        ),
        (
            "height: min(214px, 53vw);",
            "height: 214px; height: min(214px, 53vw);",
        ),
    ];
    for (from, to) in math_fallbacks {
        out = out.replace(from, to);
    }

    // 6. Add -webkit-backdrop-filter prefix for Safari 11–13
    out = out.replace(
        "backdrop-filter:",
        "-webkit-backdrop-filter: blur(2px); backdrop-filter:",
    );
    // Clean up any double-prefixed `-webkit--webkit-backdrop-filter`
    out = out.replace(
        "-webkit--webkit-backdrop-filter: blur(2px); backdrop-filter:",
        "-webkit-backdrop-filter:",
    );

    // 7. Rewrite `:where(...):focus-visible` selector (dropped in Safari < 14)
    out = out.replace(
        ":where(button, a, input, select, textarea, [role=\"button\"]):focus-visible",
        "button:focus, a:focus, input:focus, select:focus, textarea:focus, [role=\"button\"]:focus",
    );

    // 8. Append High Sierra Flexbox spacing fallback rules
    out.push_str(HIGH_SIERRA_CSS_FALLBACK);
    out
}

// =============================================================================
// Lightweight Local Compatibility Proxy (Rustls TLS + Streaming + OAuth Route)
// =============================================================================

struct ParsedHttpRequest {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut TcpStream) -> Result<ParsedHttpRequest, String> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);

    let mut request_line = String::new();
    let first_bytes = reader
        .read_line(&mut request_line)
        .map_err(|e| format!("Failed reading request line: {e}"))?;
    if first_bytes == 0 {
        return Err("Empty connection".to_string());
    }

    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "Missing HTTP method".to_string())?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| "Missing HTTP target".to_string())?
        .to_string();

    let mut headers = HashMap::new();
    let mut header_count = 0usize;
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| format!("Failed reading header: {e}"))?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        header_count += 1;
        if header_count > 128 {
            return Err("Too many HTTP headers".to_string());
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let mut body = Vec::new();
    if let Some(cl_str) = headers.get("content-length") {
        let len: usize = cl_str
            .parse()
            .map_err(|_| "Invalid Content-Length".to_string())?;
        if len > MAX_PROXY_REQUEST_BODY {
            return Err("Request body exceeds safety limit".to_string());
        }
        if len > 0 {
            body.resize(len, 0);
            reader
                .read_exact(&mut body)
                .map_err(|e| format!("Failed reading request body: {e}"))?;
        }
    } else if headers
        .get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        loop {
            let mut size_line = String::new();
            reader
                .read_line(&mut size_line)
                .map_err(|e| format!("Failed reading chunk size: {e}"))?;
            let hex_part = size_line.split(';').next().unwrap_or("").trim();
            let chunk_size = usize::from_str_radix(hex_part, 16)
                .map_err(|_| "Invalid chunk size".to_string())?;
            if chunk_size == 0 {
                let mut trailer = String::new();
                let _ = reader.read_line(&mut trailer);
                break;
            }
            if body.len().saturating_add(chunk_size) > MAX_PROXY_REQUEST_BODY {
                return Err("Chunked request body exceeds safety limit".to_string());
            }
            let start = body.len();
            body.resize(start + chunk_size, 0);
            reader
                .read_exact(&mut body[start..])
                .map_err(|e| format!("Failed reading chunk data: {e}"))?;
            let mut crlf = [0u8; 2];
            let _ = reader.read_exact(&mut crlf);
        }
    }

    Ok(ParsedHttpRequest {
        method,
        target,
        headers,
        body,
    })
}

fn write_simple_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    cache_control: &str,
    body: &[u8],
) {
    let head = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: {cache_control}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn write_oauth_html_page(stream: &mut TcpStream, status: &str, title: &str, body_msg: &str) {
    let html = format!(
        "<!doctype html><html><head><meta charset='utf-8'><title>{title}</title>\
         <style>body{{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#f6f4ee;\
         color:#1d1b18;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}}\
         .box{{background:#fff;border:1px solid #ddd6c8;border-radius:14px;padding:28px 24px;\
         max-width:420px;text-align:center;}}</style></head><body><div class='box'>\
         <h2>{title}</h2><p>{body_msg}</p></div></body></html>"
    );
    write_simple_http_response(
        stream,
        status,
        "text/html; charset=utf-8",
        "no-store",
        html.as_bytes(),
    );
}

fn status_reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        416 => "Range Not Satisfiable",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

/// Streams an upstream `ureq::Response` directly to the local client socket in 64 KB chunks
/// preserving status code (including `206 Partial Content`), `Content-Range`, `Accept-Ranges`,
/// and `Content-Type` without buffering large MP3s in RAM.
fn stream_upstream_response(
    stream: &mut TcpStream,
    resp: ureq::Response,
    is_head: bool,
) {
    let status_code = resp.status();
    let status_line = format!("HTTP/1.1 {status_code} {}\r\n", status_reason(status_code));
    let mut header_block = String::from(&status_line);

    let forward_headers = [
        "content-type",
        "content-length",
        "content-range",
        "accept-ranges",
        "etag",
        "last-modified",
        "cache-control",
        "content-disposition",
        "x-content-type-options",
    ];
    for name in forward_headers {
        if let Some(val) = resp.header(name) {
            header_block.push_str(&format!("{name}: {val}\r\n"));
        }
    }
    header_block.push_str("Access-Control-Allow-Origin: *\r\n");
    header_block.push_str("Connection: close\r\n\r\n");

    if stream.write_all(header_block.as_bytes()).is_err() {
        return;
    }
    if is_head || status_code == 204 || status_code == 304 {
        let _ = stream.flush();
        return;
    }

    let mut reader = resp.into_reader();
    let mut buf = [0u8; PROXY_STREAM_BUF_BYTES];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if stream.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = stream.flush();
}

fn proxy_supabase_request(stream: &mut TcpStream, req: &ParsedHttpRequest) {
    if req.method.eq_ignore_ascii_case("OPTIONS") {
        let cors = "HTTP/1.1 204 No Content\r\n\
            Access-Control-Allow-Origin: *\r\n\
            Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS\r\n\
            Access-Control-Allow-Headers: authorization, apikey, content-type, prefer, accept, range, x-upsert, x-client-info, cache-control\r\n\
            Access-Control-Max-Age: 86400\r\n\
            Connection: close\r\n\r\n";
        let _ = stream.write_all(cors.as_bytes());
        let _ = stream.flush();
        return;
    }

    let rest = req
        .target
        .strip_prefix("/__supabase")
        .unwrap_or("/");
    let upstream_url = format!("{}{}", supabase_url(), rest);

    let agent = http_agent();
    let mut ureq_req = agent.request(&req.method, &upstream_url);

    let pass_headers = [
        "authorization",
        "apikey",
        "content-type",
        "prefer",
        "accept",
        "range",
        "if-none-match",
        "if-modified-since",
        "x-upsert",
        "x-client-info",
        "cache-control",
    ];
    for name in pass_headers {
        if let Some(val) = req.headers.get(name) {
            ureq_req = ureq_req.set(name, val);
        }
    }

    let result = if !req.body.is_empty() {
        ureq_req.send_bytes(&req.body)
    } else {
        ureq_req.call()
    };

    let is_head = req.method.eq_ignore_ascii_case("HEAD");
    match result {
        Ok(resp) => stream_upstream_response(stream, resp, is_head),
        Err(ureq::Error::Status(_, resp)) => stream_upstream_response(stream, resp, is_head),
        Err(ureq::Error::Transport(t)) => {
            let msg = serde_json::json!({ "error": format!("Supabase proxy transport error: {t}") }).to_string();
            write_simple_http_response(
                stream,
                "502 Bad Gateway",
                "application/json; charset=utf-8",
                "no-store",
                msg.as_bytes(),
            );
        }
    }
}

fn proxy_fonts_css(stream: &mut TcpStream, req: &ParsedHttpRequest) {
    let rest = req.target.strip_prefix("/__fonts_css").unwrap_or("/");
    let upstream_url = format!("https://fonts.googleapis.com{rest}");
    match http_agent().get(&upstream_url).call() {
        Ok(resp) => {
            let css = resp.into_string().unwrap_or_default();
            let patched = css.replace("https://fonts.gstatic.com", "/__fonts_static");
            write_simple_http_response(
                stream,
                "200 OK",
                "text/css; charset=utf-8",
                "public, max-age=3600",
                patched.as_bytes(),
            );
        }
        Err(_) => {
            write_simple_http_response(
                stream,
                "200 OK",
                "text/css; charset=utf-8",
                "no-cache",
                b"/* Google Fonts unavailable offline */",
            );
        }
    }
}

fn proxy_fonts_static(stream: &mut TcpStream, req: &ParsedHttpRequest) {
    let rest = req.target.strip_prefix("/__fonts_static").unwrap_or("/");
    let upstream_url = format!("https://fonts.gstatic.com{rest}");
    match http_agent().get(&upstream_url).call() {
        Ok(resp) => stream_upstream_response(stream, resp, false),
        Err(ureq::Error::Status(_, resp)) => stream_upstream_response(stream, resp, false),
        Err(_) => {
            write_simple_http_response(
                stream,
                "404 Not Found",
                "text/plain",
                "no-store",
                b"Font not found",
            );
        }
    }
}

fn proxy_chiroot_asset(stream: &mut TcpStream, req: &ParsedHttpRequest) {
    let target_path = if req.target == "/" || req.target.is_empty() {
        "/Main.html"
    } else {
        req.target.as_str()
    };
    let upstream_url = format!("{CHIROOT_ORIGIN}{target_path}");
    let path_only = target_path.split(['?', '#']).next().unwrap_or(target_path);
    let lower_path = path_only.to_ascii_lowercase();

    let is_html_path = lower_path == "/main.html" || lower_path.ends_with(".html") || lower_path == "/";
    let is_css_path = lower_path.ends_with(".css");
    let is_js_path = lower_path.ends_with(".js");
    let needs_patch = (is_html_path || is_css_path || is_js_path) && req.method.eq_ignore_ascii_case("GET");

    let mut ureq_req = http_agent().request(&req.method, &upstream_url);
    if !needs_patch {
        for name in ["range", "if-none-match", "if-modified-since", "accept"] {
            if let Some(val) = req.headers.get(name) {
                ureq_req = ureq_req.set(name, val);
            }
        }
    }

    let is_head = req.method.eq_ignore_ascii_case("HEAD");
    match ureq_req.call() {
        Ok(resp) => {
            if needs_patch {
                let status = resp.status();
                if status == 200 {
                    let body_text = resp.into_string().unwrap_or_default();
                    let (patched, ctype, cache) = if is_html_path {
                        (
                            patch_html_for_high_sierra(&body_text),
                            "text/html; charset=utf-8",
                            "no-cache",
                        )
                    } else if is_css_path {
                        (
                            patch_css_for_high_sierra(&body_text),
                            "text/css; charset=utf-8",
                            "public, max-age=300",
                        )
                    } else {
                        (
                            patch_js_for_high_sierra(&body_text),
                            "application/javascript; charset=utf-8",
                            "public, max-age=300",
                        )
                    };
                    write_simple_http_response(
                        stream,
                        "200 OK",
                        ctype,
                        cache,
                        patched.as_bytes(),
                    );
                    return;
                }
            }
            stream_upstream_response(stream, resp, is_head);
        }
        Err(ureq::Error::Status(_, resp)) => stream_upstream_response(stream, resp, is_head),
        Err(ureq::Error::Transport(t)) => {
            let msg = format!("Unable to reach Chiroot ({upstream_url}): {t}");
            write_simple_http_response(
                stream,
                "502 Bad Gateway",
                "text/plain; charset=utf-8",
                "no-store",
                msg.as_bytes(),
            );
        }
    }
}

fn handle_proxy_connection(app: AppHandle, mut stream: TcpStream, port: u16) {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let Ok(req) = read_http_request(&mut stream) else {
        return;
    };

    if req.target.starts_with("/auth/callback") {
        let full_url = format!("http://127.0.0.1:{port}{}", req.target);
        match complete_oauth_callback(&app, &full_url) {
            Ok(_) => write_oauth_html_page(
                &mut stream,
                "200 OK",
                "Signed in to Chiroot Desktop",
                "Google authentication succeeded. You can close this tab and return to Chiroot Desktop.",
            ),
            Err(err) => write_oauth_html_page(
                &mut stream,
                "400 Bad Request",
                "Sign-in Failed",
                &err,
            ),
        }
    } else if req.target.starts_with("/__supabase") {
        proxy_supabase_request(&mut stream, &req);
    } else if req.target.starts_with("/__fonts_css") {
        proxy_fonts_css(&mut stream, &req);
    } else if req.target.starts_with("/__fonts_static") {
        proxy_fonts_static(&mut stream, &req);
    } else {
        proxy_chiroot_asset(&mut stream, &req);
    }
}

fn start_compat_proxy(app: &AppHandle) -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", PREFERRED_PROXY_PORT))
        .or_else(|_| TcpListener::bind(("127.0.0.1", 0)))
        .map_err(|e| format!("Failed starting local compatibility proxy: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed reading local proxy port: {e}"))?
        .port();

    app.state::<AppState>()
        .proxy_port
        .store(port, Ordering::SeqCst);

    let app_handle = app.clone();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            if let Ok(stream) = incoming {
                let handle = app_handle.clone();
                std::thread::spawn(move || {
                    handle_proxy_connection(handle, stream, port);
                });
            }
        }
    });

    Ok(port)
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
            let has_sync_soon = header
                .windows(2)
                .any(|w| w[0] == 0xFF && (w[1] & 0xE0) == 0xE0);
            if !is_id3 && !is_mpeg_frame && !has_sync_soon {
                return Err("File does not appear to be a valid MP3 audio file.".to_string());
            }
        }
        "json" => {
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

    let mut file = File::open(&path)
        .map_err(|e| format!("Cannot open file '{}': {e}", path.display()))?;
    let mut header = [0u8; 512];
    let n = file
        .read(&mut header)
        .map_err(|e| format!("Failed reading file header: {e}"))?;
    validate_file_header(&ext, &header[..n])?;

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
    let target_url = app.state::<AppState>().proxy_main_url();
    let Ok(target_literal) = serde_json::to_string(&target_url) else {
        return;
    };
    let reload_js = if reload_after {
        format!("window.location.replace({target_literal});")
    } else {
        String::new()
    };
    let script = format!(
        r#"(function () {{
          try {{
            var h = (window.location.hostname || '').toLowerCase();
            if (h === '127.0.0.1' || h === 'localhost' || h === 'chiroot.my.id' || h.slice(-14) === '.chiroot.my.id') {{
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

fn parse_oauth_callback_params(
    raw_url: &str,
) -> Result<(Option<String>, Option<String>, Option<String>), String> {
    let trimmed = raw_url.trim();
    // Allow users to paste either a full callback URL or a bare authorization code
    if !trimmed.contains("://") && !trimmed.contains('?') && !trimmed.is_empty() {
        return Ok((Some(trimmed.to_string()), None, None));
    }

    let parsed = Url::parse(trimmed).map_err(|e| format!("Invalid callback URL: {e}"))?;
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

    let code = code_opt
        .ok_or_else(|| "OAuth callback did not contain an authorization code.".to_string())?;
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

fn begin_google_oauth_flow(app: &AppHandle, use_deep_link: bool) -> Result<AuthStartResponse, String> {
    let verifier = random_base64url(32)?;
    let challenge = pkce_challenge_s256(&verifier);
    let expected_state = random_base64url(16)?;

    let (redirect_uri, mode) = if use_deep_link {
        (OAUTH_DEEP_LINK_REDIRECT.to_string(), "deep-link".to_string())
    } else {
        let port = app.state::<AppState>().proxy_port.load(Ordering::SeqCst);
        if port == 0 {
            return Err("Local OAuth callback server is not running.".to_string());
        }
        (
            format!("http://127.0.0.1:{port}/auth/callback"),
            "loopback".to_string(),
        )
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
            return Err(
                "macOS system_profiler returned an error querying audio hardware.".to_string(),
            );
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
// Tauri Commands (Exposed to frontend/index.html & proxied Chiroot origin)
// =============================================================================

#[tauri::command]
async fn get_app_entry_url(app: AppHandle) -> EntryUrlResult {
    let entry = app.state::<AppState>().proxy_main_url();
    let resp = http_agent().head(CHIROOT_URL).call();
    match resp {
        Ok(r) => EntryUrlResult {
            reachable: true,
            entry_url: Some(entry),
            status: Some(r.status()),
            error: None,
        },
        Err(ureq::Error::Status(code, _)) => EntryUrlResult {
            reachable: (200..500).contains(&code),
            entry_url: if (200..500).contains(&code) {
                Some(entry)
            } else {
                None
            },
            status: Some(code),
            error: if code >= 500 {
                Some(format!("Chiroot server returned HTTP {code}."))
            } else {
                None
            },
        },
        Err(ureq::Error::Transport(t)) => EntryUrlResult {
            reachable: false,
            entry_url: None,
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
async fn complete_oauth_from_url(
    app: AppHandle,
    callback_url: String,
) -> Result<SupabaseSession, String> {
    complete_oauth_callback(&app, &callback_url)
}

#[tauri::command]
async fn get_auth_session(app: AppHandle) -> Result<Option<SupabaseSession>, String> {
    let Some(session) = load_persisted_session(&app) else {
        return Ok(None);
    };
    let now = now_unix_ms();
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
    if let Some(raw) = session_json {
        if !raw.trim().is_empty() {
            if let Ok(session) = serde_json::from_str::<SupabaseSession>(&raw) {
                if !session.access_token.is_empty() && !session.user.id.is_empty() {
                    save_persisted_session(&app, &session)?;
                }
            }
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

    let import_all =
        MenuItemBuilder::with_id("import_all", "Import Files (.mp3, .json, .png, .jpg)…")
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
    let auth_paste =
        MenuItemBuilder::with_id("auth_paste_callback", "Complete Sign-In from Callback URL…")
            .build(app)?;
    let auth_logout = MenuItemBuilder::with_id("auth_logout", "Sign Out").build(app)?;

    let account_submenu = SubmenuBuilder::new(app, "Account")
        .item(&auth_browser)
        .item(&auth_deeplink)
        .item(&auth_paste)
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
                let target = app.state::<AppState>().proxy_main_url();
                if let Ok(url) = Url::parse(&target) {
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
        "auth_paste_callback" => {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.eval(
                    r#"(function () {
                      var val = window.prompt('Paste the redirect URL (containing ?code=...) from your browser:');
                      if (val && window.ChirootDesktop && window.ChirootDesktop.completeOAuthFromUrl) {
                        window.ChirootDesktop.completeOAuthFromUrl(val).catch(function (e) {
                          window.ChirootDesktop.notify('Sign-in failed: ' + (e && e.message ? e.message : e), true);
                        });
                      }
                    })();"#,
                );
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
                if url_str.contains("/Main.html") || url_str.contains("chiroot.my.id") {
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
            get_app_entry_url,
            open_external_url,
            pick_import_files,
            read_imported_file_chunk,
            release_imported_file,
            list_macos_audio_devices,
            start_google_auth,
            complete_oauth_from_url,
            get_auth_session,
            logout_auth,
            sync_web_session,
        ])
        .setup(|app| {
            let handle = app.handle();
            start_compat_proxy(handle).map_err(std::io::Error::other)?;

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
        assert!(is_allowed_webview_url("http://127.0.0.1:47821/Main.html"));
        assert!(is_allowed_webview_url("https://www.chiroot.my.id/Main.html"));
        assert!(!is_allowed_webview_url("https://accounts.google.com/o/oauth2/v2/auth"));
        assert!(!is_allowed_webview_url("https://example.com/external"));
        assert!(is_download_url("https://www.chiroot.my.id/Chiroot.dmg"));
        assert!(!is_download_url("https://www.chiroot.my.id/Main.html"));
    }

    #[test]
    fn oauth_callback_parser_extracts_code_error_and_bare_code() {
        let (code, err, state) = parse_oauth_callback_params(
            "chiroot://auth/callback?code=abc123&state=xyz789",
        )
        .unwrap();
        assert_eq!(code.as_deref(), Some("abc123"));
        assert_eq!(err, None);
        assert_eq!(state.as_deref(), Some("xyz789"));

        let (code2, err2, _) = parse_oauth_callback_params(
            "http://127.0.0.1:47821/auth/callback?error=access_denied&error_description=User+cancelled",
        )
        .unwrap();
        assert_eq!(code2, None);
        assert_eq!(err2.as_deref(), Some("User cancelled"));

        let (code3, err3, _) = parse_oauth_callback_params("bare-code-999").unwrap();
        assert_eq!(code3.as_deref(), Some("bare-code-999"));
        assert_eq!(err3, None);
    }

    #[test]
    fn high_sierra_css_patcher_expands_inset_and_double_stops_safely() {
        let sample = ".record{background:radial-gradient(circle at 50% 50%, #23232b 0 34%, #17171d 35% 100%);box-shadow:inset 0 0 26px rgba(255,255,255,0.045);}\
                      .overlay{position:fixed; inset:0; min-height:100dvh;}\
                      .bar{inset: -8px 0;}";
        let patched = patch_css_for_high_sierra(sample);
        assert!(patched.contains("#23232b 0%, #23232b 34%, #17171d 35%, #17171d 100%"));
        // box-shadow: inset MUST stay untouched!
        assert!(patched.contains("box-shadow:inset 0 0 26px"));
        // standalone inset: MUST expand to top/right/bottom/left
        assert!(patched.contains("top:0;right:0;bottom:0;left:0"));
        assert!(patched.contains("top:-8px;right:0;bottom:-8px;left:0"));
        assert!(!patched.contains("100dvh"));
    }

    #[test]
    fn high_sierra_html_patcher_removes_optional_chaining_and_upgrade_insecure() {
        let sample = "<html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; upgrade-insecure-requests\"></head><body><script>\
                      const x = w[0]?.toUpperCase();\
                      e.target.closest('.vswatch')?.classList.add('active');\
                      return parsedUrl.protocol === 'https:' && publishableKey.length >= 20;\
                      </script></body></html>";
        let patched = patch_html_for_high_sierra(sample);
        assert!(!patched.contains("?."));
        assert!(!patched.contains("upgrade-insecure-requests"));
        assert!(patched.contains("CHIROOT_CONFIG"));
        assert!(patched.contains("Blob.prototype.arrayBuffer"));
        assert!(patched.contains("parsedUrl.hostname === '127.0.0.1'"));
    }
}
