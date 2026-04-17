// hooks/akamai-bot-manager.js — Akamai Bot Manager (ABM) detection.
//
// Akamai Bot Manager is Akamai's anti-bot / anti-fraud product,
// heavily deployed by banks, airlines, ticketing, and e-commerce
// (e.g. citibank.com.sg/<random>/<random>/<random>/<random>/...).
//
// Detection challenges:
// - Scripts are always served first-party through Akamai's edge
// - URL paths are RANDOMIZED per customer (and rotate periodically)
//   specifically to prevent URL-based blocklists
// - No .js extension typically, no fixed script name
//
// So we can't match filenames or paths. What we CAN rely on:
//
// 1. window.bmak — "Bot Manager Akamai" global. Universal across
//    ABM deployments. This is the highest-confidence signal.
// 2. A family of distinctive cookies Akamai sets on every
//    protected site: _abck (primary), bm_sz, bm_s, bm_sv, bm_mi,
//    bm_so, ak_bmsc (legacy), sbsd, sbsd_o (SEC Bot Score variants).
//    The _abck cookie specifically is the required anchor — no ABM
//    deployment omits it.
// 3. localStorage / sessionStorage keys under the same prefixes
//    (some deployments persist state there as well).
//
// Information we surface:
// - "Detected" flag via the popup banner
// - List of which cookies + globals + storage keys matched (in the
//   Debug Log), giving the user visibility into which ABM signals
//   fired on this specific site
// - No sensor_data extraction — the payload is encrypted/encoded
//   client-side and our inspecting it would be invasive anyway

export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  const fired = new Set();
  function fireOnce(key, label, detail) {
    if (fired.has(key)) return;
    fired.add(key);
    record("AkamaiBotManagerDetect", label, detail);
  }

  // ── Global variable detection ────────────────────────────────────────
  // Primary: window.bmak is THE Akamai Bot Manager global. Pattern
  // scan also catches _abck* variants some builds expose.
  const ABM_GLOBALS = [
    "bmak",           // primary signal
    "_abck",          // occasionally exposed as a global in addition to cookie
    "bm_sz",
    "ak_bmsc",
  ];

  function scanGlobals() {
    for (let i = 0; i < ABM_GLOBALS.length; i++) {
      const name = ABM_GLOBALS[i];
      try {
        if (name in window && window[name] !== undefined && window[name] !== null) {
          fireOnce("global:" + name, "Global variable", "window." + name);
        }
      } catch { /* no-op */ }
    }
    // Pattern scan — catches any window key starting with bm_, _abck,
    // or ak_ (the three ABM prefixes). Filter to reduce noise from
    // unrelated keys that happen to share a prefix.
    try {
      const keys = Object.keys(window);
      for (let i = 0; i < keys.length; i++) {
        const k = keys[i];
        if (typeof k !== "string") continue;
        if (k.indexOf("bmak") === 0 ||
            k === "_abck" ||
            k.indexOf("_bm_") === 0) {
          fireOnce("global-pattern:" + k, "Global variable (pattern match)", "window." + k);
        }
      }
    } catch { /* no-op */ }
  }

  // ── Cookie + storage key detection ───────────────────────────────────
  // The Akamai Bot Manager cookie family is the most reliable
  // signal — _abck is required on every deployment.
  const KEY_PATTERNS = [
    /^_abck$/,
    /^bm_sz$/,
    /^bm_s$/,
    /^bm_sv$/,
    /^bm_mi$/,
    /^bm_so$/,
    /^ak_bmsc$/,
    /^sbsd$/,
    /^sbsd_o$/,
  ];

  function matchesKey(key) {
    if (typeof key !== "string" || !key) return false;
    for (let i = 0; i < KEY_PATTERNS.length; i++) {
      if (KEY_PATTERNS[i].test(key)) return true;
    }
    return false;
  }

  function scanCookies() {
    try {
      const cookies = document.cookie;
      if (!cookies || typeof cookies !== "string") return;
      const parts = cookies.split(";");
      for (let i = 0; i < parts.length; i++) {
        const eq = parts[i].indexOf("=");
        const name = (eq > -1 ? parts[i].slice(0, eq) : parts[i]).trim();
        if (matchesKey(name)) {
          fireOnce("cookie:" + name, "Cookie key", name);
        }
      }
    } catch { /* no-op */ }
  }

  function scanLocalStorage() {
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (matchesKey(key)) {
          fireOnce("storage:" + key, "localStorage key", key);
        }
      }
    } catch { /* no-op */ }
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (matchesKey(key)) {
          fireOnce("sessionStorage:" + key, "sessionStorage key", key);
        }
      }
    } catch { /* no-op */ }
  }

  function runScans() {
    scanGlobals();
    scanCookies();
    scanLocalStorage();
  }

  // Scan now, at DOMContentLoaded, +2s, and window load. ABM often
  // runs early in page load but sometimes sets cookies only after
  // the sensor_data POST completes, so multiple check points help.
  runScans();
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", runScans, { once: true });
  }
  setTimeout(runScans, 2000);
  window.addEventListener("load", runScans, { once: true });
}
