// hooks/matomo.js — Matomo / Piwik analytics library detection.
//
// Matomo is a self-hosted analytics platform (formerly named Piwik)
// that performs extensive tracking and some fingerprinting. Detection
// uses variable-based signatures rather than filename matching, since
// many deployments serve the tracker under non-default names (e.g.
// piwik.js, matomo.js, js/container_*.js, or entirely custom paths).
//
// Signals:
// 1. Global variables: window.Matomo, window.Piwik, window._paq
//    (the _paq queue is the universal Matomo tracker call pattern —
//    present even when the library is loaded under a custom name)
// 2. Cookie keys: _pk_id, _pk_ses, _pk_ref, _pk_cvar, _pk_hsr,
//    _pk_testcookie, mtm_consent*
// 3. localStorage/sessionStorage keys: _pk_* prefix, mtm_ prefix
// 4. DOM integration: <script src> matching matomo.js / piwik.js /
//    mtm.js filename patterns (fallback for default deployments)
// 5. Anomaly: Date.prototype.getTimeAlias (Matomo sets this alias
//    specifically to bypass anti-tracking toString checks)

export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  const fired = new Set();
  function fireOnce(key, label, detail) {
    if (fired.has(key)) return;
    fired.add(key);
    record("MatomoDetect", label, detail);
  }

  // ── Global variable detection ────────────────────────────────────────
  const MATOMO_GLOBALS = [
    "Matomo", "Piwik",
    "_paq",           // the universal queue — reliable signal
    "_mtm",           // Matomo Tag Manager queue
    "Piwik_Overlay",  // admin/debug feature
  ];

  function scanGlobals() {
    for (let i = 0; i < MATOMO_GLOBALS.length; i++) {
      const name = MATOMO_GLOBALS[i];
      try {
        if (name in window && window[name] !== undefined && window[name] !== null) {
          fireOnce("global:" + name, "Global variable", "window." + name);
        }
      } catch { /* no-op */ }
    }
    // Pattern scan — catches any window property starting with _pk_
    // (Matomo's configurable prefix but default everywhere)
    try {
      const keys = Object.keys(window);
      for (let i = 0; i < keys.length; i++) {
        const k = keys[i];
        if (typeof k === "string" && k.indexOf("_pk_") === 0) {
          fireOnce("global-pattern:" + k, "Global variable (pattern match)", "window." + k);
        }
      }
    } catch { /* no-op */ }

    // Date.prototype.getTimeAlias — Matomo-specific anomaly
    try {
      if (Date.prototype && typeof Date.prototype.getTimeAlias === "function") {
        fireOnce("anomaly:getTimeAlias", "Date.prototype.getTimeAlias",
          "Matomo-specific alias property");
      }
    } catch { /* no-op */ }
  }

  // ── Storage key detection ────────────────────────────────────────────
  // Matomo's default cookie/storage prefix is "_pk_" but can be
  // customized. mtm_ is the Tag Manager prefix.
  const STORAGE_KEY_PATTERNS = [
    /^_pk_id/i,
    /^_pk_ses/i,
    /^_pk_ref/i,
    /^_pk_cvar/i,
    /^_pk_hsr/i,
    /^_pk_testcookie/i,
    /^_pk_/i,         // fallback generic prefix
    /^mtm_consent/i,
    /^mtm_cookie/i,
    /^mtm_/i,         // fallback generic prefix
    /^piwik_/i,
  ];

  function matchesStorageKey(key) {
    if (typeof key !== "string" || !key) return false;
    for (let i = 0; i < STORAGE_KEY_PATTERNS.length; i++) {
      if (STORAGE_KEY_PATTERNS[i].test(key)) return true;
    }
    return false;
  }

  function scanLocalStorage() {
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (matchesStorageKey(key)) {
          fireOnce("storage:" + key, "localStorage key", key);
        }
      }
    } catch { /* no-op */ }
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (matchesStorageKey(key)) {
          fireOnce("sessionStorage:" + key, "sessionStorage key", key);
        }
      }
    } catch { /* no-op */ }
  }

  // Cookie pattern check — read document.cookie and match. Note: we
  // intentionally don't write to cookies or modify anything.
  function scanCookies() {
    try {
      const cookies = document.cookie;
      if (!cookies || typeof cookies !== "string") return;
      const parts = cookies.split(";");
      for (let i = 0; i < parts.length; i++) {
        const eq = parts[i].indexOf("=");
        const name = (eq > -1 ? parts[i].slice(0, eq) : parts[i]).trim();
        if (matchesStorageKey(name)) {
          fireOnce("cookie:" + name, "Cookie key", name);
        }
      }
    } catch { /* no-op */ }
  }

  // ── DOM <script> detection (fallback for default filenames) ─────────
  const SCRIPT_FILENAME_PATTERNS = [
    /\/matomo(?:\.v\d+)?\.(?:min\.)?js\b/i,
    /\/piwik(?:\.v\d+)?\.(?:min\.)?js\b/i,
    /\/mtm\.(?:min\.)?js\b/i,
    /\/container_[a-zA-Z0-9]+\.js\b/i,  // Matomo Tag Manager containers
  ];

  function matchesScriptSrc(src) {
    if (typeof src !== "string" || !src) return false;
    for (let i = 0; i < SCRIPT_FILENAME_PATTERNS.length; i++) {
      if (SCRIPT_FILENAME_PATTERNS[i].test(src)) return true;
    }
    return false;
  }

  function scanScript(script) {
    if (!script || script.nodeType !== 1 || script.tagName !== "SCRIPT") return;
    const src = typeof script.getAttribute === "function"
      ? script.getAttribute("src") : null;
    if (matchesScriptSrc(src)) {
      fireOnce("dom-script:" + src, "DOM <script src>", src.slice(0, 200));
    }
  }

  function scanAllScripts() {
    try {
      const scripts = document.getElementsByTagName("script");
      for (let i = 0; i < scripts.length; i++) scanScript(scripts[i]);
    } catch { /* no-op */ }
  }

  if (typeof MutationObserver !== "undefined") {
    try {
      const domObserver = new MutationObserver((mutations) => {
        for (let i = 0; i < mutations.length; i++) {
          const added = mutations[i].addedNodes;
          for (let j = 0; j < added.length; j++) {
            const node = added[j];
            if (!node || node.nodeType !== 1) continue;
            if (node.tagName === "SCRIPT") scanScript(node);
            if (typeof node.querySelectorAll === "function") {
              const nested = node.querySelectorAll("script");
              for (let k = 0; k < nested.length; k++) scanScript(nested[k]);
            }
          }
        }
      });
      function startDomObserve() {
        const root = document.documentElement || document.body;
        if (root) domObserver.observe(root, { childList: true, subtree: true });
      }
      if (document.documentElement) {
        startDomObserve();
      } else {
        document.addEventListener("DOMContentLoaded", startDomObserve, { once: true });
      }
    } catch { /* no-op */ }
  }

  // Combined scan runner
  function runScans() {
    scanGlobals();
    scanLocalStorage();
    scanCookies();
    scanAllScripts();
  }

  runScans();
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", runScans, { once: true });
  }
  setTimeout(runScans, 2000);
  window.addEventListener("load", runScans, { once: true });
}
