// hooks/fingerprint-library.js — FingerprintJS library detection.
//
// Identifies when a page is running FingerprintJS (or FingerprintJS Pro)
// via multiple independent signals, and classifies the script's origin
// as first-party (same-origin / custom subdomain) vs third-party.
//
// Signals checked:
// 1. PerformanceObserver resource entries matching the FingerprintJS
//    Pro loader query-string signature (apiKey + loaderVersion) —
//    works regardless of domain, catches custom-subdomain setups
//    that dodge DNS-based blockers (e.g. metrics.nytimes.com).
// 2. MutationObserver for <script> tags with FingerprintJS-specific
//    data-* attributes or src= patterns.
// 3. Global variable presence check on a timer (handles libraries
//    that set globals after loading).
//
// All signals use the "FingerprintJSDetect" category. Each signal
// fires once per page (via an in-module fired-keys set) so we don't
// spam the log with duplicate detections.

export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  const fired = new Set();
  function fireOnce(key, label, detail) {
    if (fired.has(key)) return;
    fired.add(key);
    record("FingerprintJSDetect", label, detail);
  }

  // ── URL pattern matching ─────────────────────────────────────────────
  // Distinct signatures that identify a FingerprintJS loader regardless
  // of the hostname it's served from.
  const LOADER_PATTERNS = [
    // FingerprintJS Pro loader: apiKey + loaderVersion in query string.
    // This combo is specific to their loader contract.
    /[?&]apiKey=[^&]+[\s\S]*[?&]loaderVersion=/i,
    /[?&]loaderVersion=[^&]+[\s\S]*[?&]apiKey=/i,
    // Known public CDN hostnames — only matches when not using a
    // custom subdomain; the query-string matches above handle that case.
    /\bfpjscdn\.(?:net|sh|com|io)\b/i,
    /\bfpcdn\.io\b/i,
    /\bopenfpcdn\.io\b/i,
    /\bapi\.fpjs\.(?:io|sh)\b/i,
    /\bm\.instant\.one\b/i,
    // Common OSS bundle filenames
    /\/fingerprintjs[^/?]*\.(?:min\.)?js\b/i,
    /\/fp(?:\.v\d+)?\.min\.js\b/i,
  ];

  function matchesLoader(url) {
    if (typeof url !== "string" || url.length < 10) return false;
    for (let i = 0; i < LOADER_PATTERNS.length; i++) {
      if (LOADER_PATTERNS[i].test(url)) return true;
    }
    return false;
  }

  // Classify the script's origin relative to the current page's host.
  // "1p (same origin)" — script host identical to page host
  // "1p (custom subdomain: x.example.com)" — different subdomain but
  //   same registrable-ish domain (bottom two labels match). Catches
  //   FingerprintJS Pro custom-subdomain integrations.
  // "3p (other.com)" — cross-site
  function classifyOrigin(url) {
    try {
      const u = new URL(url, location.href);
      const pageHost = location.hostname;
      const scriptHost = u.hostname;
      if (!scriptHost) return "unknown";
      if (scriptHost === pageHost) return "1p (same origin)";
      const pageParts = pageHost.split(".");
      const scriptParts = scriptHost.split(".");
      if (pageParts.length >= 2 && scriptParts.length >= 2) {
        const pageSuffix = pageParts.slice(-2).join(".");
        const scriptSuffix = scriptParts.slice(-2).join(".");
        if (pageSuffix === scriptSuffix) {
          return "1p (custom subdomain: " + scriptHost + ")";
        }
      }
      return "3p (" + scriptHost + ")";
    } catch {
      return "unknown";
    }
  }

  function reportLoader(url, source) {
    if (!matchesLoader(url)) return;
    const classification = classifyOrigin(url);
    const key = source + ":" + classification;
    const label = source + " (" + classification + ")";
    fireOnce(key, label, url.slice(0, 200));
  }

  // ── PerformanceObserver for resource loads ───────────────────────────
  if (typeof PerformanceObserver !== "undefined") {
    try {
      const observer = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        for (let i = 0; i < entries.length; i++) {
          const entry = entries[i];
          if (entry.entryType !== "resource") continue;
          reportLoader(entry.name, "loader");
        }
      });
      observer.observe({ entryTypes: ["resource"] });
      // Retroactive scan: observer only sees FUTURE loads, but some
      // resources may already be complete by the time our content
      // script runs.
      try {
        const existing = performance.getEntriesByType("resource");
        for (let i = 0; i < existing.length; i++) {
          reportLoader(existing[i].name, "loader");
        }
      } catch { /* no-op */ }
    } catch { /* PerformanceObserver not supported */ }
  }

  // ── DOM integration tag detection ────────────────────────────────────
  function scanScript(script) {
    if (!script || script.nodeType !== 1 || script.tagName !== "SCRIPT") return;
    if (typeof script.hasAttribute === "function") {
      if (script.hasAttribute("data-fpjs-public-key") ||
          script.hasAttribute("data-fpjs-api-key")) {
        fireOnce("dom:data-attr", "DOM integration tag",
          "<script data-fpjs-*>");
      }
    }
    const src = typeof script.getAttribute === "function"
      ? script.getAttribute("src") : null;
    if (src) reportLoader(src, "DOM <script src>");
  }

  function scanAllScripts() {
    try {
      const scripts = document.getElementsByTagName("script");
      for (let i = 0; i < scripts.length; i++) scanScript(scripts[i]);
    } catch { /* no-op */ }
  }

  if (document.readyState !== "loading") {
    scanAllScripts();
  } else {
    document.addEventListener("DOMContentLoaded", scanAllScripts, { once: true });
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
            // Scripts inside inserted subtrees (e.g. innerHTML'd divs)
            if (typeof node.querySelectorAll === "function") {
              const nested = node.querySelectorAll("script");
              for (let k = 0; k < nested.length; k++) scanScript(nested[k]);
            }
          }
        }
      });
      function startObserving() {
        const root = document.documentElement || document.body;
        if (root) domObserver.observe(root, { childList: true, subtree: true });
      }
      if (document.documentElement) {
        startObserving();
      } else {
        document.addEventListener("DOMContentLoaded", startObserving, { once: true });
      }
    } catch { /* no-op */ }
  }

  // ── Global variable detection ────────────────────────────────────────
  // Two layers: explicit name list (public integrations, common UMD
  // names) and pattern-based scan for any window property starting
  // with "__fpjs" (catches per-build obfuscated globals like
  // __fpjs_p_l_b, __fpjs_d_c, __fpjs_d_m, __fpjs_pvid, etc. — the
  // Pro loader's internals vary by build/version).
  const FP_GLOBALS = [
    "FingerprintJS", "FingerprintJSPro",
    "fpjsAgent", "fpPromise",
    "__fpjs", "fpjs",
    // Known Pro loader internal exports observed across builds
    "__fpjs_p_l_b", "__fpjs_d_c", "__fpjs_d_m",
    "FPJS_AGENT", "FPJS",
  ];

  function scanGlobals() {
    for (let i = 0; i < FP_GLOBALS.length; i++) {
      const name = FP_GLOBALS[i];
      try {
        if (name in window && window[name] !== undefined && window[name] !== null) {
          fireOnce("global:" + name, "Global variable", "window." + name);
        }
      } catch { /* some globals may throw on access */ }
    }
    // Pattern scan — catches arbitrary __fpjs* prefixes set by
    // obfuscated loader builds we haven't explicitly listed.
    try {
      const keys = Object.keys(window);
      for (let i = 0; i < keys.length; i++) {
        const k = keys[i];
        if (typeof k === "string" &&
            (k.indexOf("__fpjs") === 0 || k.indexOf("_fpjs_") === 0)) {
          fireOnce("global-pattern:" + k, "Global variable (pattern match)", "window." + k);
        }
      }
    } catch { /* no-op */ }
  }

  // ── Storage key detection ───────────────────────────────────────────
  // FingerprintJS Pro persists the visitor ID under well-known storage
  // and cookie keys. Scanning localStorage for these gives a separate
  // signal that's independent of scripts/globals (useful for cases
  // where the loader has already finished and cleaned up its globals
  // by the time we scan).
  const STORAGE_KEY_PATTERNS = [
    /^__fpjs/i,
    /^_fpjs/i,
    /^_vid$/i,
    /^_sid$/i,
    /^_fp_vid$/i,
    /^fpjs_/i,
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
    } catch { /* cross-origin / disabled / quota */ }
  }

  // Combined init: scan globals + localStorage at install, at
  // DOMContentLoaded, and +2s (catches late-loading libraries).
  function runScans() {
    scanGlobals();
    scanLocalStorage();
  }

  runScans();
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", runScans, { once: true });
  }
  setTimeout(runScans, 2000);
  // Also scan on window load in case the loader finishes only at
  // or after the load event (less common but possible with async).
  window.addEventListener("load", runScans, { once: true });
}
