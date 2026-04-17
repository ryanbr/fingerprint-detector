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
  // FingerprintJS libraries commonly set one or more of these globals.
  // We poll at install, at DOMContentLoaded, and after a 2s delay —
  // this catches libraries that load asynchronously after page load.
  const FP_GLOBALS = [
    "FingerprintJS", "FingerprintJSPro",
    "fpjsAgent", "fpPromise",
    "__fpjs", "fpjs",
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
  }

  scanGlobals();
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", scanGlobals, { once: true });
  }
  setTimeout(scanGlobals, 2000);
}
