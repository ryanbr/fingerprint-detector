// hooks/tracking-libraries.js — Unified tracking library detection.
//
// Single data-driven detector that replaces three previously separate
// modules (fingerprint-library.js, matomo.js, akamai-bot-manager.js).
//
// Each library is described as a LIBRARIES registry entry. A shared
// scan pipeline checks every registered library against all signal
// types in one pass.
//
// Benefits over the three-module approach:
// - 1 PerformanceObserver (was 3)
// - 1 MutationObserver (was 3)
// - 1 set of scheduled scans (was 3)
// - 1 `Object.keys(window)` iteration per scan (was 3)
// - 1 localStorage + sessionStorage + cookie iteration per scan (was 3)
// - Adding a new library = one entry in the registry (no new
//   observers, timers, or iterations)
//
// To add a new tracker detector: append an entry to LIBRARIES with
// the name, category, and whichever signal arrays apply. Pattern
// checkers below automatically pick it up.

export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent, fnWrapperMap }) {
  // ── Library registry ─────────────────────────────────────────────────
  const LIBRARIES = [
    {
      name: "FingerprintJS",
      category: "FingerprintJSDetect",
      // Well-known explicit global names
      globals: [
        "FingerprintJS", "FingerprintJSPro",
        "fpjsAgent", "fpPromise",
        "__fpjs", "fpjs",
        "__fpjs_p_l_b", "__fpjs_d_c", "__fpjs_d_m",  // Pro loader internals
        "FPJS_AGENT", "FPJS",
      ],
      // Any window own-key matching one of these prefixes → match
      globalPrefixes: ["__fpjs", "_fpjs_"],
      // Cookie / storage key patterns
      keyPatterns: [
        /^__fpjs/i, /^_fpjs/i,
        /^_vid$/i, /^_sid$/i, /^_fp_vid$/i, /^fpjs_/i,
      ],
      // <script src> URL patterns (also used by PerformanceObserver)
      scriptSrcPatterns: [
        // FingerprintJS Pro loader: apiKey + loaderVersion combo
        /[?&]apiKey=[^&]+[\s\S]*[?&]loaderVersion=/i,
        /[?&]loaderVersion=[^&]+[\s\S]*[?&]apiKey=/i,
        // Known public CDN hosts (only fires when not behind a
        // custom subdomain; the query-string patterns above catch
        // the custom-subdomain case)
        /\bfpjscdn\.(?:net|sh|com|io)\b/i,
        /\bfpcdn\.io\b/i,
        /\bopenfpcdn\.io\b/i,
        /\bapi\.fpjs\.(?:io|sh)\b/i,
        /\bm\.instant\.one\b/i,
        /\/fingerprintjs[^/?]*\.(?:min\.)?js\b/i,
        /\/fp(?:\.v\d+)?\.min\.js\b/i,
      ],
      // <script data-*> attributes
      domAttributes: ["data-fpjs-public-key", "data-fpjs-api-key"],
      // Classify script origin 1p vs 3p (only FingerprintJS uses
      // custom-subdomain obfuscation routinely)
      classifyOrigin: true,
    },
    {
      name: "Matomo",
      category: "MatomoDetect",
      globals: ["Matomo", "Piwik", "_paq", "_mtm", "Piwik_Overlay"],
      globalPrefixes: ["_pk_"],
      keyPatterns: [
        /^_pk_id/i, /^_pk_ses/i, /^_pk_ref/i, /^_pk_cvar/i,
        /^_pk_hsr/i, /^_pk_testcookie/i, /^_pk_/i,
        /^mtm_consent/i, /^mtm_cookie/i, /^mtm_/i,
        /^piwik_/i,
      ],
      scriptSrcPatterns: [
        /\/matomo(?:\.v\d+)?\.(?:min\.)?js\b/i,
        /\/piwik(?:\.v\d+)?\.(?:min\.)?js\b/i,
        /\/mtm\.(?:min\.)?js\b/i,
        /\/container_[a-zA-Z0-9]+\.js\b/i,   // Tag Manager containers
      ],
      domAttributes: [],
      classifyOrigin: false,
      // Matomo-specific anomaly: Date.prototype.getTimeAlias
      anomaly: {
        key: "Date.prototype.getTimeAlias",
        label: "Date.prototype.getTimeAlias",
        detail: "Matomo-specific alias property",
        check: () => {
          try {
            return typeof Date.prototype.getTimeAlias === "function";
          } catch { return false; }
        },
      },
    },
    {
      name: "Akamai Bot Manager",
      category: "AkamaiBotManagerDetect",
      globals: ["bmak", "_abck", "bm_sz", "ak_bmsc"],
      globalPrefixes: ["bmak", "_bm_"],
      keyPatterns: [
        /^_abck$/, /^bm_sz$/, /^bm_s$/, /^bm_sv$/, /^bm_mi$/,
        /^bm_so$/, /^ak_bmsc$/, /^sbsd$/, /^sbsd_o$/,
      ],
      scriptSrcPatterns: [],  // ABM URLs are randomized per customer
      domAttributes: [],
      classifyOrigin: false,
    },
    {
      name: "Cloudflare Bot Management",
      category: "CloudflareBotManagementDetect",
      globals: ["turnstile"],   // Turnstile CAPTCHA widget
      globalPrefixes: ["_cf_chl_"],  // Cloudflare challenge runtime options
      keyPatterns: [
        /^__cf_bm$/, /^cf_clearance$/, /^_cfuvid$/, /^_cf_bm$/,
      ],
      scriptSrcPatterns: [
        /\bchallenges\.cloudflare\.com\b/i,
        /\/cdn-cgi\/challenge-platform\//i,
        /\/cdn-cgi\/bm\//i,
      ],
      domAttributes: [],
      classifyOrigin: false,
    },
    {
      name: "DataDome",
      category: "DataDomeDetect",
      // Note: the globals DD_RUM and DD_LOGS are DataDog (observability
      // product), NOT DataDome — deliberately excluded to prevent false
      // positives. DataDome client-side presence is primarily via the
      // cookie + script URL; it doesn't expose obvious globals.
      globals: ["datadome"],
      globalPrefixes: [],
      keyPatterns: [
        /^datadome$/i, /^dd_cookie_test/i, /^dd_s$/i,
      ],
      scriptSrcPatterns: [
        /\bjs\.datadome\.co\b/i,
        /\bapi\.datadome\.co\b/i,
        /\bcaptcha-delivery\.com\b/i,
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "PerimeterX / HUMAN",
      category: "PerimeterXDetect",
      globals: [
        "_pxAppId", "_pxAction", "_pxSID",
        "_pxParam1", "_pxjsClientSrc",
        "_pxttld", "_pxUuid",
      ],
      globalPrefixes: ["_px"],
      // Both underscore-prefixed and non-underscore cookie families.
      // The _px* family is universal; the non-underscore ones
      // (pxjsc/pxhc/pxcts/pxsid/pxac) are set by newer builds and
      // the _pxc cookie is the main tracking cookie observed on
      // apartmenttherapy.com and similar first-party proxy sites.
      keyPatterns: [
        /^_px/i,           // catches _px, _px2, _px3, _pxc, _pxhd, _pxvid, _pxff_*, _pxttld, _pxUuid, etc.
        /^pxjsc$/i, /^pxhc$/i, /^pxcts$/i, /^pxsid$/i, /^pxac$/i,
      ],
      scriptSrcPatterns: [
        // Direct / third-party CDN deployments
        /\bclient\.perimeterx\.net\b/i,
        /\bclient\.px-cdn\.net\b/i,
        /\bclient\.px-cloud\.net\b/i,
        /\bcollector-\w+\.px-cloud\.net\b/i,
        /\bpxl\.humansecurity\.com\b/i,
        /\bclient-response\.px-client\.net\b/i,
        // First-party proxy path pattern — the <appId>/init.js
        // structure is distinctive to PerimeterX. appId is 6-12
        // alphanumeric chars. Confirmed on apartmenttherapy.com
        // (/jAYekY18/init.js) and similar customer-domain setups.
        /\/[a-zA-Z0-9]{6,12}\/init\.js\b/,
        /\/[a-zA-Z0-9]{6,12}\/main\.min\.js\b/,
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Imperva / Incapsula",
      category: "ImpervaDetect",
      globals: [],  // Imperva operates mostly at edge, limited client globals
      globalPrefixes: ["__imperva_"],
      // Only high-confidence cookie names. ___utmvc was removed —
      // couldn't confirm it's Imperva-specific, may be other trackers.
      keyPatterns: [
        /^incap_ses/i, /^visid_incap/i, /^nlbi_/i,
      ],
      scriptSrcPatterns: [
        /\bcdn\.incapsula\.com\b/i,
        /\bincapsula\.com\/.+\.js\b/i,
        /\bimperva\.com\/.+\.js\b/i,
      ],
      domAttributes: [],
      classifyOrigin: false,
    },
    {
      name: "Hotjar",
      category: "HotjarDetect",
      // Session-replay + heatmap product. Records user interactions,
      // mouse movements, and scrolls. Rebranded ContentSquare
      // subsidiary since 2023.
      // Signatures confirmed from static.hotjar.com/c/hotjar-*.js loader.
      globals: [
        "hj",                      // main queue fn (hj('event', ...))
        "hjSiteSettings",          // config object with site_id
        "hjBootstrap",             // loader fn
        "hjBootstrapCalled",       // array of booted instances
        "hjLazyModules",           // module registry (SURVEY_V2, HEATMAP_RETAKER, etc.)
      ],
      globalPrefixes: ["_hj"],     // catches _hj*, _hjSettings, _hjUserAttributesHash, etc.
      keyPatterns: [
        /^_hjSession/i,            // _hjSession_*, _hjSessionUser_*
        /^_hjIncluded/i,           // _hjIncludedInSessionSample_*
        /^_hjAbsolute/i,           // _hjAbsoluteSessionInProgress
        /^_hjFirstSeen$/i,
        /^_hjMinimizedPolls/i,
        /^_hjShown/i,              // _hjShownFeedback*
        /^_hjTLDTest$/i,
        /^hj-uut$/i,               // sessionStorage UUID key
        /^_hj/i,                   // generic fallback for any _hj* key
      ],
      scriptSrcPatterns: [
        /\bstatic\.hotjar\.com\b/i,
        /\bscript\.hotjar\.com\b/i,
        /\bmetrics\.hotjar\.io\b/i,
        /\binsights\.hotjar\.com\b/i,
        /\bvoc\.hotjar\.com\b/i,
        /\bvc\.hotjar\.io\b/i,
        /\bhotjarians\.net\b/i,           // integration env
        /\/hotjar-[0-9a-f]+\.js\b/i,       // static.hotjar.com/c/hotjar-3736802.js
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Piano / Tinypass",
      category: "PianoDetect",
      // Piano (formerly Tinypass) is a paywall / subscription platform.
      // Used by news and magazine publishers. Their script does user
      // identification and page-view tracking for paywall enforcement.
      globals: [
        "tp",                 // primary Piano SDK global
        "pn",                 // internal namespace (confirmed on cdn-au.piano.io)
        "pdl",                // Piano Data Layer
        "tinypass",           // legacy name
        "__tpVersion",        // version string
        "pnFullTPVersion",
        "pnHasPolyfilled",
        "pnInitPerformance",
      ],
      globalPrefixes: ["__tp_", "pn_", "tp__"],
      keyPatterns: [
        // Consent / tracking cookies
        /^_pc_/i,
        /^_pcid$/i, /^_pctx$/i, /^_pcus$/i, /^_pprv$/i,
        // Telemetry cookies (short prefixes are distinctive)
        /^__tbc$/i, /^__tac$/i, /^__tae$/i,
        /^__pls$/i, /^__pnahc$/i, /^__pat$/i,
        // localStorage keys
        /^__tp/i,            // __tp*
        /^tp__/i,            // tp__*
        /^pianoId$/i,
        /^_ls_ttl$/i,
      ],
      scriptSrcPatterns: [
        /\bcdn(?:-\w+)?\.piano\.io\b/i,   // cdn.piano.io, cdn-au.piano.io, cdn-eu, cdn-na
        /\btinypass\.com\b/i,              // legacy domain
        /\bexperience\.piano\.io\b/i,
        /\/tinypass(?:\.min)?\.js\b/i,    // script filename
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Kasada",
      category: "KasadaDetect",
      // KPSDK global is the primary reliable signal. x-kpsdk-* are
      // primarily HTTP request headers (not localStorage/cookies) so
      // storage-based detection is inconsistent; keeping the patterns
      // for deployments that do cache the tokens, but the global +
      // script-URL checks are the reliable path.
      globals: ["KPSDK"],
      globalPrefixes: ["KPSDK_"],
      keyPatterns: [
        /^x-kpsdk-/i, /^KPSDK-/i,
      ],
      scriptSrcPatterns: [
        /\bips\.js\.kasada\.io\b/i,
        /\bkasada\.io\b/i,
      ],
      domAttributes: [],
      classifyOrigin: false,
    },
  ];

  // ── Shared fired-key dedupe ──────────────────────────────────────────
  // Single Set shared across all libraries. Keys are namespaced by
  // library name to prevent cross-library collisions.
  const fired = new Set();
  function fireOnce(library, signalKey, label, detail) {
    const k = library.name + "|" + signalKey;
    if (fired.has(k)) return;
    fired.add(k);
    record(library.category, label, detail);
  }

  // ── Origin classification (FingerprintJS only opts in currently) ─────
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

  // ── Scan implementations ─────────────────────────────────────────────
  function scanGlobals() {
    // Snapshot window keys ONCE for all libraries to share
    let windowKeys = null;
    try { windowKeys = Object.keys(window); } catch { windowKeys = []; }

    for (let li = 0; li < LIBRARIES.length; li++) {
      const lib = LIBRARIES[li];
      // Explicit globals
      for (let i = 0; i < lib.globals.length; i++) {
        const name = lib.globals[i];
        try {
          if (name in window && window[name] !== undefined && window[name] !== null) {
            fireOnce(lib, "global:" + name, "Global variable", "window." + name);
          }
        } catch { /* throws on some globals */ }
      }
      // Prefix matches against shared window-keys snapshot
      if (lib.globalPrefixes && lib.globalPrefixes.length > 0) {
        for (let k = 0; k < windowKeys.length; k++) {
          const key = windowKeys[k];
          if (typeof key !== "string") continue;
          for (let p = 0; p < lib.globalPrefixes.length; p++) {
            if (key.indexOf(lib.globalPrefixes[p]) === 0) {
              fireOnce(lib, "global-pattern:" + key,
                "Global variable (pattern match)", "window." + key);
              break;
            }
          }
        }
      }
      // Anomaly check (e.g. Date.prototype.getTimeAlias for Matomo)
      if (lib.anomaly && lib.anomaly.check()) {
        fireOnce(lib, "anomaly:" + lib.anomaly.key,
          lib.anomaly.label, lib.anomaly.detail);
      }
    }
  }

  function keyMatchesAnyLibrary(key) {
    if (typeof key !== "string" || !key) return null;
    for (let li = 0; li < LIBRARIES.length; li++) {
      const lib = LIBRARIES[li];
      if (!lib.keyPatterns) continue;
      for (let p = 0; p < lib.keyPatterns.length; p++) {
        if (lib.keyPatterns[p].test(key)) return lib;
      }
    }
    return null;
  }

  function scanStorage(store, kind) {
    try {
      for (let i = 0; i < store.length; i++) {
        const key = store.key(i);
        const lib = keyMatchesAnyLibrary(key);
        if (lib) {
          fireOnce(lib, kind + ":" + key, kind + " key", key);
        }
      }
    } catch { /* no-op */ }
  }

  function scanCookies() {
    try {
      const cookies = document.cookie;
      if (!cookies || typeof cookies !== "string") return;
      const parts = cookies.split(";");
      for (let i = 0; i < parts.length; i++) {
        const eq = parts[i].indexOf("=");
        const name = (eq > -1 ? parts[i].slice(0, eq) : parts[i]).trim();
        const lib = keyMatchesAnyLibrary(name);
        if (lib) {
          fireOnce(lib, "cookie:" + name, "Cookie key", name);
        }
      }
    } catch { /* no-op */ }
  }

  // ── Script URL / resource matching ───────────────────────────────────
  // Checks a URL against every library's scriptSrcPatterns. Returns
  // the matching library (and optional origin classification) or null.
  function matchScriptUrl(url) {
    if (typeof url !== "string" || url.length < 4) return null;
    for (let li = 0; li < LIBRARIES.length; li++) {
      const lib = LIBRARIES[li];
      if (!lib.scriptSrcPatterns || lib.scriptSrcPatterns.length === 0) continue;
      for (let p = 0; p < lib.scriptSrcPatterns.length; p++) {
        if (lib.scriptSrcPatterns[p].test(url)) return lib;
      }
    }
    return null;
  }

  function reportLoader(url, source) {
    const lib = matchScriptUrl(url);
    if (!lib) return;
    let label, key;
    if (lib.classifyOrigin) {
      const cls = classifyOrigin(url);
      label = source + " (" + cls + ")";
      key = source + ":" + cls;
    } else {
      label = source;
      key = source;
    }
    fireOnce(lib, key, label, url.slice(0, 200));
  }

  // ── Scan a single <script> for library signals ───────────────────────
  function scanScript(script) {
    if (!script || script.nodeType !== 1 || script.tagName !== "SCRIPT") return;
    // data-* attributes
    if (typeof script.hasAttribute === "function") {
      for (let li = 0; li < LIBRARIES.length; li++) {
        const lib = LIBRARIES[li];
        if (!lib.domAttributes || lib.domAttributes.length === 0) continue;
        for (let a = 0; a < lib.domAttributes.length; a++) {
          if (script.hasAttribute(lib.domAttributes[a])) {
            fireOnce(lib, "dom-attr:" + lib.domAttributes[a],
              "DOM integration tag",
              "<script " + lib.domAttributes[a] + ">");
          }
        }
      }
    }
    // src URL
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

  // ── Combined runner ──────────────────────────────────────────────────
  function runScans() {
    scanGlobals();
    try { if (typeof localStorage !== "undefined" && localStorage) scanStorage(localStorage, "localStorage"); } catch { /* no-op */ }
    try { if (typeof sessionStorage !== "undefined" && sessionStorage) scanStorage(sessionStorage, "sessionStorage"); } catch { /* no-op */ }
    scanCookies();
    scanAllScripts();
  }

  // Shared scan points — runs all libraries in one pass.
  // Skip the install-time scan (we're at document_start before any
  // page scripts have run — nothing to find yet). PerformanceObserver
  // + MutationObserver below DO start immediately so we don't miss
  // early resource loads.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", runScans, { once: true });
  } else {
    runScans();
  }
  setTimeout(runScans, 2000);
  window.addEventListener("load", runScans, { once: true });

  // ── Single shared PerformanceObserver ────────────────────────────────
  if (typeof PerformanceObserver !== "undefined") {
    try {
      const observer = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        for (let i = 0; i < entries.length; i++) {
          const entry = entries[i];
          if (entry.entryType === "resource") {
            reportLoader(entry.name, "loader");
          }
        }
      });
      observer.observe({ entryTypes: ["resource"] });
      // Retroactive scan of already-completed resources
      try {
        const existing = performance.getEntriesByType("resource");
        for (let i = 0; i < existing.length; i++) {
          reportLoader(existing[i].name, "loader");
        }
      } catch { /* no-op */ }
    } catch { /* not supported */ }
  }

  // ── Single shared MutationObserver for <script> tag injections ───────
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
}
