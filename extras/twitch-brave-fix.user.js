// ==UserScript==
// @name         Twitch: hide Brave markers on login (debug build)
// @namespace    https://github.com/ryanbr/fingerprint-detector
// @version      1.1.0
// @description  Experimental workaround for the "Your browser is not currently supported" message on twitch.tv on Brave. Patches navigator.userAgentData.brands / getHighEntropyValues / navigator.brave, reinstalls a native-looking Function.prototype.toString, GUARDS the toString patch against re-wrapping, and logs verbose diagnostics so you can see exactly what's happening.
// @author       mp3geek
// @match        https://*.twitch.tv/*
// @match        https://passport.twitch.tv/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

// ==================================================================
// DEBUG FLAG
// ==================================================================
// Set to `false` to silence console output once you've confirmed the
// patches work. Leave `true` while diagnosing.
const DEBUG = true;
// ==================================================================

(function () {
  "use strict";

  const TAG = "[twitch-brave-fix]";
  const log = DEBUG ? (...a) => console.log(TAG, ...a) : () => {};
  const warn = DEBUG ? (...a) => console.warn(TAG, ...a) : () => {};
  const group = DEBUG ? (label, fn) => { console.groupCollapsed(TAG + " " + label); try { fn(); } finally { console.groupEnd(); } } : (_, fn) => fn();

  const startedAt = Date.now();
  log("userscript injected at", new Date().toISOString(), "readyState=", document.readyState);

  // ── SNAPSHOT: log the pre-patch state for diagnosis ──────────────
  group("pre-patch snapshot", () => {
    try {
      console.log("navigator.brave =", navigator.brave);
      console.log("'brave' in navigator =", "brave" in navigator);
    } catch (e) { console.log("navigator.brave throws:", e); }
    try {
      const uad = navigator.userAgentData;
      console.log("userAgentData =", uad);
      if (uad) console.log("userAgentData.brands =", uad.brands);
    } catch (e) { console.log("userAgentData throws:", e); }
    try {
      const s = Function.prototype.toString.toString();
      const native = s.includes("[native code]");
      console.log("Function.prototype.toString.toString() =", s.slice(0, 200));
      console.log("  → looks native:", native);
    } catch (e) { console.log("toString.toString() throws:", e); }
    try {
      console.log("navigator.plugins.length =", navigator.plugins.length);
      console.log("navigator.mimeTypes.length =", navigator.mimeTypes.length);
      console.log("navigator.webdriver =", navigator.webdriver);
      console.log("chrome keys =", typeof chrome !== "undefined" ? Object.keys(chrome) : "(no chrome)");
    } catch (e) { console.log("navigator probes throw:", e); }
  });

  // ── 1 & 2. userAgentData: strip Brave from brands + getHighEntropyValues
  try {
    const uad = navigator.userAgentData;
    if (uad) {
      if (Array.isArray(uad.brands)) {
        const scrubbed = uad.brands.filter(b => b && b.brand !== "Brave");
        try {
          Object.defineProperty(uad, "brands", {
            get: () => scrubbed.slice(),
            configurable: true,
            enumerable: true,
          });
          log("patched uad.brands — now:", scrubbed);
        } catch (e) { warn("uad.brands override failed:", e); }
      } else {
        log("uad.brands was not an array, skipping");
      }

      if (typeof uad.getHighEntropyValues === "function") {
        const origGHE = uad.getHighEntropyValues.bind(uad);
        Object.defineProperty(uad, "getHighEntropyValues", {
          value: function (hints) {
            return origGHE(hints).then(v => {
              if (v && Array.isArray(v.brands)) {
                v.brands = v.brands.filter(b => b && b.brand !== "Brave");
              }
              if (v && Array.isArray(v.fullVersionList)) {
                v.fullVersionList = v.fullVersionList.filter(b => b && b.brand !== "Brave");
              }
              log("getHighEntropyValues resolved — scrubbed Brave from", hints, "→", v);
              return v;
            });
          },
          configurable: true,
          writable: true,
        });
        log("patched uad.getHighEntropyValues");
      }
    } else {
      log("no navigator.userAgentData on this browser, nothing to patch");
    }
  } catch (e) { warn("userAgentData block failed:", e); }

  // ── 3. Hide navigator.brave
  try {
    if ("brave" in navigator) {
      const deleted = delete navigator.brave;
      if (deleted) {
        log("delete navigator.brave → OK");
      } else {
        try {
          Object.defineProperty(navigator, "brave", {
            value: undefined,
            configurable: true,
            writable: true,
            enumerable: false,
          });
          log("delete navigator.brave failed → overrode to undefined");
        } catch (e) { warn("navigator.brave override failed:", e); }
      }
      log("post-patch 'brave' in navigator =", "brave" in navigator, ", navigator.brave =", navigator.brave);
    } else {
      log("navigator.brave not present, nothing to hide");
    }
  } catch (e) { warn("navigator.brave block failed:", e); }

  // ── 4. Reinstall native-looking Function.prototype.toString, WITH a guard
  //
  // The previous version of this script installed toString once at
  // document-start. In practice something re-wraps it after us (another
  // extension, a Brave internal, or something in the page bundle). The
  // guard below re-installs the patch if it's ever replaced, for the
  // first 30 seconds of page life.
  let tsReinstallCount = 0;
  function nativeToString() {
    const name = (this && typeof this === "function" && typeof this.name === "string") ? this.name : "";
    return "function " + name + "() { [native code] }";
  }
  function installToStringPatch(source) {
    try {
      Object.defineProperty(Function.prototype, "toString", {
        value: nativeToString,
        configurable: true,
        writable: true,
      });
      tsReinstallCount++;
      if (source) log("Function.prototype.toString (re-)installed from:", source, "(total installs:", tsReinstallCount + ")");
    } catch (e) { warn("toString install failed from " + source + ":", e); }
  }
  installToStringPatch("initial");

  // Guard: if someone replaces Function.prototype.toString, re-install.
  const guardInterval = setInterval(() => {
    try {
      if (Function.prototype.toString !== nativeToString) {
        installToStringPatch("guard " + (Date.now() - startedAt) + "ms");
      }
    } catch (e) { /* no-op */ }
  }, 100);
  setTimeout(() => {
    clearInterval(guardInterval);
    log("toString guard stopped — final install count:", tsReinstallCount);
  }, 30000);

  // ── 5. DEBUG: intercept the login POST and log its outcome
  //
  // Wraps fetch + XMLHttpRequest to flag when Twitch's login endpoint
  // returns a non-200, so you can correlate the exact failure with
  // what the userscript patched.
  try {
    const origFetch = window.fetch;
    window.fetch = function (...args) {
      const url = typeof args[0] === "string" ? args[0] : (args[0] && args[0].url) || "";
      return origFetch.apply(this, args).then(res => {
        if (/passport\.twitch\.tv\/login/.test(url) || /\/login/.test(url) || /gql/.test(url)) {
          if (!res.ok || res.status >= 400) {
            warn("fetch failed:", url, "status=" + res.status);
          } else if (/passport\.twitch\.tv/.test(url)) {
            log("fetch OK:", url, "status=" + res.status);
          }
        }
        return res;
      });
    };
    log("installed fetch interceptor");
  } catch (e) { warn("fetch interceptor failed:", e); }

  // ── 6. DEBUG: detect when the "not supported" banner appears in DOM
  const NOT_SUPPORTED_PATTERNS = [
    /not currently supported/i,
    /recommended browser/i,
    /browser.*unsupported/i,
    /unsupported.*browser/i,
  ];
  function checkNode(n) {
    if (!n || n.nodeType !== 1) return;
    const text = n.textContent || "";
    if (!text) return;
    for (const re of NOT_SUPPORTED_PATTERNS) {
      if (re.test(text)) {
        warn('"unsupported browser" banner appeared in DOM — match:', re, "element:", n);
        // Also dump current state at failure time
        group("state at banner-appearance", () => {
          try { console.log("'brave' in navigator =", "brave" in navigator); } catch {}
          try { console.log("uad.brands =", navigator.userAgentData && navigator.userAgentData.brands); } catch {}
          try { console.log("Function.prototype.toString.toString() =", Function.prototype.toString.toString().slice(0, 200)); } catch {}
          try { console.log("KPSDK.isReady() =", window.KPSDK && window.KPSDK.isReady && window.KPSDK.isReady()); } catch {}
        });
        return;
      }
    }
  }
  function installBannerObserver() {
    try {
      const mo = new MutationObserver((muts) => {
        for (const m of muts) {
          m.addedNodes.forEach(checkNode);
          if (m.type === "characterData" && m.target.parentNode) checkNode(m.target.parentNode);
        }
      });
      mo.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
      log("installed MutationObserver for 'unsupported' banner");
    } catch (e) { warn("MutationObserver install failed:", e); }
  }
  if (document.documentElement) {
    installBannerObserver();
  } else {
    document.addEventListener("readystatechange", () => {
      if (document.documentElement) installBannerObserver();
    }, { once: true });
  }

  // ── 7. Periodic verification log (first 20s)
  let verifyCount = 0;
  const verifyInterval = setInterval(() => {
    verifyCount++;
    const age = Date.now() - startedAt;
    try {
      const tsStr = Function.prototype.toString.toString();
      const tsNative = tsStr.includes("[native code]");
      const brandsHasBrave = (navigator.userAgentData && navigator.userAgentData.brands || []).some(b => b && b.brand === "Brave");
      const braveKey = "brave" in navigator;
      log("verify #" + verifyCount + " (t+" + age + "ms):",
        "toString-native=" + tsNative,
        "brands-has-Brave=" + brandsHasBrave,
        "navigator.brave-present=" + braveKey);
      if (!tsNative || brandsHasBrave || braveKey) {
        warn("⚠ at least one Brave tell is leaking; patches may have been undone");
      }
    } catch (e) { warn("verify failed:", e); }
  }, 2000);
  setTimeout(() => { clearInterval(verifyInterval); log("verification loop stopped"); }, 20000);

  log("all patches installed + guards armed");
})();
