// ==UserScript==
// @name         Twitch: hide Brave markers on login (debug build)
// @namespace    https://github.com/ryanbr/fingerprint-detector
// @version      1.2.0
// @description  v1.2: patch at the prototype level (not instance) so brands / getHighEntropyValues / navigator.brave overrides actually stick through Brave's fingerprint-farming. Rename the toString spoof so .name reports 'toString' instead of 'nativeToString'. Keep verbose debug logging.
// @author       mp3geek
// @match        https://*.twitch.tv/*
// @match        https://passport.twitch.tv/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

const DEBUG = true;

(function () {
  "use strict";

  const TAG = "[twitch-brave-fix]";
  const log = DEBUG ? (...a) => console.log(TAG, ...a) : () => {};
  const warn = DEBUG ? (...a) => console.warn(TAG, ...a) : () => {};
  const group = DEBUG ? (label, fn) => { console.groupCollapsed(TAG + " " + label); try { fn(); } finally { console.groupEnd(); } } : (_, fn) => fn();

  const startedAt = Date.now();
  log("userscript injected at", new Date().toISOString(), "readyState=", document.readyState);

  // ── SNAPSHOT: pre-patch state ────────────────────────────────────
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
      console.log("Function.prototype.toString.toString() =", s.slice(0, 200));
      console.log("  → looks native:", s.includes("[native code]"));
      console.log("  → .name =", Function.prototype.toString.name);
    } catch (e) { console.log("toString.toString() throws:", e); }
    try {
      console.log("navigator.plugins.length =", navigator.plugins.length);
      console.log("navigator.mimeTypes.length =", navigator.mimeTypes.length);
      console.log("navigator.webdriver =", navigator.webdriver);
      console.log("chrome keys =", typeof chrome !== "undefined" ? Object.keys(chrome) : "(no chrome)");
    } catch (e) { console.log("navigator probes throw:", e); }
  });

  // ── 1. userAgentData.brands — patch at the PROTOTYPE level
  //
  // v1.1 patched the instance. Brave's fingerprint-farming may return
  // a fresh NavigatorUAData instance each time navigator.userAgentData
  // is accessed, so the instance-level override didn't survive. Patch
  // NavigatorUAData.prototype.brands instead so every instance is
  // covered.
  try {
    const uad = navigator.userAgentData;
    if (uad) {
      const proto = Object.getPrototypeOf(uad);
      const descBrands = proto && Object.getOwnPropertyDescriptor(proto, "brands");
      if (descBrands && typeof descBrands.get === "function") {
        const origGetter = descBrands.get;
        Object.defineProperty(proto, "brands", {
          get: function () {
            const orig = origGetter.call(this);
            if (!Array.isArray(orig)) return orig;
            return orig.filter(b => b && b.brand !== "Brave");
          },
          configurable: true,
          enumerable: descBrands.enumerable !== false,
        });
        log("patched NavigatorUAData.prototype.brands (filters Brave on read)");
      } else {
        warn("could not locate NavigatorUAData.prototype.brands getter; falling back to instance override");
        if (Array.isArray(uad.brands)) {
          const scrubbed = uad.brands.filter(b => b && b.brand !== "Brave");
          try {
            Object.defineProperty(uad, "brands", {
              get: () => scrubbed.slice(),
              configurable: true,
              enumerable: true,
            });
            log("fallback: patched instance.brands");
          } catch (e) { warn("fallback also failed:", e); }
        }
      }

      // getHighEntropyValues — patch on prototype too
      const proto2 = Object.getPrototypeOf(uad);
      if (proto2 && typeof proto2.getHighEntropyValues === "function") {
        const origGHE = proto2.getHighEntropyValues;
        Object.defineProperty(proto2, "getHighEntropyValues", {
          value: function (hints) {
            return origGHE.call(this, hints).then(v => {
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
        log("patched NavigatorUAData.prototype.getHighEntropyValues");
      }
    } else {
      log("no navigator.userAgentData on this browser");
    }
  } catch (e) { warn("userAgentData prototype patch failed:", e); }

  // ── 2. navigator.brave — prototype-level deletion
  //
  // `delete navigator.brave` failed silently on the instance (the
  // property may be non-configurable). Try deleting from the prototype
  // chain; if it's an accessor on Navigator.prototype, override that
  // accessor to return undefined.
  try {
    let target = navigator;
    let deleted = false;
    for (let depth = 0; depth < 5 && target; depth++) {
      if (Object.prototype.hasOwnProperty.call(target, "brave")) {
        const desc = Object.getOwnPropertyDescriptor(target, "brave");
        try {
          if (desc && desc.configurable) {
            delete target.brave;
            deleted = true;
            log("deleted 'brave' from", depth === 0 ? "navigator instance" : "Navigator.prototype[depth=" + depth + "]");
            break;
          }
          // Non-configurable — override with accessor returning undefined
          Object.defineProperty(target, "brave", {
            get: () => undefined,
            configurable: true,
            enumerable: false,
          });
          log("overrode 'brave' getter on depth=" + depth + " (returns undefined)");
          deleted = true;
          break;
        } catch (e) {
          warn("override/delete at depth=" + depth + " failed:", e);
        }
      }
      target = Object.getPrototypeOf(target);
    }
    if (!deleted) log("'brave' not found in navigator prototype chain (may already be hidden)");
    log("post-patch: 'brave' in navigator =", "brave" in navigator, ", navigator.brave =", navigator.brave);
  } catch (e) { warn("navigator.brave block failed:", e); }

  // ── 3. Function.prototype.toString — with correct .name = "toString"
  //
  // v1.1 set Function.prototype.toString to a function whose .name
  // was "nativeToString" — which leaks through
  // `Function.prototype.toString.name`. Here we force .name = "toString"
  // so it matches vanilla Chrome exactly.
  let tsReinstallCount = 0;
  const tsSpoof = (function () {
    // declare with no name leakage via object-literal method
    const o = {
      toString: function () {
        const name = (this && typeof this === "function" && typeof this.name === "string") ? this.name : "";
        return "function " + name + "() { [native code] }";
      },
    };
    // Belt-and-braces: explicitly lock the name to "toString"
    try { Object.defineProperty(o.toString, "name", { value: "toString", configurable: true }); } catch (_) {}
    return o.toString;
  })();
  function installToStringPatch(source) {
    try {
      Object.defineProperty(Function.prototype, "toString", {
        value: tsSpoof,
        configurable: true,
        writable: true,
      });
      tsReinstallCount++;
      if (source) log("Function.prototype.toString (re-)installed from:", source, "(total installs:", tsReinstallCount + ")");
    } catch (e) { warn("toString install failed from " + source + ":", e); }
  }
  installToStringPatch("initial");

  // Guard loop: re-install if anything overwrites us
  const guardInterval = setInterval(() => {
    try {
      if (Function.prototype.toString !== tsSpoof) {
        installToStringPatch("guard " + (Date.now() - startedAt) + "ms");
      }
    } catch (e) { /* no-op */ }
  }, 100);
  setTimeout(() => {
    clearInterval(guardInterval);
    log("toString guard stopped — final install count:", tsReinstallCount);
  }, 30000);

  // ── 4. DEBUG: network interceptor + banner observer + verify loop
  //     (unchanged from v1.1)
  try {
    const origFetch = window.fetch;
    window.fetch = function (...args) {
      const url = typeof args[0] === "string" ? args[0] : (args[0] && args[0].url) || "";
      return origFetch.apply(this, args).then(res => {
        if (/passport\.twitch\.tv\/login/.test(url) || /\/login/.test(url) || /\/gql/.test(url)) {
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
        group("state at banner-appearance", () => {
          try { console.log("'brave' in navigator =", "brave" in navigator); } catch {}
          try { console.log("navigator.brave =", navigator.brave); } catch {}
          try { console.log("uad.brands =", navigator.userAgentData && navigator.userAgentData.brands); } catch {}
          try { console.log("Function.prototype.toString.toString() =", Function.prototype.toString.toString().slice(0, 200)); } catch {}
          try { console.log("Function.prototype.toString.name =", Function.prototype.toString.name); } catch {}
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

  // Verify loop — logs the three tells every 2s for 20s
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
        "toString.name=" + Function.prototype.toString.name,
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
