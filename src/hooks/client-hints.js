// hooks/client-hints.js — Sec-CH-UA Client Hints, GPC, Accept-CH meta detection
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 4b. User-Agent Client Hints (Sec-CH-UA) ───────────────────────────
  // Maps getHighEntropyValues() hint names to their Sec-CH-UA-* header equivalents.
  const HINT_TO_HEADER = {
    architecture:    "Sec-CH-UA-Arch",
    bitness:         "Sec-CH-UA-Bitness",
    brands:          "Sec-CH-UA",
    formFactors:     "Sec-CH-UA-Form-Factors",
    fullVersionList: "Sec-CH-UA-Full-Version-List",
    mobile:          "Sec-CH-UA-Mobile",
    model:           "Sec-CH-UA-Model",
    platform:        "Sec-CH-UA-Platform",
    platformVersion: "Sec-CH-UA-Platform-Version",
    uaFullVersion:   "Sec-CH-UA-Full-Version (deprecated)",
    wow64:           "Sec-CH-UA-WoW64",
  };

  // Browser brands that reveal specific browser identity via Sec-CH-UA
  const IDENTITY_BRANDS = ["brave", "edge", "opera", "vivaldi", "yandex", "samsung", "ucbrowser"];

  function describeBrands(brands) {
    if (!Array.isArray(brands)) return "";
    const names = brands.map(b => b.brand).filter(Boolean);
    const identified = names.filter(n => IDENTITY_BRANDS.some(ib => n.toLowerCase().includes(ib)));
    if (identified.length > 0) {
      return `brands=[${names.join(", ")}] exposes: ${identified.join(", ")}`;
    }
    return `brands=[${names.join(", ")}]`;
  }

  if (typeof NavigatorUAData !== "undefined") {
    // brands getter — inspect return value for browser identity leaks
    {
      const brandsDesc = Object.getOwnPropertyDescriptor(NavigatorUAData.prototype, "brands");
      if (brandsDesc && brandsDesc.get) {
        const origGet = brandsDesc.get;
        Object.defineProperty(NavigatorUAData.prototype, "brands", {
          ...brandsDesc,
          get() {
            const val = origGet.call(this);
            record("ClientHints", "Sec-CH-UA (userAgentData.brands)", describeBrands(val));
            return val;
          },
        });
      }
    }

    hookGetter(NavigatorUAData.prototype, "mobile", "ClientHints", "Sec-CH-UA-Mobile (userAgentData.mobile)");
    hookGetter(NavigatorUAData.prototype, "platform", "ClientHints", "Sec-CH-UA-Platform (userAgentData.platform)");

    // getHighEntropyValues — log hints requested AND inspect returned brands
    const origGetHEV = NavigatorUAData.prototype.getHighEntropyValues;
    if (typeof origGetHEV === "function") {
      NavigatorUAData.prototype.getHighEntropyValues = function (hints) {
        const hintList = Array.isArray(hints) ? hints : [];
        const headers = hintList.map(h => HINT_TO_HEADER[h] || h).join(", ");
        record("ClientHints", "getHighEntropyValues", `[${hintList.join(", ")}] → ${headers}`);

        const result = origGetHEV.call(this, hints);
        // Inspect the resolved value for brand identity leaks
        if (result && typeof result.then === "function") {
          result.then(data => {
            // Check brands and fullVersionList for identity-revealing brands
            for (const key of ["brands", "fullVersionList"]) {
              if (data[key]) {
                const desc = describeBrands(data[key]);
                if (desc.includes("exposes:")) {
                  record("ClientHints", `getHighEntropyValues → ${key}`, desc);
                }
              }
            }
          }).catch(() => {});
        }
        return result;
      };
    }

    hookMethod(NavigatorUAData.prototype, "toJSON", "ClientHints", "userAgentData.toJSON");
  }
  hookGetter(Navigator.prototype, "userAgentData", "ClientHints", "navigator.userAgentData");

  // ── 4c. Global Privacy Control (GPC) ──────────────────────────────────
  hookGetter(Navigator.prototype, "globalPrivacyControl", "GPC", "navigator.globalPrivacyControl");

  // ── 4d. Accept-CH meta tag detection ──────────────────────────────────
  // Sites can request Client Hints via <meta http-equiv="Accept-CH" content="...">.
  // This tells the browser to send Sec-CH-* headers on subsequent requests.
  {
    // Known Client Hint header names for classification
    const CLIENT_HINT_HEADERS = new Set([
      "sec-ch-ua", "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-full-version",
      "sec-ch-ua-full-version-list", "sec-ch-ua-mobile", "sec-ch-ua-model",
      "sec-ch-ua-platform", "sec-ch-ua-platform-version", "sec-ch-ua-wow64",
      "sec-ch-ua-form-factors",
      "sec-ch-prefers-color-scheme", "sec-ch-prefers-reduced-motion",
      "sec-ch-prefers-reduced-transparency",
      "device-memory", "dpr", "viewport-width", "viewport-height", "width",
      "downlink", "ect", "rtt", "save-data",
    ]);

    function scanAcceptCH() {
      const metas = document.querySelectorAll('meta[http-equiv="Accept-CH" i]');
      for (const meta of metas) {
        const content = meta.getAttribute("content");
        if (!content) continue;
        const hints = content.split(",").map(h => h.trim()).filter(Boolean);
        const recognized = hints.filter(h => CLIENT_HINT_HEADERS.has(h.toLowerCase()));
        if (recognized.length > 0) {
          record("ClientHints", "Accept-CH meta", recognized.join(", "));
        }
      }
    }

    // Scan after DOM is ready
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", scanAcceptCH);
    } else {
      scanAcceptCH();
    }

    // Watch for dynamically injected Accept-CH meta tags via MutationObserver
    // instead of hooking appendChild (which fires on EVERY DOM append).
    if (typeof MutationObserver !== "undefined") {
      const observer = new MutationObserver((mutations) => {
        for (const mut of mutations) {
          for (const node of mut.addedNodes) {
            if (node.nodeName === "META" &&
                node.getAttribute("http-equiv")?.toLowerCase() === "accept-ch") {
              const content = node.getAttribute("content");
              if (content) {
                const hints = content.split(",").map(h => h.trim()).filter(Boolean);
                const recognized = hints.filter(h => CLIENT_HINT_HEADERS.has(h.toLowerCase()));
                if (recognized.length > 0) {
                  record("ClientHints", "Accept-CH meta (dynamic)", recognized.join(", "));
                }
              }
            }
          }
        }
      });
      // Start observing once <head> or <body> exists
      const startObserving = () => {
        const target = document.head || document.documentElement;
        if (target) {
          observer.observe(target, { childList: true, subtree: true });
        }
      };
      if (document.head) startObserving();
      else document.addEventListener("DOMContentLoaded", startObserving, { once: true });
    }
  }
}
