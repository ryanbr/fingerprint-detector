// hooks/vendor.js — Brave detection, vendor globals, Opera, Vivaldi, Edge, CSS prefixes
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 4a. Brave Browser Detection ────────────────────────────────────────
  // Brave defines navigator.brave as a plain object (not a prototype getter),
  // with an isBrave() method. We need to:
  // 1. Intercept property access to navigator.brave
  // 2. Hook isBrave() if it exists
  // We save a reference first, before any hooking, to avoid self-triggering.
  {
    const braveObj = navigator.brave;
    // Hook isBrave() on the actual brave object if it exists
    if (braveObj && typeof braveObj.isBrave === "function") {
      const origIsBrave = braveObj.isBrave;
      braveObj.isBrave = function () {
        record("VendorDetect", "navigator.brave.isBrave", "");
        return origIsBrave.call(this);
      };
    }
    // Replace navigator.brave with a property that records access
    // Works whether it's a value prop on the instance or on the prototype
    const desc = Object.getOwnPropertyDescriptor(navigator, "brave") ||
                 Object.getOwnPropertyDescriptor(Navigator.prototype, "brave");
    if (desc) {
      if (desc.get) {
        // Getter-based (unlikely but safe)
        const origGet = desc.get;
        Object.defineProperty(navigator, "brave", {
          get() {
            record("VendorDetect", "navigator.brave", "get");
            return origGet.call(this);
          },
          configurable: true,
          enumerable: desc.enumerable,
        });
      } else if (desc.value !== undefined) {
        // Value property — replace with getter that returns the original object
        Object.defineProperty(navigator, "brave", {
          get() {
            record("VendorDetect", "navigator.brave", "get");
            return braveObj;
          },
          configurable: true,
          enumerable: desc.enumerable,
        });
      }
    }
  }

  // ── 32. Vendor Flavors (browser-specific window globals) ──────────────
  // FingerprintJS checks for browser-specific globals to distinguish engines.
  {
    const vendorGlobals = [
      // Chromium / Chrome
      "chrome",
      // Safari / WebKit
      "safari", "__crWeb", "__gCrWeb", "webkit",
      // Firefox
      "__firefox__",
      // Edge
      "__edgeTrackingPreventionStatistics", "__edgeContentSpoofingProtection",
      "MSStream", "msCredentials", "MSInputMethodContext",
      // Opera
      "opr", "opera",
      // Vivaldi
      "vivaldi",
      // Yandex
      "yandex", "__yb", "__ybro",
      // Samsung
      "samsungAr",
      // UC Browser
      "ucweb", "UCShellJava",
      // Puffin
      "puffinDevice",
    ];
    for (const name of vendorGlobals) {
      const desc = Object.getOwnPropertyDescriptor(window, name);
      if (desc && desc.get) {
        const origGet = desc.get;
        Object.defineProperty(window, name, {
          ...desc,
          get() {
            record("VendorDetect", `window.${name}`, "get");
            return origGet.call(this);
          },
        });
      } else if (desc && desc.value !== undefined) {
        // For plain value properties, detect access via proxy-like approach:
        // Just record that this global exists at hook time
      }
    }
    // Also hook 'in' operator checks via Proxy on common lookups
    // (not possible to fully intercept, but we can hook property access)
    // Record which vendor globals exist at load time for static detection
    const present = vendorGlobals.filter(g => g in window);
    if (present.length > 0) {
      record("VendorDetect", "vendor globals present", present.join(", "));
    }
  }

  // ── 32b. Opera-specific API probing ────────────────────────────────────
  // Sites check window.opr.addons, opr.sidebarAction, etc.
  if (typeof window.opr !== "undefined" && window.opr) {
    for (const prop of ["addons", "sidebarAction", "operaInstalled"]) {
      if (prop in window.opr) {
        const desc = Object.getOwnPropertyDescriptor(window.opr, prop);
        if (desc && desc.get) {
          hookGetter(window.opr, prop, "VendorDetect", `opr.${prop}`);
        }
      }
    }
  }

  // ── 32c. Vivaldi-specific API probing ─────────────────────────────────
  // Vivaldi exposes window.vivaldi.jdhooks and other APIs
  if (typeof window.vivaldi !== "undefined" && window.vivaldi) {
    for (const prop of ["jdhooks", "searchEngines", "utilities", "runtime"]) {
      if (prop in window.vivaldi) {
        const desc = Object.getOwnPropertyDescriptor(window.vivaldi, prop);
        if (desc && desc.get) {
          hookGetter(window.vivaldi, prop, "VendorDetect", `vivaldi.${prop}`);
        }
      }
    }
  }

  // ── 32d. Edge-specific API probing ────────────────────────────────────
  if (typeof window.MSStream !== "undefined") {
    record("VendorDetect", "window.MSStream", "Edge legacy API present");
  }

  // ── 32e. CSS prefix detection ─────────────────────────────────────────
  // Sites use CSS.supports() or getComputedStyle to detect vendor prefixes
  // which reveal the browser engine: -webkit- (Chrome/Opera/Edge/Vivaldi),
  // -moz- (Firefox), -ms- (Edge legacy).
  if (typeof CSS !== "undefined" && CSS.supports) {
    const origSupports = CSS.supports;
    const prefixRe = /-(webkit|moz|ms|o)-/i; // pre-compiled
    CSS.supports = function (prop, val) {
      const query = val !== undefined ? prop + " " + val : prop;
      if (prefixRe.test(query)) {
        recordHot("VendorDetect", "CSS.supports", query);
      }
      return val !== undefined ? origSupports.call(this, prop, val) : origSupports.call(this, prop);
    };
  }
}
