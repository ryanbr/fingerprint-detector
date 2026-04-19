// ==UserScript==
// @name         Twitch: hide Brave markers on login
// @namespace    https://github.com/ryanbr/fingerprint-detector
// @version      1.0.0
// @description  Paper over the "Your browser is not currently supported" message on twitch.tv by hiding the three Brave-specific tells an ordinary integrity check catches: the Brave entry in navigator.userAgentData.brands, the navigator.brave property, and a non-native Function.prototype.toString (usually left wrapped by another extension).
// @author       mp3geek
// @match        https://*.twitch.tv/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

// --------------------------------------------------------------------
// What this script does
// --------------------------------------------------------------------
// 1. Strips "Brave" from navigator.userAgentData.brands (static getter)
// 2. Strips "Brave" from navigator.userAgentData.getHighEntropyValues
//    response when it resolves (covers the async client-hint path).
// 3. Hides navigator.brave — both the value AND the `'brave' in navigator`
//    check (via property deletion, with a best-effort fallback if the
//    property isn't configurable).
// 4. Reinstalls a native-looking Function.prototype.toString so any
//    function — including ones another extension has wrapped — reports
//    "function NAME() { [native code] }". This defeats the most common
//    browser-integrity check:
//        Function.prototype.toString.toString().includes("[native code]")
//
// What this script CANNOT guarantee
// --------------------------------------------------------------------
// - Other extensions that hook Function.prototype.toString AFTER this
//   script runs (race condition) will undo step 4. Tampermonkey on
//   Chromium usually wins document-start races, but not always.
// - Twitch may use additional Brave tells beyond the three above (the
//   plugins array length, specific chrome.* internals, font enumeration
//   results, etc.). Those aren't patched here.
// - If your actual blocker is something else (e.g. Kasada failure,
//   Shields-induced probe farming), this script won't help.
//
// Honest tradeoff: user-defined functions also return "[native code]"
// --------------------------------------------------------------------
// The toString override is a blanket spoof — ALL functions, including
// user-defined ones, report native-looking output. In theory this
// breaks code that reads its own source via Function.toString at
// runtime. In practice production bundles rarely do that. If you hit
// breakage, localise the @match to just the login page.
//
// --------------------------------------------------------------------

(function () {
  "use strict";

  // ── 1 & 2. userAgentData: strip Brave from brands + getHighEntropyValues
  try {
    const uad = navigator.userAgentData;
    if (uad) {
      // Static .brands — override as a getter that filters on read.
      if (Array.isArray(uad.brands)) {
        const scrubbed = uad.brands.filter(function (b) {
          return b && b.brand !== "Brave";
        });
        try {
          Object.defineProperty(uad, "brands", {
            get: function () { return scrubbed.slice(); },
            configurable: true,
            enumerable: true,
          });
        } catch (_) { /* some builds refuse */ }
      }

      // Async high-entropy query — wrap the method.
      if (typeof uad.getHighEntropyValues === "function") {
        const origGHE = uad.getHighEntropyValues.bind(uad);
        Object.defineProperty(uad, "getHighEntropyValues", {
          value: function (hints) {
            return origGHE(hints).then(function (v) {
              if (v && Array.isArray(v.brands)) {
                v.brands = v.brands.filter(function (b) { return b && b.brand !== "Brave"; });
              }
              if (v && Array.isArray(v.fullVersionList)) {
                v.fullVersionList = v.fullVersionList.filter(function (b) { return b && b.brand !== "Brave"; });
              }
              return v;
            });
          },
          configurable: true,
          writable: true,
        });
      }
    }
  } catch (_) { /* no-op */ }

  // ── 3. Hide navigator.brave entirely
  //
  // `delete navigator.brave` works on Brave where the prop is configurable.
  // Fall back to defineProperty with undefined if deletion isn't allowed,
  // which at least hides the value (though `'brave' in navigator` still
  // returns true — can't help that without deletion).
  try {
    if ("brave" in navigator) {
      const deleted = delete navigator.brave;
      if (!deleted) {
        try {
          Object.defineProperty(navigator, "brave", {
            value: undefined,
            configurable: true,
            writable: true,
            enumerable: false,
          });
        } catch (_) { /* no-op */ }
      }
    }
  } catch (_) { /* no-op */ }

  // ── 4. Reinstall a native-looking Function.prototype.toString
  //
  // Any extension / userscript / inline wrapper that has replaced
  // Function.prototype.toString with non-native source is undone here:
  // we set toString to a function whose own toString() (invoked on
  // itself) returns "function toString() { [native code] }", and which
  // returns the same shape for ANY function it's called on. That
  // collapses the standard integrity check
  //   Function.prototype.toString.toString().includes("[native code]")
  // back to true.
  try {
    function nativeToString() {
      const name = (this && typeof this === "function" && typeof this.name === "string") ? this.name : "";
      return "function " + name + "() { [native code] }";
    }
    Object.defineProperty(Function.prototype, "toString", {
      value: nativeToString,
      configurable: true,
      writable: true,
    });
  } catch (_) { /* no-op */ }
})();
