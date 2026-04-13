// hooks/extension.js — Extension Detection (resource probing, CSS detection, messaging)
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 29b. Extension Detection ────────────────────────────────────────────
  // Sites detect installed Chrome extensions via:
  // 1. Probing web-accessible resources (chrome-extension://<id>/...)
  // 2. Detecting injected CSS via getComputedStyle on tripwire elements
  // 3. Messaging known extension IDs via chrome.runtime.sendMessage
  //
  // Rate limiting: first probe + summary every 50. Self-unwrapping hooks
  // after probing completes (detected via idle timeout).
  {
    const extProbeCount = { total: 0, ids: new Set() };
    const EXT_LOG_EVERY = 50;
    const MAX_EXT_IDS = 5000; // cap memory for extension ID Set
    let extFirstLogged = false;
    let extProbesDone = false; // true after idle timeout → unwrap hooks

    function isExtUrl(url) {
      return typeof url === "string" &&
        (url.indexOf("chrome-extension://") === 0 || url.indexOf("moz-extension://") === 0);
    }

    function extractExtId(url) {
      const m = url.match(/:\/\/([a-z]{32})\//);
      return m ? m[1] : url.slice(0, 60);
    }

    // Self-unwrap timer: if no probes for 2s after first probe, restore hooks
    let unwrapTimer = 0;
    const UNWRAP_DELAY = 2000;
    // Hard deadline for unwrapping fetch/XHR, independent of probe
    // activity. Sites like amazon.com keep firing non-probe fetches
    // continuously, and sites that probe repeatedly could keep the idle
    // timer resetting forever — both scenarios kept our wrapper in the
    // stack and caused fetch rejections to be blamed on dist/inject.js.
    // 3s is enough to catch load-time extension probing but short enough
    // that user-interaction fetches land on unwrapped native.
    const FETCH_XHR_HARD_DEADLINE = 3000;

    // Saved originals for unwrapping
    const savedOriginals = {};

    function scheduleUnwrap() {
      if (unwrapTimer) clearTimeout(unwrapTimer);
      unwrapTimer = setTimeout(() => {
        extProbesDone = true;
        // Restore setAttribute to original
        if (savedOriginals.setAttribute) {
          Element.prototype.setAttribute = savedOriginals.setAttribute;
        }
        // Restore Image.src and Link.href setters
        if (savedOriginals.imageSrc) {
          Object.defineProperty(HTMLImageElement.prototype, "src", savedOriginals.imageSrc);
        }
        if (savedOriginals.linkHref) {
          Object.defineProperty(HTMLLinkElement.prototype, "href", savedOriginals.linkHref);
        }
        if (extProbeCount.total > 0) {
          record("ExtensionDetect", "hooks unwrapped",
            "probing complete — " + extProbeCount.total + " probes, " +
            extProbeCount.ids.size + " unique IDs. Restoring native setters");
        }
      }, UNWRAP_DELAY);
    }

    // fetch/XHR get a separate hard-deadline unwrap: fires exactly once,
    // FETCH_XHR_HARD_DEADLINE ms after install. Does NOT reset on probe
    // activity — we accept missing late fetch-based probes in exchange
    // for never being in the call stack when the page's own fetch fails.
    setTimeout(() => {
      if (savedOriginals.fetch) {
        window.fetch = savedOriginals.fetch;
        savedOriginals.fetch = null;
      }
      if (savedOriginals.xhrOpen) {
        XMLHttpRequest.prototype.open = savedOriginals.xhrOpen;
        savedOriginals.xhrOpen = null;
      }
    }, FETCH_XHR_HARD_DEADLINE);

    function recordExtProbe(method, url) {
      extProbeCount.total++;
      if (extProbeCount.ids.size < MAX_EXT_IDS) {
        extProbeCount.ids.add(extractExtId(url));
      }

      if (!extFirstLogged) {
        extFirstLogged = true;
        record("ExtensionDetect", method, url);
      }

      if (extProbeCount.total % EXT_LOG_EVERY === 0) {
        record("ExtensionDetect", "extension probe summary",
          extProbeCount.total + " probes across " + extProbeCount.ids.size + " unique extension IDs");
      }

      // Reset unwrap timer on each probe — unwrap after probing stops
      scheduleUnwrap();
    }

    // Expose full extension ID list for export
    window.addEventListener("__fpDetector_getExtIds", () => {
      if (extProbeCount.ids.size > 0) {
        window.dispatchEvent(new CustomEvent("__fpDetector_extIds", {
          detail: JSON.stringify({
            total: extProbeCount.total,
            ids: [...extProbeCount.ids],
          }),
        }));
      }
    });

    // fetch()
    const origFetch = window.fetch;
    if (typeof origFetch === "function") {
      savedOriginals.fetch = origFetch;
      window.fetch = function (input) {
        const url = (typeof input === "string") ? input : (input && input.url) || "";
        if (!extProbesDone && isExtUrl(url)) recordExtProbe("fetch(extension URL)", url);
        return origFetch.apply(this, arguments);
      };
    }

    // XMLHttpRequest
    const origXHROpen = XMLHttpRequest.prototype.open;
    savedOriginals.xhrOpen = origXHROpen;
    XMLHttpRequest.prototype.open = function (method, url) {
      if (!extProbesDone && isExtUrl(url)) recordExtProbe("XHR.open(extension URL)", url);
      return origXHROpen.apply(this, arguments);
    };

    // Image.src setter — charCodeAt fast-exit, self-unwraps after probing
    const origImageSrc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, "src");
    if (origImageSrc && origImageSrc.set) {
      savedOriginals.imageSrc = origImageSrc;
      const origSet = origImageSrc.set;
      Object.defineProperty(HTMLImageElement.prototype, "src", {
        ...origImageSrc,
        set(val) {
          if (typeof val === "string") {
            const c = val.charCodeAt(0);
            if ((c === 99 || c === 109) && isExtUrl(val)) recordExtProbe("Image.src = extension URL", val);
          }
          origSet.call(this, val);
        },
      });
    }

    // Link.href setter — self-unwraps after probing
    const origLinkHref = Object.getOwnPropertyDescriptor(HTMLLinkElement.prototype, "href");
    if (origLinkHref && origLinkHref.set) {
      savedOriginals.linkHref = origLinkHref;
      const origSet = origLinkHref.set;
      Object.defineProperty(HTMLLinkElement.prototype, "href", {
        ...origLinkHref,
        set(val) {
          if (typeof val === "string") {
            const c = val.charCodeAt(0);
            if ((c === 99 || c === 109) && isExtUrl(val)) recordExtProbe("Link.href = extension URL", val);
          }
          origSet.call(this, val);
        },
      });
    }

    // setAttribute — self-unwraps after probing
    const origSetAttribute = Element.prototype.setAttribute;
    savedOriginals.setAttribute = origSetAttribute;
    Element.prototype.setAttribute = function (name, value) {
      if (!extProbesDone && typeof value === "string" && (name === "src" || name === "href")) {
        const c = value.charCodeAt(0);
        if ((c === 99 || c === 109) && isExtUrl(value)) {
          recordExtProbe(this.tagName + ".setAttribute(extension URL)", value);
        }
      }
      return origSetAttribute.call(this, name, value);
    };

    // chrome.runtime.sendMessage
    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
      const origRSM = chrome.runtime.sendMessage;
      chrome.runtime.sendMessage = function () {
        const extId = arguments[0];
        if (typeof extId === "string" && extId.length === 32) {
          recordExtProbe("chrome.runtime.sendMessage(extension ID)", extId);
        }
        return origRSM.apply(this, arguments);
      };
    }

    // 2. getComputedStyle burst detection — short-circuits after detection
    const origGetCS = window.getComputedStyle;
    if (typeof origGetCS === "function") {
      let csProbeCount = 0;
      let csProbeStart = 0;
      const CS_BURST_WINDOW = 500;
      const CS_BURST_THRESHOLD = 20;
      let csBurstReported = false;

      window.getComputedStyle = function (el, pseudo) {
        const result = origGetCS.call(this, el, pseudo);
        if (csBurstReported) return result;

        if (el && el.parentNode && (el.parentNode === document.body || el.parentNode.parentNode === document.body)) {
          const now = Date.now();
          if (now - csProbeStart > CS_BURST_WINDOW) {
            csProbeCount = 0;
            csProbeStart = now;
          }
          csProbeCount++;
          if (csProbeCount >= CS_BURST_THRESHOLD) {
            csBurstReported = true;
            record("ExtensionDetect", "getComputedStyle burst",
              csProbeCount + " calls in " + CS_BURST_WINDOW + "ms (extension CSS detection pattern)");
          }
        }

        return result;
      };
    }

    // Kick off the unwrap timer unconditionally at install time. Pages
    // that never probe for extensions should still have their fetch /
    // XHR / setAttribute wrappers restored so we don't sit in the stack
    // forever — otherwise any unrelated fetch rejection or DOM-attribute
    // write error gets blamed on dist/inject.js (seen on nzherald.co.nz).
    // Real probing will keep resetting the timer via recordExtProbe.
    scheduleUnwrap();
  }
}
