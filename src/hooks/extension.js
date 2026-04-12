// hooks/extension.js — Extension Detection (resource probing, CSS detection, messaging)
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 29b. Extension Detection ────────────────────────────────────────────
  // Sites detect installed Chrome extensions via three techniques:
  // 1. Probing web-accessible resources (chrome-extension://<id>/...)
  // 2. Detecting injected CSS via getComputedStyle on tripwire elements
  // 3. Messaging known extension IDs via chrome.runtime.sendMessage
  //
  // Sites like browserleaks.com probe 1000+ extension IDs. To avoid flooding
  // the log, we count probes and only emit:
  //   - The first probe (with full URL and stack trace)
  //   - A periodic summary every 50 probes with total count + unique IDs seen
  {
    const extProbeCount = { total: 0, ids: new Set() };
    const EXT_LOG_EVERY = 50;
    let extFirstLogged = false;

    function isExtUrl(url) {
      return typeof url === "string" &&
        (url.indexOf("chrome-extension://") === 0 || url.indexOf("moz-extension://") === 0);
    }

    function extractExtId(url) {
      // chrome-extension://abcdefghijklmnopabcdefghijklmnop/...
      const m = url.match(/:\/\/([a-z]{32})\//);
      return m ? m[1] : url.slice(0, 60);
    }

    function recordExtProbe(method, url) {
      extProbeCount.total++;
      extProbeCount.ids.add(extractExtId(url));

      if (!extFirstLogged) {
        extFirstLogged = true;
        record("ExtensionDetect", method, url);
      }

      if (extProbeCount.total % EXT_LOG_EVERY === 0) {
        record("ExtensionDetect", "extension probe summary",
          extProbeCount.total + " probes across " + extProbeCount.ids.size + " unique extension IDs");
      }
    }

    // Expose full extension ID list for export — dispatched on request from bridge
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
      window.fetch = function (input) {
        const url = (typeof input === "string") ? input : (input && input.url) || "";
        if (isExtUrl(url)) recordExtProbe("fetch(extension URL)", url);
        return origFetch.apply(this, arguments);
      };
    }

    // XMLHttpRequest
    const origXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      if (isExtUrl(url)) recordExtProbe("XHR.open(extension URL)", url);
      return origXHROpen.apply(this, arguments);
    };

    // Image.src setter — charCodeAt fast-exit (99='c', 109='m')
    const origImageSrc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, "src");
    if (origImageSrc && origImageSrc.set) {
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

    // Link.href setter — charCodeAt fast-exit
    const origLinkHref = Object.getOwnPropertyDescriptor(HTMLLinkElement.prototype, "href");
    if (origLinkHref && origLinkHref.set) {
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

    // setAttribute("src"/"href") — covers script, iframe, img, link
    // Fast path: only check values starting with 'c' (chrome-extension) or 'm' (moz-extension)
    const origSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function (name, value) {
      if (typeof value === "string" && (name === "src" || name === "href")) {
        const c = value.charCodeAt(0);
        if ((c === 99 || c === 109) && isExtUrl(value)) { // 'c' or 'm'
          recordExtProbe(this.tagName + ".setAttribute(extension URL)", value);
        }
      }
      return origSetAttribute.call(this, name, value);
    };

    // chrome.runtime.sendMessage to probe extension IDs
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

    // 2. Detect getComputedStyle probing for extension-injected CSS
    // Sites create tripwire elements with known extension-targeted selectors
    // and check if styles were modified. We detect suspicious patterns:
    // rapid getComputedStyle calls on freshly created elements.
    const origGetCS = window.getComputedStyle;
    if (typeof origGetCS === "function") {
      let csProbeCount = 0;
      let csProbeStart = 0;
      const CS_BURST_WINDOW = 500;  // ms
      const CS_BURST_THRESHOLD = 20; // calls
      let csBurstReported = false;

      window.getComputedStyle = function (el, pseudo) {
        const result = origGetCS.call(this, el, pseudo);

        // Short-circuit after detection — no more overhead on subsequent calls
        if (csBurstReported) return result;

        // Detect burst pattern: many getComputedStyle calls in quick succession
        // on elements appended to body (typical extension detection pattern)
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
  }
}
