// Fingerprint Detector — injected into page MAIN world at document_start
// Hooks fingerprinting-related APIs and reports access to the extension.

(function () {
  "use strict";

  const LOG_KEY = "__fpDetector";

  // ── Batched event dispatch ────────────────────────────────────────────
  // Events are queued and flushed every 250ms. Cap batch size to prevent
  // huge JSON payloads from blocking the main thread.
  let eventBatch = [];
  let flushTimer = 0;
  const FLUSH_INTERVAL = 250;
  const MAX_BATCH_SIZE = 50;

  function flushBatch() {
    flushTimer = 0;
    if (eventBatch.length === 0) return;
    const batch = eventBatch;
    eventBatch = [];
    window.dispatchEvent(
      new CustomEvent(LOG_KEY, { detail: JSON.stringify(batch) })
    );
  }

  function queueEvent(entry) {
    eventBatch.push(entry);
    if (eventBatch.length >= MAX_BATCH_SIZE) {
      clearTimeout(flushTimer);
      flushTimer = 0;
      flushBatch();
    } else if (!flushTimer) {
      flushTimer = setTimeout(flushBatch, FLUSH_INTERVAL);
    }
  }

  // ── Mute state (synced from extension storage via bridge) ─────────────
  const mutedMethodsSet = new Set();
  const mutedCategoriesSet = new Set();

  window.addEventListener("__fpDetector_mutes", (e) => {
    try {
      const { mutedMethods, mutedCategories } = JSON.parse(e.detail);
      mutedMethodsSet.clear();
      mutedCategoriesSet.clear();
      for (const m of (mutedMethods || [])) mutedMethodsSet.add(m);
      for (const c of (mutedCategories || [])) mutedCategoriesSet.add(c);
    } catch (_) {}
  });

  // ── Rate limiting per method ──────────────────────────────────────────
  // Uses a flat array indexed by numeric ID for O(1) counter lookups,
  // avoiding string concatenation and Map overhead on hot paths.
  const methodIdMap = {};  // "category|method" -> numeric ID
  const methodCountArr = []; // indexed by ID
  let nextMethodId = 0;
  const METHOD_LOG_FIRST = 3;
  const METHOD_LOG_EVERY = 100;

  // ── V8 optimization #3: Error.captureStackTrace ───────────────────────
  // Skips creating the full Error object — just captures the stack string.
  // V8-specific but this is a Chrome extension, so always available.
  const hasCapture = typeof Error.captureStackTrace === "function";

  function captureStack() {
    if (hasCapture) {
      const obj = {};
      Error.captureStackTrace(obj, captureStack);
      return obj.stack;
    }
    return new Error().stack;
  }

  // Extract the first non-inject.js caller URL from a stack trace.
  // Uses indexOf instead of regex for the common case (faster in V8).
  function extractSource(stack) {
    if (!stack) return "";
    const lines = stack.split("\n");
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (line.length < 10) continue;
      // Fast indexOf scan instead of regex
      let idx = line.indexOf("https://");
      if (idx === -1) idx = line.indexOf("http://");
      if (idx === -1) continue;
      // Extract URL: runs until whitespace (32) or closing paren (41)
      let end = idx;
      while (end < line.length && line.charCodeAt(end) !== 32 && line.charCodeAt(end) !== 41) end++;
      const url = line.substring(idx, end);
      // Skip our own frames
      if (url.indexOf("inject.js") !== -1) continue;
      if (url.charCodeAt(0) === 99 && url.indexOf("chrome-extension://") === 0) continue;
      return url;
    }
    return "";
  }

  // Main record function — optimized hot path
  function record(category, method, detail) {
    // Fast mute check — Set.has is O(1)
    if (mutedCategoriesSet.size > 0 && mutedCategoriesSet.has(category)) return;
    if (mutedMethodsSet.size > 0 && mutedMethodsSet.has(method)) return;

    // Rate limiting with numeric ID lookup
    const key = category + "|" + method;
    let id = methodIdMap[key];
    if (id === undefined) {
      id = nextMethodId++;
      methodIdMap[key] = id;
      methodCountArr[id] = 0;
    }
    const count = ++methodCountArr[id];

    // Skip if rate-limited — this is the fast-exit path for 99%+ of calls
    if (count > METHOD_LOG_FIRST && count % METHOD_LOG_EVERY !== 0) return;

    // Slow path: capture stack and queue event
    const stack = captureStack();
    const source = extractSource(stack);
    const countLabel = count > METHOD_LOG_FIRST ? " (call #" + count + ")" : "";
    queueEvent({
      category, method,
      detail: detail + countLabel,
      source, ts: Date.now(), stack,
    });
  }

  // ── Lightweight hook for extremely high-frequency APIs ────────────────
  const hotMethodFirstSeen = {};

  function recordHot(category, method, detail) {
    if (mutedCategoriesSet.size > 0 && mutedCategoriesSet.has(category)) return;
    if (mutedMethodsSet.size > 0 && mutedMethodsSet.has(method)) return;

    const key = category + "|" + method;
    if (hotMethodFirstSeen[key]) return;
    hotMethodFirstSeen[key] = true;

    const stack = captureStack();
    const source = extractSource(stack);
    queueEvent({
      category, method, detail, source, ts: Date.now(), stack,
    });
  }

  // ── V8 optimization #1: Inline mute check into hook wrappers ─────────
  // Avoids the function call to record() + string concat for the rate-limit
  // key when the method is muted. The wrapper exits immediately.

  function hookGetter(obj, prop, category, method) {
    const desc = Object.getOwnPropertyDescriptor(obj, prop);
    if (!desc || !desc.get) return;
    const origGet = desc.get;
    Object.defineProperty(obj, prop, {
      ...desc,
      get() {
        if (!(mutedCategoriesSet.size > 0 && mutedCategoriesSet.has(category)) &&
            !(mutedMethodsSet.size > 0 && mutedMethodsSet.has(method))) {
          record(category, method, prop);
        }
        return origGet.call(this);
      },
    });
  }

  function hookMethod(obj, prop, category, method) {
    const orig = obj[prop];
    if (typeof orig !== "function") return;
    obj[prop] = function () {
      if (!(mutedCategoriesSet.size > 0 && mutedCategoriesSet.has(category)) &&
          !(mutedMethodsSet.size > 0 && mutedMethodsSet.has(method))) {
        record(category, method, prop);
      }
      return orig.apply(this, arguments);
    };
  }

  // hookMethodHot: fully inlined — mute check + hot check + capture in one
  function hookMethodHot(obj, prop, category, method) {
    const orig = obj[prop];
    if (typeof orig !== "function") return;
    const hotKey = category + "|" + method;
    obj[prop] = function () {
      if (!hotMethodFirstSeen[hotKey] &&
          !(mutedCategoriesSet.size > 0 && mutedCategoriesSet.has(category)) &&
          !(mutedMethodsSet.size > 0 && mutedMethodsSet.has(method))) {
        hotMethodFirstSeen[hotKey] = true;
        const stack = captureStack();
        const source = extractSource(stack);
        queueEvent({ category, method, detail: prop, source, ts: Date.now(), stack });
      }
      return orig.apply(this, arguments);
    };
  }

  // ── 1. Canvas Fingerprinting ──────────────────────────────────────────
  hookMethod(CanvasRenderingContext2D.prototype, "toDataURL", "Canvas", "toDataURL");
  hookMethod(CanvasRenderingContext2D.prototype, "toBlob", "Canvas", "toBlob");
  hookMethod(CanvasRenderingContext2D.prototype, "getImageData", "Canvas", "getImageData");
  hookMethodHot(CanvasRenderingContext2D.prototype, "measureText", "Canvas", "measureText");
  hookMethod(HTMLCanvasElement.prototype, "toDataURL", "Canvas", "HTMLCanvasElement.toDataURL");
  hookMethod(HTMLCanvasElement.prototype, "toBlob", "Canvas", "HTMLCanvasElement.toBlob");

  // Hook getContext to detect canvas context creation
  {
    const origGetContext = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function (type) {
      if (typeof type === "string") {
        if (type === "2d") {
          recordHot("Canvas", "getContext('2d')", "2d");
        } else if (type === "webgl" || type === "webgl2" || type === "experimental-webgl") {
          recordHot("WebGL", "getContext('" + type + "')", type);
        }
      }
      return origGetContext.apply(this, arguments);
    };
  }

  // OffscreenCanvas — can bypass main-thread canvas hooks
  if (typeof OffscreenCanvas !== "undefined") {
    const origOSC = OffscreenCanvas;
    window.OffscreenCanvas = function (w, h) {
      recordHot("Canvas", "new OffscreenCanvas", "");
      return new origOSC(w, h);
    };
    window.OffscreenCanvas.prototype = origOSC.prototype;
    if (OffscreenCanvas.prototype.getContext) {
      hookMethod(OffscreenCanvas.prototype, "getContext", "Canvas", "OffscreenCanvas.getContext");
    }
    if (OffscreenCanvas.prototype.convertToBlob) {
      hookMethod(OffscreenCanvas.prototype, "convertToBlob", "Canvas", "OffscreenCanvas.convertToBlob");
    }
    if (OffscreenCanvas.prototype.transferToImageBitmap) {
      hookMethod(OffscreenCanvas.prototype, "transferToImageBitmap", "Canvas", "OffscreenCanvas.transferToImageBitmap");
    }
  }

  // ── 2. WebGL Fingerprinting ───────────────────────────────────────────
  // WebGL exposes GPU hardware details, driver info, supported extensions,
  // precision formats, buffer limits, and rendering output — all high entropy.
  function hookWebGL(proto, label) {
    // Core parameter/extension queries
    hookMethod(proto, "getParameter", "WebGL", label + ".getParameter");
    hookMethod(proto, "getSupportedExtensions", "WebGL", label + ".getSupportedExtensions");
    hookMethod(proto, "getExtension", "WebGL", label + ".getExtension");
    hookMethod(proto, "getShaderPrecisionFormat", "WebGL", label + ".getShaderPrecisionFormat");

    // Pixel readback — used for WebGL canvas fingerprint (GPU-rendered image)
    hookMethod(proto, "readPixels", "WebGL", label + ".readPixels");

    // Shader compilation pipeline — shader error messages vary by driver
    hookMethodHot(proto, "createShader", "WebGL", label + ".createShader");
    hookMethodHot(proto, "shaderSource", "WebGL", label + ".shaderSource");
    hookMethodHot(proto, "compileShader", "WebGL", label + ".compileShader");
    hookMethodHot(proto, "getShaderInfoLog", "WebGL", label + ".getShaderInfoLog");
    hookMethodHot(proto, "createProgram", "WebGL", label + ".createProgram");
    hookMethodHot(proto, "linkProgram", "WebGL", label + ".linkProgram");
    hookMethodHot(proto, "getProgramInfoLog", "WebGL", label + ".getProgramInfoLog");

    // Draw calls — combined with readPixels, produces a GPU-specific image
    hookMethodHot(proto, "drawArrays", "WebGL", label + ".drawArrays");
    hookMethodHot(proto, "drawElements", "WebGL", label + ".drawElements");

    // Buffer/renderbuffer queries — limits vary by GPU
    hookMethodHot(proto, "getBufferParameter", "WebGL", label + ".getBufferParameter");
    hookMethodHot(proto, "getRenderbufferParameter", "WebGL", label + ".getRenderbufferParameter");
    hookMethodHot(proto, "getFramebufferAttachmentParameter", "WebGL", label + ".getFramebufferAttachmentParameter");
  }

  if (typeof WebGLRenderingContext !== "undefined") {
    hookWebGL(WebGLRenderingContext.prototype, "WebGL");
  }
  if (typeof WebGL2RenderingContext !== "undefined") {
    hookWebGL(WebGL2RenderingContext.prototype, "WebGL2");

    // WebGL2-specific methods
    const gl2 = WebGL2RenderingContext.prototype;
    hookMethodHot(gl2, "getInternalformatParameter", "WebGL", "WebGL2.getInternalformatParameter");
    hookMethodHot(gl2, "getIndexedParameter", "WebGL", "WebGL2.getIndexedParameter");
    hookMethodHot(gl2, "drawArraysInstanced", "WebGL", "WebGL2.drawArraysInstanced");
    hookMethodHot(gl2, "drawElementsInstanced", "WebGL", "WebGL2.drawElementsInstanced");
    hookMethodHot(gl2, "drawRangeElements", "WebGL", "WebGL2.drawRangeElements");
  }

  // Hook WEBGL_debug_renderer_info reads — the highest-value WebGL fingerprint.
  // getParameter(UNMASKED_VENDOR_WEBGL) and getParameter(UNMASKED_RENDERER_WEBGL)
  // reveal the exact GPU model. We wrap getExtension to intercept the debug info
  // extension object and hook its parameter reads.
  {
    const hookDebugRenderer = (proto, label) => {
      const origGetExt = proto.getExtension;
      if (typeof origGetExt !== "function") return;
      proto.getExtension = function (name) {
        const ext = origGetExt.call(this, name);
        if (name === "WEBGL_debug_renderer_info" && ext) {
          record("WebGL", label + ".WEBGL_debug_renderer_info", "extension accessed — exposes GPU vendor/renderer");
        }
        return ext;
      };
    };
    if (typeof WebGLRenderingContext !== "undefined") {
      hookDebugRenderer(WebGLRenderingContext.prototype, "WebGL");
    }
    if (typeof WebGL2RenderingContext !== "undefined") {
      hookDebugRenderer(WebGL2RenderingContext.prototype, "WebGL2");
    }
  }

  // ── 3. AudioContext Fingerprinting ────────────────────────────────────
  if (typeof AudioContext !== "undefined" || typeof webkitAudioContext !== "undefined") {
    const AudioCtx = typeof AudioContext !== "undefined" ? AudioContext : webkitAudioContext;
    hookMethod(AudioCtx.prototype, "createOscillator", "Audio", "createOscillator");
    hookMethod(AudioCtx.prototype, "createDynamicsCompressor", "Audio", "createDynamicsCompressor");
    hookMethod(AudioCtx.prototype, "createAnalyser", "Audio", "createAnalyser");
    if (typeof OfflineAudioContext !== "undefined") {
      hookMethod(OfflineAudioContext.prototype, "startRendering", "Audio", "OfflineAudioContext.startRendering");
    }
  }

  // ── 4. Navigator / UA Fingerprinting ──────────────────────────────────
  const navProps = [
    "userAgent", "platform", "language", "languages", "hardwareConcurrency",
    "deviceMemory", "maxTouchPoints", "vendor", "appVersion", "oscpu",
    "cpuClass", "productSub", "vendorSub",
  ];
  for (const prop of navProps) {
    hookGetter(Navigator.prototype, prop, "Navigator", `navigator.${prop}`);
  }
  hookMethod(Navigator.prototype, "getBattery", "Navigator", "navigator.getBattery");
  if (Navigator.prototype.getGamepads) {
    hookMethod(Navigator.prototype, "getGamepads", "Navigator", "navigator.getGamepads");
  }

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

  // ── 5. Screen Properties ──────────────────────────────────────────────
  const screenProps = ["width", "height", "colorDepth", "pixelDepth", "availWidth", "availHeight"];
  for (const prop of screenProps) {
    hookGetter(Screen.prototype, prop, "Screen", `screen.${prop}`);
  }

  // ── 6. Font Enumeration ───────────────────────────────────────────────
  // offsetWidth/offsetHeight are called millions of times on every page.
  // We use an ultra-lightweight inline check: only SPAN elements with
  // fontFamily set are font probes. After first detection, we only log
  // periodically. The tagName check uses charCodeAt for speed.
  if (typeof document !== "undefined") {
    const origOffsetWidth = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "offsetWidth");
    const origOffsetHeight = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "offsetHeight");
    let fontProbeCount = 0;
    let fontProbeLogged = false; // true after first record

    if (origOffsetWidth && origOffsetWidth.get) {
      const owGet = origOffsetWidth.get;
      Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
        configurable: true, enumerable: true,
        get() {
          const val = owGet.call(this);
          // Fast exit: 83 = 'S' for SPAN — skip 99.9% of elements
          if (this.tagName.charCodeAt(0) === 83 && this.tagName === "SPAN" && this.style.fontFamily) {
            fontProbeCount++;
            if (!fontProbeLogged || fontProbeCount % 200 === 0) {
              fontProbeLogged = true;
              record("Fonts", "offsetWidth probe", "fontFamily=\"" + this.style.fontFamily + "\" (probe #" + fontProbeCount + ")");
            }
          }
          return val;
        },
      });
    }

    if (origOffsetHeight && origOffsetHeight.get) {
      const ohGet = origOffsetHeight.get;
      Object.defineProperty(HTMLElement.prototype, "offsetHeight", {
        configurable: true, enumerable: true,
        get() {
          const val = ohGet.call(this);
          if (this.tagName.charCodeAt(0) === 83 && this.tagName === "SPAN" && this.style.fontFamily) {
            fontProbeCount++;
            if (!fontProbeLogged || fontProbeCount % 200 === 0) {
              fontProbeLogged = true;
              record("Fonts", "offsetHeight probe", "fontFamily=\"" + this.style.fontFamily + "\" (probe #" + fontProbeCount + ")");
            }
          }
          return val;
        },
      });
    }
  }

  // ── 6b. FontFace API ───────────────────────────────────────────────────
  // document.fonts (FontFaceSet) provides direct font availability checks
  // without the offsetWidth/offsetHeight measurement trick.
  if (typeof window.FontFaceSet !== "undefined") {
    // check() can be called 100s of times during font probing — fire-once
    hookMethodHot(window.FontFaceSet.prototype, "check", "Fonts", "document.fonts.check");
    hookMethodHot(window.FontFaceSet.prototype, "load", "Fonts", "document.fonts.load");
    hookMethodHot(window.FontFaceSet.prototype, "forEach", "Fonts", "document.fonts.forEach");
  }
  // document.fonts.ready — sites await this before probing
  if (typeof document !== "undefined" && document.fonts) {
    const fontsDesc = Object.getOwnPropertyDescriptor(document.fonts, "ready") ||
                      (typeof window.FontFaceSet !== "undefined" && Object.getOwnPropertyDescriptor(window.FontFaceSet.prototype, "ready"));
    if (fontsDesc && fontsDesc.get) {
      const origGet = fontsDesc.get;
      Object.defineProperty(document.fonts, "ready", {
        get() {
          recordHot("Fonts", "document.fonts.ready", "");
          return origGet.call(this);
        },
        configurable: true,
        enumerable: true,
      });
    }
  }

  // ── 7. WebRTC Fingerprinting ────────────────────────────────────────────
  // WebRTC is used for:
  // - Local/public IP discovery via ICE candidates
  // - STUN server probing to extract IPs behind VPN
  // - Media codec enumeration via getCapabilities()
  if (typeof RTCPeerConnection !== "undefined") {
    const OrigRTC = RTCPeerConnection;

    window.RTCPeerConnection = function (config, constraints) {
      // Log STUN/TURN servers — these are used to extract public IPs
      let stunServers = "";
      if (config && config.iceServers) {
        const urls = [];
        for (const server of config.iceServers) {
          const u = server.urls || server.url;
          if (Array.isArray(u)) urls.push(...u);
          else if (u) urls.push(u);
        }
        stunServers = urls.join(", ");
      }
      record("WebRTC", "new RTCPeerConnection", stunServers || "(no ICE servers)");

      const pc = constraints ? new OrigRTC(config, constraints) : new OrigRTC(config);

      // Hook onicecandidate — this is where IP addresses leak
      const origDesc = Object.getOwnPropertyDescriptor(OrigRTC.prototype, "onicecandidate");
      let iceCandidateHooked = false;

      if (origDesc && origDesc.set) {
        const origSet = origDesc.set;
        Object.defineProperty(pc, "onicecandidate", {
          get() { return origDesc.get ? origDesc.get.call(this) : undefined; },
          set(handler) {
            if (!iceCandidateHooked && typeof handler === "function") {
              iceCandidateHooked = true;
              const wrappedHandler = function (event) {
                if (event && event.candidate && event.candidate.candidate) {
                  const c = event.candidate.candidate;
                  // Extract IP from ICE candidate string
                  const ipMatch = c.match(/(\d+\.\d+\.\d+\.\d+|[0-9a-f:]{3,})/i);
                  if (ipMatch) {
                    record("WebRTC", "ICE candidate (IP leak)", ipMatch[0] + " — " + c.slice(0, 80));
                  }
                }
                return handler.call(this, event);
              };
              return origSet.call(this, wrappedHandler);
            }
            return origSet.call(this, handler);
          },
          configurable: true,
        });
      }

      return pc;
    };
    window.RTCPeerConnection.prototype = OrigRTC.prototype;

    // Hook the IP leak pipeline methods on the prototype
    hookMethod(OrigRTC.prototype, "createDataChannel", "WebRTC", "createDataChannel");
    hookMethod(OrigRTC.prototype, "createOffer", "WebRTC", "createOffer");
    hookMethod(OrigRTC.prototype, "createAnswer", "WebRTC", "createAnswer");
    hookMethod(OrigRTC.prototype, "setLocalDescription", "WebRTC", "setLocalDescription");
    hookMethod(OrigRTC.prototype, "setRemoteDescription", "WebRTC", "setRemoteDescription");

    // Hook addEventListener for "icecandidate" — alternative to onicecandidate
    const origAddEL = OrigRTC.prototype.addEventListener;
    OrigRTC.prototype.addEventListener = function (type, listener, opts) {
      if (type === "icecandidate" && typeof listener === "function") {
        record("WebRTC", "addEventListener('icecandidate')", "");
        const origListener = listener;
        listener = function (event) {
          if (event && event.candidate && event.candidate.candidate) {
            const c = event.candidate.candidate;
            const ipMatch = c.match(/(\d+\.\d+\.\d+\.\d+|[0-9a-f:]{3,})/i);
            if (ipMatch) {
              record("WebRTC", "ICE candidate (IP leak)", ipMatch[0] + " — " + c.slice(0, 80));
            }
          }
          return origListener.call(this, event);
        };
      }
      return origAddEL.call(this, type, listener, opts);
    };

    // Media codec fingerprinting via getCapabilities (static method)
    if (typeof RTCRtpSender !== "undefined" && RTCRtpSender.getCapabilities) {
      const origSenderCaps = RTCRtpSender.getCapabilities;
      RTCRtpSender.getCapabilities = function (kind) {
        record("WebRTC", "RTCRtpSender.getCapabilities", kind || "");
        return origSenderCaps.call(this, kind);
      };
    }
    if (typeof RTCRtpReceiver !== "undefined" && RTCRtpReceiver.getCapabilities) {
      const origReceiverCaps = RTCRtpReceiver.getCapabilities;
      RTCRtpReceiver.getCapabilities = function (kind) {
        record("WebRTC", "RTCRtpReceiver.getCapabilities", kind || "");
        return origReceiverCaps.call(this, kind);
      };
    }
  }

  // ── 8. Permissions API ────────────────────────────────────────────────
  if (typeof Permissions !== "undefined" && Permissions.prototype.query) {
    hookMethod(Permissions.prototype, "query", "Permissions", "Permissions.query");
  }

  // ── 9. ClientRects Fingerprinting ─────────────────────────────────────
  // Hot path — called 1000s of times by UI frameworks
  hookMethodHot(Element.prototype, "getClientRects", "ClientRects", "getClientRects");
  hookMethodHot(Element.prototype, "getBoundingClientRect", "ClientRects", "getBoundingClientRect");

  // ── 10. Date/Timezone Fingerprinting ──────────────────────────────────
  hookMethod(Date.prototype, "getTimezoneOffset", "Timezone", "getTimezoneOffset");
  if (typeof Intl !== "undefined" && Intl.DateTimeFormat) {
    hookMethod(Intl.DateTimeFormat.prototype, "resolvedOptions", "Timezone", "Intl.DateTimeFormat.resolvedOptions");
  }

  // ── 11. Storage Fingerprinting ────────────────────────────────────────
  hookGetter(Navigator.prototype, "cookieEnabled", "Storage", "navigator.cookieEnabled");
  if (typeof Storage !== "undefined") {
    // Hot path — called constantly by many sites
    hookMethodHot(Storage.prototype, "setItem", "Storage", "localStorage.setItem");
    hookMethodHot(Storage.prototype, "getItem", "Storage", "localStorage.getItem");
  }
  if (typeof window.indexedDB !== "undefined") {
    hookMethod(IDBFactory.prototype, "open", "Storage", "indexedDB.open");
  }

  // ── 12. Media Devices ─────────────────────────────────────────────────
  if (typeof MediaDevices !== "undefined" && MediaDevices.prototype.enumerateDevices) {
    hookMethod(MediaDevices.prototype, "enumerateDevices", "MediaDevices", "enumerateDevices");
  }

  // ── 13. Speech Synthesis (voice enumeration) ──────────────────────────
  if (typeof speechSynthesis !== "undefined") {
    hookMethod(speechSynthesis, "getVoices", "SpeechSynthesis", "getVoices");
  }

  // ── 14. Connection Info ───────────────────────────────────────────────
  if (typeof NetworkInformation !== "undefined") {
    for (const prop of ["effectiveType", "downlink", "rtt", "saveData"]) {
      hookGetter(NetworkInformation.prototype, prop, "Network", `connection.${prop}`);
    }
  }

  // ── 15. Plugin Enumeration ────────────────────────────────────────────
  hookGetter(Navigator.prototype, "plugins", "Plugins", "navigator.plugins");
  hookGetter(Navigator.prototype, "mimeTypes", "Plugins", "navigator.mimeTypes");

  // ── 16. WebSocket Fingerprinting ──────────────────────────────────────
  // WebSocket connections can:
  // - Reveal real IP behind VPN/proxy (bypass HTTP proxy)
  // - Probe localhost ports to detect installed software
  // - Scan local network services
  // - Measure round-trip latency for network fingerprinting
  if (typeof WebSocket !== "undefined") {
    const OrigWS = WebSocket;

    // Local address patterns for port scanning detection
    const LOCAL_RE = /^wss?:\/\/(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)(:\d+)?/i;

    // Track connection bursts (rapid opens = port scanning)
    let wsCount = 0;
    let wsBurstStart = 0;
    let wsLocalCount = 0;
    let wsLocalPorts = new Set();
    const WS_BURST_WINDOW = 2000; // ms
    const WS_BURST_THRESHOLD = 5;
    let wsBurstReported = false;
    let wsLocalReported = false;

    function extractPort(url) {
      try {
        const u = new URL(url);
        return u.port || (u.protocol === "wss:" ? "443" : "80");
      } catch (_) {
        return "";
      }
    }

    window.WebSocket = function (url, protocols) {
      const urlStr = typeof url === "string" ? url : String(url);
      const now = Date.now();

      // Reset burst window
      if (now - wsBurstStart > WS_BURST_WINDOW) {
        wsCount = 0;
        wsBurstStart = now;
      }
      wsCount++;

      // Detect localhost/local network probing (port scanning)
      const isLocal = LOCAL_RE.test(urlStr);
      if (isLocal) {
        wsLocalCount++;
        wsLocalPorts.add(extractPort(urlStr));

        if (wsLocalCount === 1) {
          // First local probe — log with full detail
          record("WebSocket", "localhost probe", urlStr);
        }
        if (wsLocalCount % 10 === 0 && !wsLocalReported) {
          record("WebSocket", "localhost port scan",
            wsLocalCount + " local connections across " + wsLocalPorts.size + " ports");
        }
        if (wsLocalPorts.size >= 5 && !wsLocalReported) {
          wsLocalReported = true;
          record("WebSocket", "localhost port scan detected",
            wsLocalPorts.size + " unique ports probed: " +
            [...wsLocalPorts].slice(0, 20).join(", ") +
            (wsLocalPorts.size > 20 ? "..." : ""));
        }
      } else {
        // Non-local WebSocket — log first one
        if (wsCount === 1) {
          record("WebSocket", "new WebSocket", urlStr);
        }
      }

      // Detect rapid connection burst (any target)
      if (wsCount >= WS_BURST_THRESHOLD && !wsBurstReported) {
        wsBurstReported = true;
        record("WebSocket", "connection burst",
          wsCount + " connections in " + WS_BURST_WINDOW + "ms");
      }

      return protocols !== undefined ? new OrigWS(url, protocols) : new OrigWS(url);
    };
    window.WebSocket.prototype = OrigWS.prototype;
    for (const key of ["CONNECTING", "OPEN", "CLOSING", "CLOSED"]) {
      window.WebSocket[key] = OrigWS[key];
    }

    // Expose local port scan data for export
    window.addEventListener("__fpDetector_getWsPorts", () => {
      if (wsLocalPorts.size > 0) {
        window.dispatchEvent(new CustomEvent("__fpDetector_wsPorts", {
          detail: JSON.stringify({
            totalLocal: wsLocalCount,
            totalAll: wsCount,
            ports: [...wsLocalPorts],
          }),
        }));
      }
    });
  }

  // ── 17. Font Access API (direct font enumeration) ─────────────────────
  if (typeof window.queryLocalFonts === "function") {
    hookMethod(window, "queryLocalFonts", "Fonts", "queryLocalFonts");
  }

  // ── 18. Do Not Track ──────────────────────────────────────────────────
  hookGetter(Navigator.prototype, "doNotTrack", "DNT", "navigator.doNotTrack");

  // ── 19. Device Pixel Ratio ────────────────────────────────────────────
  {
    const dprDesc = Object.getOwnPropertyDescriptor(window, "devicePixelRatio") ||
                    Object.getOwnPropertyDescriptor(Window.prototype, "devicePixelRatio");
    if (dprDesc && dprDesc.get) {
      const origGet = dprDesc.get;
      Object.defineProperty(window, "devicePixelRatio", {
        ...dprDesc,
        get() {
          record("Screen", "window.devicePixelRatio", "devicePixelRatio");
          return origGet.call(this);
        },
      });
    }
  }

  // ── 20. matchMedia (CSS media query probing) ──────────────────────────
  // Sites probe prefers-color-scheme, prefers-reduced-motion, display-mode,
  // forced-colors, etc. to build a media feature fingerprint.
  {
    const origMatchMedia = window.matchMedia;
    if (typeof origMatchMedia === "function") {
      window.matchMedia = function (query) {
        record("MediaQuery", "matchMedia", query);
        return origMatchMedia.call(this, query);
      };
    }
  }

  // ── 21. Keyboard Layout API ───────────────────────────────────────────
  if (typeof Keyboard !== "undefined" && Keyboard.prototype.getLayoutMap) {
    hookMethod(Keyboard.prototype, "getLayoutMap", "Keyboard", "keyboard.getLayoutMap");
  }

  // ── 22. Performance Timing ────────────────────────────────────────────
  // High-resolution timers can be used for timing attacks and hardware fingerprinting.
  // Hot path — called 1000s of times per second by frameworks/animations
  hookMethodHot(Performance.prototype, "now", "Timing", "performance.now");
  if (Performance.prototype.getEntries) {
    hookMethodHot(Performance.prototype, "getEntries", "Timing", "performance.getEntries");
    hookMethodHot(Performance.prototype, "getEntriesByType", "Timing", "performance.getEntriesByType");
    hookMethodHot(Performance.prototype, "getEntriesByName", "Timing", "performance.getEntriesByName");
  }
  if (typeof PerformanceObserver !== "undefined") {
    const OrigPO = PerformanceObserver;
    window.PerformanceObserver = function (callback) {
      record("Timing", "new PerformanceObserver", "");
      return new OrigPO(callback);
    };
    window.PerformanceObserver.prototype = OrigPO.prototype;
    if (OrigPO.supportedEntryTypes) {
      Object.defineProperty(window.PerformanceObserver, "supportedEntryTypes", {
        get: () => OrigPO.supportedEntryTypes,
      });
    }
  }

  // ── 23. WebGPU ────────────────────────────────────────────────────────
  if (typeof GPU !== "undefined") {
    hookMethod(GPU.prototype, "requestAdapter", "WebGPU", "gpu.requestAdapter");
  }
  if (typeof GPUAdapter !== "undefined") {
    hookMethod(GPUAdapter.prototype, "requestDevice", "WebGPU", "gpuAdapter.requestDevice");
    hookMethod(GPUAdapter.prototype, "requestAdapterInfo", "WebGPU", "gpuAdapter.requestAdapterInfo");
  }

  // ── 24. Bluetooth / USB / Serial / HID (hardware enumeration) ────────
  if (typeof Bluetooth !== "undefined" && Bluetooth.prototype.requestDevice) {
    hookMethod(Bluetooth.prototype, "requestDevice", "Hardware", "bluetooth.requestDevice");
    hookMethod(Bluetooth.prototype, "getDevices", "Hardware", "bluetooth.getDevices");
  }
  if (typeof USB !== "undefined") {
    hookMethod(USB.prototype, "getDevices", "Hardware", "usb.getDevices");
    hookMethod(USB.prototype, "requestDevice", "Hardware", "usb.requestDevice");
  }
  if (typeof Serial !== "undefined") {
    hookMethod(Serial.prototype, "getPorts", "Hardware", "serial.getPorts");
    hookMethod(Serial.prototype, "requestPort", "Hardware", "serial.requestPort");
  }
  if (typeof HID !== "undefined") {
    hookMethod(HID.prototype, "getDevices", "Hardware", "hid.getDevices");
    hookMethod(HID.prototype, "requestDevice", "Hardware", "hid.requestDevice");
  }

  // ── 25. Sensor APIs ──────────────────────────────────────────────────
  for (const SensorCls of ["Accelerometer", "Gyroscope", "Magnetometer",
    "AbsoluteOrientationSensor", "RelativeOrientationSensor",
    "LinearAccelerationSensor", "GravitySensor", "AmbientLightSensor"]) {
    if (typeof window[SensorCls] !== "undefined") {
      const Orig = window[SensorCls];
      const sensorLabel = "new " + SensorCls;
      window[SensorCls] = function (options) {
        recordHot("Sensors", sensorLabel, SensorCls);
        return options ? new Orig(options) : new Orig();
      };
      window[SensorCls].prototype = Orig.prototype;
    }
  }

  // ── 26. PDF Viewer detection ──────────────────────────────────────────
  hookGetter(Navigator.prototype, "pdfViewerEnabled", "Navigator", "navigator.pdfViewerEnabled");

  // ── 27. Touch support detection ───────────────────────────────────────
  // ontouchstart and TouchEvent presence are commonly probed.
  {
    const touchDesc = Object.getOwnPropertyDescriptor(window, "ontouchstart");
    if (touchDesc) {
      const origGet = touchDesc.get;
      const origSet = touchDesc.set;
      Object.defineProperty(window, "ontouchstart", {
        get() {
          record("Touch", "window.ontouchstart", "get");
          return origGet ? origGet.call(this) : undefined;
        },
        set(v) {
          record("Touch", "window.ontouchstart", "set");
          return origSet ? origSet.call(this, v) : undefined;
        },
        configurable: true,
        enumerable: true,
      });
    }
  }

  // ── 28. Credential Management ─────────────────────────────────────────
  if (typeof CredentialsContainer !== "undefined") {
    hookMethod(CredentialsContainer.prototype, "get", "Credentials", "credentials.get");
    hookMethod(CredentialsContainer.prototype, "create", "Credentials", "credentials.create");
  }

  // ── 29. Notification permission probe ─────────────────────────────────
  if (typeof Notification !== "undefined") {
    hookGetter(Notification, "permission", "Permissions", "Notification.permission");
  }

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

    // Image.src setter
    const origImageSrc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, "src");
    if (origImageSrc && origImageSrc.set) {
      const origSet = origImageSrc.set;
      Object.defineProperty(HTMLImageElement.prototype, "src", {
        ...origImageSrc,
        set(val) {
          if (isExtUrl(val)) recordExtProbe("Image.src = extension URL", val);
          return origSet.call(this, val);
        },
      });
    }

    // Link.href setter
    const origLinkHref = Object.getOwnPropertyDescriptor(HTMLLinkElement.prototype, "href");
    if (origLinkHref && origLinkHref.set) {
      const origSet = origLinkHref.set;
      Object.defineProperty(HTMLLinkElement.prototype, "href", {
        ...origLinkHref,
        set(val) {
          if (isExtUrl(val)) recordExtProbe("Link.href = extension URL", val);
          return origSet.call(this, val);
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
        const now = Date.now();

        // Detect burst pattern: many getComputedStyle calls in quick succession
        // on elements appended to body (typical extension detection pattern)
        if (el && el.parentNode && (el.parentNode === document.body || el.parentNode.parentNode === document.body)) {
          if (now - csProbeStart > CS_BURST_WINDOW) {
            csProbeCount = 0;
            csProbeStart = now;
          }
          csProbeCount++;
          if (csProbeCount >= CS_BURST_THRESHOLD && !csBurstReported) {
            csBurstReported = true;
            record("ExtensionDetect", "getComputedStyle burst",
              csProbeCount + " calls in " + CS_BURST_WINDOW + "ms (extension CSS detection pattern)");
          }
        }

        return result;
      };
    }
  }

  // ── 29d. Storage Quota (disk size leak) ────────────────────────────────
  // navigator.storage.estimate() returns {usage, quota} — the quota reveals
  // approximate disk size which is a high-entropy fingerprint signal.
  if (typeof StorageManager !== "undefined") {
    hookMethod(StorageManager.prototype, "estimate", "Storage", "navigator.storage.estimate");
    hookMethod(StorageManager.prototype, "persist", "Storage", "navigator.storage.persist");
    hookMethod(StorageManager.prototype, "persisted", "Storage", "navigator.storage.persisted");
  }

  // ── 29e. Headless / Automation Detection ──────────────────────────────
  // navigator.webdriver is true in automated browsers (Puppeteer, Playwright,
  // Selenium). Sites read it to detect bots and as a fingerprint signal.
  hookGetter(Navigator.prototype, "webdriver", "HeadlessDetect", "navigator.webdriver");

  // Additional headless detection signals
  if (typeof VisualViewport !== "undefined") {
    for (const prop of ["width", "height", "scale", "offsetTop", "offsetLeft"]) {
      hookGetter(VisualViewport.prototype, prop, "HeadlessDetect", "visualViewport." + prop);
    }
  }
  // navigator.share / canShare absence indicates headless Chrome
  if (Navigator.prototype.share) {
    hookMethod(Navigator.prototype, "share", "HeadlessDetect", "navigator.share");
  }
  if (Navigator.prototype.canShare) {
    hookMethod(Navigator.prototype, "canShare", "HeadlessDetect", "navigator.canShare");
  }

  // ── 30. Math Fingerprinting ───────────────────────────────────────────
  // Math functions are called millions of times by normal code. We use
  // recordHot (fire-once) so the wrapper is effectively free after first call.
  {
    const mathFns = [
      "acos", "acosh", "asin", "asinh", "atan", "atanh",
      "cos", "cosh", "exp", "expm1", "log1p",
      "sin", "sinh", "tan", "tanh",
    ];
    for (const fn of mathFns) {
      if (typeof Math[fn] === "function") {
        const orig = Math[fn];
        const label = "Math." + fn;
        Math[fn] = function () {
          recordHot("Math", label, fn);
          return orig.apply(this, arguments);
        };
      }
    }
  }

  // ── 31. Architecture Detection (NaN bit pattern) ──────────────────────
  // FingerprintJS creates NaN via Float32Array and reads the sign bit
  // through a Uint8Array view to distinguish x86 vs ARM.
  {
    const OrigFloat32 = Float32Array;
    const origF32From = Float32Array.from;
    // Hook the constructor — architecture probing always creates new Float32Array(1)
    window.Float32Array = function (arg0, arg1, arg2) {
      if (arg0 === 1) {
        recordHot("Architecture", "new Float32Array", "size=1 (possible NaN bit pattern probe)");
      }
      // Fast path for common constructor signatures
      if (arg2 !== undefined) return new OrigFloat32(arg0, arg1, arg2);
      if (arg1 !== undefined) return new OrigFloat32(arg0, arg1);
      return new OrigFloat32(arg0);
    };
    window.Float32Array.prototype = OrigFloat32.prototype;
    window.Float32Array.BYTES_PER_ELEMENT = OrigFloat32.BYTES_PER_ELEMENT;
    if (origF32From) window.Float32Array.from = origF32From;
    if (OrigFloat32.of) window.Float32Array.of = OrigFloat32.of;
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

  // ── 33. DOM Blockers (ad blocker fingerprinting) ───────────────────────
  // Detects the FingerprintJS-style pattern: rapid creation of many hidden
  // bait elements followed by offsetParent checks to determine which ad
  // blocker filter lists are active.
  //
  // Detection strategy:
  // 1. Track offsetParent reads in a sliding time window
  // 2. If many reads happen in a short burst (>15 in 200ms), it's a probe
  // 3. Also match known FingerprintJS bait selectors by ID/class
  // 4. Track element creation + immediate removal (create-check-remove cycle)
  {
    // Known bait element IDs used by FingerprintJS across 41 filter lists
    const KNOWN_BAIT_IDS = new Set([
      "ad_300X250", "Ad-Content", "bannerfloat22", "campaign-banner",
      "ad_banner", "adbanner", "adbox", "adsbox", "ad-slot",
      "adblock-honeypot", "ad_blocker", "Iklan-Melayang",
      "Kolom-Iklan-728", "SidebarIklan-wrapper", "Box-Banner-ads",
      "mobileCatfish", "pavePub", "kauli_yad_1", "mgid_iframe1",
      "ad_inview_area", "barraPublicidade", "Publicidade",
      "publiEspecial", "queTooltip", "backkapat", "reklami",
      "onlajny-stickers", "reklamni-box", "advertentie",
      "vipAdmarktBannerBlock", "SSpotIMPopSlider", "werbungsky",
      "reklame-rechts-mitte", "ceneo-placeholder-ceneo-12",
      "cemp_doboz", "hirdetesek_box", "cookieconsentdiv",
      "qoo-counter", "top100counter", "pgeldiz", "livereAdWrapper",
      "navbar_notice_50", "divAgahi",
    ]);

    const KNOWN_BAIT_CLASSES = new Set([
      "sponsored-text-link", "trafficjunky-ad", "textad_headline",
      "yb-floorad", "widget_po_ads_widget", "BetterJsPopOverlay",
      "quangcao", "close-ads", "mainostila", "sponsorit", "ylamainos",
      "reklama-megaboard", "sklik", "adstekst", "reklamos_tarpas",
      "reklamos_nuorodos", "box_adv_annunci", "cnt-publi",
      "reclama", "geminiLB1Ad", "right-and-left-sponsers",
      "Zi_ad_a_H", "frontpageAdvM", "cfa_popup",
      "ezmob-footer", "cc-CookieWarning", "aw-cookie-banner",
      "sygnal24-gdpr-modal-wrap", "adblocker-root", "wp_adblock_detect",
      "header-blocked-ad", "hs-sosyal", "as-oil",
      "navigate-to-top", "newsletter_holder",
      "util-bar-module-firefly-visible", "BlockNag__Card",
      "article-sharer", "community__social-desc",
      "ctpl-fullbanner", "zergnet-recommend",
      "ads300s", "bumq", "img-kosana",
      "optimonk-iframe-container", "yandex-rtb-block",
      "lapni-pop-over", "sponsorlinkgruen",
      "ad-desktop-rectangle", "mobile_adhesion", "widgetadv", "ads_ban",
      "revenue_unit_item",
    ]);

    // Burst detection: count offsetParent reads in a time window
    const BURST_WINDOW = 200; // ms
    const BURST_THRESHOLD = 15; // reads within window = fingerprinting
    let burstCount = 0;
    let burstWindowStart = 0;
    let burstDetected = false;
    let burstReported = false;

    // Track element creation for create-check-remove pattern
    let recentCreations = 0;
    let recentRemovals = 0;
    let creationWindow = 0;
    const CREATION_BURST_THRESHOLD = 20;
    const CREATION_WINDOW_MS = 500;

    // Hook offsetParent
    const origOffsetParent = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "offsetParent");
    if (origOffsetParent && origOffsetParent.get) {
      const opGet = origOffsetParent.get;

      Object.defineProperty(HTMLElement.prototype, "offsetParent", {
        configurable: true, enumerable: true,
        get() {
          const val = opGet.call(this);
          const now = Date.now();

          // 1. Burst detection — many offsetParent reads in a short window
          if (!burstReported) {
            if (now - burstWindowStart > BURST_WINDOW) {
              burstCount = 0;
              burstWindowStart = now;
            }
            burstCount++;
            if (burstCount >= BURST_THRESHOLD && !burstDetected) {
              burstDetected = true;
              record("AdBlockDetect", "offsetParent burst",
                burstCount + " reads in " + BURST_WINDOW + "ms (filter list fingerprinting pattern)");
            }
          }

          // 2. Known bait ID match
          if (this.id && KNOWN_BAIT_IDS.has(this.id)) {
            record("AdBlockDetect", "known bait element",
              "id=\"" + this.id + "\" (FingerprintJS filter list probe)");
          }

          // 3. Known bait class match
          if (this.className && typeof this.className === "string") {
            const classes = this.className.split(" ");
            for (let i = 0; i < classes.length; i++) {
              if (KNOWN_BAIT_CLASSES.has(classes[i])) {
                record("AdBlockDetect", "known bait element",
                  "class=\"" + classes[i] + "\" (FingerprintJS filter list probe)");
                break;
              }
            }
          }

          return val;
        },
      });
    }

    // Hook element removal to detect create-check-remove cycle
    const origRemoveChild = Node.prototype.removeChild;
    Node.prototype.removeChild = function (child) {
      const result = origRemoveChild.call(this, child);
      if (child && child.nodeType === 1) {
        const now = Date.now();
        if (now - creationWindow > CREATION_WINDOW_MS) {
          recentRemovals = 0;
          recentCreations = 0;
          creationWindow = now;
        }
        recentRemovals++;
        // Detect create-check-remove pattern: many elements created and removed quickly
        if (recentCreations >= CREATION_BURST_THRESHOLD && recentRemovals >= CREATION_BURST_THRESHOLD && !burstReported) {
          burstReported = true;
          record("AdBlockDetect", "create-check-remove cycle",
            recentCreations + " elements created and " + recentRemovals +
            " removed in " + CREATION_WINDOW_MS + "ms (ad blocker fingerprinting)");
        }
      }
      return result;
    };

    // Track element creation bursts (piggyback on existing createElement hook)
    const origBodyAppend = Element.prototype.appendChild;
    Element.prototype.appendChild = function (child) {
      const result = origBodyAppend.call(this, child);
      if (child && child.nodeType === 1 && (this === document.body || this.parentNode === document.body)) {
        const now = Date.now();
        if (now - creationWindow > CREATION_WINDOW_MS) {
          recentCreations = 0;
          recentRemovals = 0;
          creationWindow = now;
        }
        recentCreations++;
      }
      return result;
    };
  }

  // ── 34. Font Preferences (default font metrics) ───────────────────────
  // Only detect iframe creation — use recordHot so the createElement wrapper
  // becomes a no-op after the first iframe is seen. This avoids penalizing
  // the millions of non-iframe createElement calls.
  {
    const origCreateElement = document.createElement;
    document.createElement = function (tag) {
      const el = origCreateElement.call(this, tag);
      // Fast check: only 'i'/'I' first char can be "iframe"
      if (typeof tag === "string" && (tag.charCodeAt(0) === 105 || tag.charCodeAt(0) === 73) && tag.toLowerCase() === "iframe") {
        recordHot("Fonts", "createElement('iframe')", "possible font metrics iframe");
      }
      return el;
    };
  }

  // ── 35. Apple Pay ─────────────────────────────────────────────────────
  if (typeof window.ApplePaySession !== "undefined") {
    hookMethod(window.ApplePaySession, "canMakePayments", "ApplePay", "ApplePaySession.canMakePayments");
  }

  // ── 36. Private Click Measurement (Safari attribution) ────────────────
  // FingerprintJS reads <a>.attributionSourceId to detect Safari's
  // Privacy Preserving Ad Measurement.
  {
    const aProto = HTMLAnchorElement.prototype;
    for (const prop of ["attributionSourceId", "attributionsourceid"]) {
      const desc = Object.getOwnPropertyDescriptor(aProto, prop);
      if (desc && desc.get) {
        hookGetter(aProto, prop, "PrivateClick", `<a>.${prop}`);
      }
    }
  }

  // ── 37. Screen Frame (taskbar/dock size) ──────────────────────────────
  for (const prop of ["availTop", "availLeft"]) {
    hookGetter(Screen.prototype, prop, "Screen", `screen.${prop}`);
  }

  // ── 38. openDatabase (Web SQL) ────────────────────────────────────────
  if (typeof window.openDatabase === "function") {
    const origOpenDB = window.openDatabase;
    window.openDatabase = function (name, ver, desc, size) {
      recordHot("Storage", "openDatabase", "");
      return origOpenDB.call(this, name, ver, desc, size);
    };
  }
  // Also check for its existence (boolean probe)
  {
    const desc = Object.getOwnPropertyDescriptor(window, "openDatabase");
    if (desc && desc.get) {
      const origGet = desc.get;
      Object.defineProperty(window, "openDatabase", {
        ...desc,
        get() {
          record("Storage", "window.openDatabase", "existence check");
          return origGet.call(this);
        },
      });
    }
  }

  // ── 39. sessionStorage probe ──────────────────────────────────────────
  {
    const desc = Object.getOwnPropertyDescriptor(window, "sessionStorage");
    if (desc && desc.get) {
      const origGet = desc.get;
      Object.defineProperty(window, "sessionStorage", {
        ...desc,
        get() {
          record("Storage", "window.sessionStorage", "access");
          return origGet.call(this);
        },
      });
    }
  }

  // ── 40. AudioContext.baseLatency ───────────────────────────────────────
  if (typeof AudioContext !== "undefined") {
    hookGetter(AudioContext.prototype, "baseLatency", "Audio", "audioContext.baseLatency");
  }

  // ── 41. Intl locale fingerprinting ────────────────────────────────────
  // Intl APIs reveal the user's language, region, calendar, numbering
  // system, and formatting preferences — high-entropy fingerprint data.
  if (typeof Intl !== "undefined") {
    // resolvedOptions() on all Intl formatters — reveals locale, calendar,
    // numbering system, timezone, and formatting preferences
    if (Intl.NumberFormat) {
      hookMethod(Intl.NumberFormat.prototype, "resolvedOptions", "Intl", "Intl.NumberFormat.resolvedOptions");
      hookMethodHot(Intl.NumberFormat.prototype, "format", "Intl", "Intl.NumberFormat.format");
    }
    if (Intl.Collator) {
      hookMethod(Intl.Collator.prototype, "resolvedOptions", "Intl", "Intl.Collator.resolvedOptions");
      hookMethodHot(Intl.Collator.prototype, "compare", "Intl", "Intl.Collator.compare");
    }
    for (const cls of ["ListFormat", "PluralRules", "RelativeTimeFormat", "Segmenter"]) {
      if (Intl[cls] && Intl[cls].prototype.resolvedOptions) {
        hookMethod(Intl[cls].prototype, "resolvedOptions", "Intl", "Intl." + cls + ".resolvedOptions");
      }
    }

    // Intl.DisplayNames — reveals how the browser localizes
    // language/region/script/currency names (locale-specific output)
    if (Intl.DisplayNames) {
      hookMethod(Intl.DisplayNames.prototype, "of", "Intl", "Intl.DisplayNames.of");
      hookMethod(Intl.DisplayNames.prototype, "resolvedOptions", "Intl", "Intl.DisplayNames.resolvedOptions");
    }

    // Intl.Locale — direct locale inspection
    if (Intl.Locale) {
      for (const prop of ["language", "region", "script", "calendar",
        "numberingSystem", "hourCycle", "baseName"]) {
        hookGetter(Intl.Locale.prototype, prop, "Intl", "Intl.Locale." + prop);
      }
    }

    // Intl.supportedValuesOf — enumerates all supported calendars,
    // numbering systems, timezones, etc. for the locale
    if (typeof Intl.supportedValuesOf === "function") {
      const origSVO = Intl.supportedValuesOf;
      Intl.supportedValuesOf = function (key) {
        record("Intl", "Intl.supportedValuesOf", key || "");
        return origSVO.call(this, key);
      };
    }
  }

  // ── 41b. Locale-dependent formatting methods ──────────────────────────
  // toLocaleString/toLocaleDateString/toLocaleTimeString produce
  // locale-specific output that reveals language and region settings.
  {
    const localeMethods = [
      [Date.prototype, "toLocaleString", "Date.toLocaleString"],
      [Date.prototype, "toLocaleDateString", "Date.toLocaleDateString"],
      [Date.prototype, "toLocaleTimeString", "Date.toLocaleTimeString"],
      [Number.prototype, "toLocaleString", "Number.toLocaleString"],
    ];
    for (const [proto, method, label] of localeMethods) {
      hookMethodHot(proto, method, "Intl", label);
    }
    // Array.toLocaleString calls element toLocaleString — fire-once
    hookMethodHot(Array.prototype, "toLocaleString", "Intl", "Array.toLocaleString");
  }

  // ── 42. TouchEvent creation probe ─────────────────────────────────────
  {
    const origCreateEvent = document.createEvent;
    document.createEvent = function (type) {
      if (typeof type === "string" && (type.charCodeAt(0) === 84 || type.charCodeAt(0) === 116) && /touch/i.test(type)) {
        recordHot("Touch", "document.createEvent", type);
      }
      return origCreateEvent.call(this, type);
    };
  }

  // ── 43. Color depth via matchMedia ────────────────────────────────────
  // FingerprintJS probes specific media features. We already hook matchMedia
  // generically (section 20), so those calls will appear in the log.
  // But we also want to flag the high-value fingerprint queries specifically.
  // (Already handled — matchMedia hook captures the query string.)

})();
