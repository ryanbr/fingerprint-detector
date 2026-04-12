// hooks/fonts.js — Font enumeration, FontFace API, queryLocalFonts, font preferences
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 6. Font Enumeration via dimension probing ─────────────────────────
  // Sites create elements with specific fontFamily values and measure their
  // dimensions to determine which fonts are installed. Common elements: SPAN, DIV.
  // offsetWidth/offsetHeight/scrollWidth/scrollHeight are all used.
  // System font keywords for default font preference detection
  const SYSTEM_FONTS = new Set([
    "system-ui", "-apple-system", "-apple-system-body", "BlinkMacSystemFont",
    "serif", "sans-serif", "monospace", "cursive", "fantasy",
    "caption", "icon", "menu", "message-box", "small-caption", "status-bar",
  ]);
  let systemFontLogged = false;

  if (typeof document !== "undefined") {
    let fontProbeCount = 0;
    let fontProbeLogged = false;

    function checkFontProbe(el, method) {
      // Fast exit: only check elements with fontFamily set
      if (!el.style || !el.style.fontFamily) return;
      const tag = el.tagName;
      const c = tag.charCodeAt(0);
      // Common probe elements: SPAN (83='S'), DIV (68='D'), P (80='P'), A (65='A')
      if (c !== 83 && c !== 68 && c !== 80 && c !== 65) return;

      fontProbeCount++;
      if (!fontProbeLogged || fontProbeCount % 200 === 0) {
        fontProbeLogged = true;
        record("Fonts", method + " probe", "fontFamily=\"" + el.style.fontFamily + "\" (probe #" + fontProbeCount + ")");
      }

      // Also check for system font keyword probing
      if (!systemFontLogged) {
        const ff = el.style.fontFamily;
        const fc = ff.charCodeAt(0);
        // Fast gate: system font keywords start with s/m/c/f/i/-/B
        if (fc === 115 || fc === 109 || fc === 99 || fc === 102 ||
            fc === 105 || fc === 45 || fc === 66) {
          const clean = ff.indexOf("'") !== -1 || ff.indexOf('"') !== -1
            ? ff.replace(/['"]/g, "").trim() : ff.trim();
          if (SYSTEM_FONTS.has(clean)) {
            systemFontLogged = true;
            recordHot("Fonts", "system font probe", "fontFamily=\"" + clean + "\"");
          }
        }
      }
    }

    // offsetWidth
    const origOffsetWidth = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "offsetWidth");
    if (origOffsetWidth && origOffsetWidth.get) {
      const owGet = origOffsetWidth.get;
      Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
        configurable: true, enumerable: true,
        get() {
          const val = owGet.call(this);
          checkFontProbe(this, "offsetWidth");
          return val;
        },
      });
    }

    // offsetHeight
    const origOffsetHeight = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "offsetHeight");
    if (origOffsetHeight && origOffsetHeight.get) {
      const ohGet = origOffsetHeight.get;
      Object.defineProperty(HTMLElement.prototype, "offsetHeight", {
        configurable: true, enumerable: true,
        get() {
          const val = ohGet.call(this);
          checkFontProbe(this, "offsetHeight");
          return val;
        },
      });
    }

    // scrollWidth — alternative dimension probe
    const origScrollWidth = Object.getOwnPropertyDescriptor(Element.prototype, "scrollWidth");
    if (origScrollWidth && origScrollWidth.get) {
      const swGet = origScrollWidth.get;
      Object.defineProperty(Element.prototype, "scrollWidth", {
        configurable: true, enumerable: true,
        get() {
          const val = swGet.call(this);
          checkFontProbe(this, "scrollWidth");
          return val;
        },
      });
    }

    // scrollHeight — alternative dimension probe
    const origScrollHeight = Object.getOwnPropertyDescriptor(Element.prototype, "scrollHeight");
    if (origScrollHeight && origScrollHeight.get) {
      const shGet = origScrollHeight.get;
      Object.defineProperty(Element.prototype, "scrollHeight", {
        configurable: true, enumerable: true,
        get() {
          const val = shGet.call(this);
          checkFontProbe(this, "scrollHeight");
          return val;
        },
      });
    }
  }

  // ── 6b. FontFace API ───────────────────────────────────────────────────
  if (typeof window.FontFaceSet !== "undefined") {
    hookMethodHot(window.FontFaceSet.prototype, "check", "Fonts", "document.fonts.check");
    hookMethodHot(window.FontFaceSet.prototype, "load", "Fonts", "document.fonts.load");
    hookMethodHot(window.FontFaceSet.prototype, "forEach", "Fonts", "document.fonts.forEach");

    // document.fonts.add() — sites add FontFace objects to test loading
    if (window.FontFaceSet.prototype.add) {
      hookMethodHot(window.FontFaceSet.prototype, "add", "Fonts", "document.fonts.add");
    }
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

  // FontFace constructor — creating new FontFace objects to test font loading
  if (typeof window.FontFace !== "undefined") {
    const OrigFF = window.FontFace;
    window.FontFace = function (family, source, descriptors) {
      record("Fonts", "new FontFace", family || "");
      return descriptors ? new OrigFF(family, source, descriptors) : new OrigFF(family, source);
    };
    window.FontFace.prototype = OrigFF.prototype;
  }

  // ── 17. Font Access API (direct font enumeration) ─────────────────────
  if (typeof window.queryLocalFonts === "function") {
    hookMethod(window, "queryLocalFonts", "Fonts", "queryLocalFonts");
  }

  // ── 34. Font Preferences (default font metrics) ───────────────────────
  // Detect iframe creation for font metrics measurement
  {
    const origCreateElement = document.createElement;
    document.createElement = function (tag) {
      const el = origCreateElement.call(this, tag);
      if (typeof tag === "string" && (tag.charCodeAt(0) === 105 || tag.charCodeAt(0) === 73) && tag.toLowerCase() === "iframe") {
        recordHot("Fonts", "createElement('iframe')", "possible font metrics iframe");
      }
      return el;
    };
  }
}
