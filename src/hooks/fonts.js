// hooks/fonts.js — Font enumeration, FontFace API, queryLocalFonts, font preferences
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
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

  // ── 17. Font Access API (direct font enumeration) ─────────────────────
  if (typeof window.queryLocalFonts === "function") {
    hookMethod(window, "queryLocalFonts", "Fonts", "queryLocalFonts");
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
}
