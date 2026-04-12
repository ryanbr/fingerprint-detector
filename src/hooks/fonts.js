// hooks/fonts.js — Font enumeration, FontFace API, queryLocalFonts, font preferences
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 6. Font Enumeration via dimension probing ─────────────────────────
  // Sites create elements with specific fontFamily values and measure their
  // dimensions to determine which fonts are installed.
  //
  // Self-unwrapping: after sufficient probes are detected (1000+), the
  // dimension getters restore themselves to the originals — zero overhead
  // on subsequent reads for the rest of the page's lifetime.

  const SYSTEM_FONTS = new Set([
    "system-ui", "-apple-system", "-apple-system-body", "BlinkMacSystemFont",
    "serif", "sans-serif", "monospace", "cursive", "fantasy",
    "caption", "icon", "menu", "message-box", "small-caption", "status-bar",
  ]);
  let systemFontLogged = false;
  const UNWRAP_THRESHOLD = 1000; // after this many probes, restore original getters

  if (typeof document !== "undefined") {
    let fontProbeCount = 0;
    let fontProbeLogged = false;
    let unwrapped = false;

    // Store originals for self-unwrapping
    const originals = {};

    function unwrapAll() {
      if (unwrapped) return;
      unwrapped = true;
      // Restore all dimension getters to their originals — zero overhead from now on
      for (const [proto, prop, desc] of Object.values(originals)) {
        Object.defineProperty(proto, prop, desc);
      }
      record("Fonts", "dimension hooks unwrapped",
        fontProbeCount + " probes detected — restoring native getters for performance");
    }

    function checkFontProbe(el, method) {
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

      // System font keyword check
      if (!systemFontLogged) {
        const ff = el.style.fontFamily;
        const fc = ff.charCodeAt(0);
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

      // Self-unwrap after enough probes — fingerprinting already detected,
      // no need to keep paying the overhead
      if (fontProbeCount >= UNWRAP_THRESHOLD) {
        unwrapAll();
      }
    }

    // Helper to hook a dimension getter with self-unwrap support
    function hookDimGetter(proto, prop, method) {
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc || !desc.get) return;
      originals[prop] = [proto, prop, desc]; // save for unwrapping
      const origGet = desc.get;
      Object.defineProperty(proto, prop, {
        configurable: true, enumerable: true,
        get() {
          const val = origGet.call(this);
          checkFontProbe(this, method);
          return val;
        },
      });
    }

    hookDimGetter(HTMLElement.prototype, "offsetWidth", "offsetWidth");
    hookDimGetter(HTMLElement.prototype, "offsetHeight", "offsetHeight");
    hookDimGetter(Element.prototype, "scrollWidth", "scrollWidth");
    hookDimGetter(Element.prototype, "scrollHeight", "scrollHeight");
  }

  // ── 6b. FontFace API ───────────────────────────────────────────────────
  if (typeof window.FontFaceSet !== "undefined") {
    hookMethodHot(window.FontFaceSet.prototype, "check", "Fonts", "document.fonts.check");
    hookMethodHot(window.FontFaceSet.prototype, "load", "Fonts", "document.fonts.load");
    hookMethodHot(window.FontFaceSet.prototype, "forEach", "Fonts", "document.fonts.forEach");
    if (window.FontFaceSet.prototype.add) {
      hookMethodHot(window.FontFaceSet.prototype, "add", "Fonts", "document.fonts.add");
    }
  }

  // document.fonts.ready
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

  // FontFace constructor
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
