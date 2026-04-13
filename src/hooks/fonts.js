// hooks/fonts.js — Font enumeration, FontFace API, queryLocalFonts, font preferences
export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
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
  const UNWRAP_HARD_DEADLINE_MS = 5000; // always unwrap after 5s regardless of probe count

  if (typeof document !== "undefined") {
    let fontProbeCount = 0;
    let fontProbeLogged = false;
    let unwrapped = false;

    // Store originals for self-unwrapping
    const originals = [];

    function unwrapAll() {
      if (unwrapped) return;
      unwrapped = true;
      // Restore all dimension getters to their originals — zero overhead from now on
      for (const [proto, prop, desc] of originals) {
        Object.defineProperty(proto, prop, desc);
      }
      if (fontProbeCount > 0) {
        record("Fonts", "dimension hooks unwrapped",
          fontProbeCount + " probes detected — restoring native getters for performance");
      }
    }

    // Hard time-based deadline: even if no font probing happens, we
    // restore the native dimension getters after 5s so we don't sit
    // in the call stack of every offsetWidth / offsetHeight /
    // scrollWidth / scrollHeight read for the rest of the page
    // lifetime. The probe-count-based unwrap above handled
    // fingerprint-heavy pages; this handles the common case of
    // normal pages that never trip the probe threshold.
    setTimeout(unwrapAll, UNWRAP_HARD_DEADLINE_MS);

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
      originals.push([proto, prop, desc]); // save for unwrapping
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
  // Access-based hooks: load returns a promise and is commonly
  // destructured; check/forEach/add are hot synchronous methods
  // where we don't want to sit in the call stack of every call.
  if (typeof window.FontFaceSet !== "undefined") {
    hookMethodViaAccess(window.FontFaceSet.prototype, "check", "Fonts", "document.fonts.check");
    hookMethodViaAccess(window.FontFaceSet.prototype, "load", "Fonts", "document.fonts.load");
    hookMethodViaAccess(window.FontFaceSet.prototype, "forEach", "Fonts", "document.fonts.forEach");
    if (window.FontFaceSet.prototype.add) {
      hookMethodViaAccess(window.FontFaceSet.prototype, "add", "Fonts", "document.fonts.add");
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

  // NOTE: we used to wrap the FontFace constructor to log every
  // `new FontFace(family, ...)` call. That wrap was removed because:
  //
  // 1. It put our frame in the call stack of the constructor, so
  //    if the original threw (invalid descriptors, bad source URL)
  //    the error was attributed to dist/inject.js.
  // 2. It was noisy — sites with many custom fonts triggered
  //    hundreds of log entries.
  // 3. `new FontFace(...)` that is never added to document.fonts
  //    is just an orphan object; the real installation signal is
  //    document.fonts.add(fontFace), which is already hooked above.

  // ── 17. Font Access API (direct font enumeration) ─────────────────────
  // queryLocalFonts returns a promise and is commonly destructured —
  // use access-based hook on Window.prototype so we don't sit in the
  // rejection stack if the user denies permission.
  if (typeof window.queryLocalFonts === "function" && typeof Window !== "undefined") {
    hookMethodViaAccess(Window.prototype, "queryLocalFonts", "Fonts", "queryLocalFonts");
  }

  // NOTE: we used to wrap document.createElement to detect iframe
  // creation as a "possible font metrics iframe" signal. That hook was
  // removed because:
  //
  // 1. document.createElement is one of the hottest functions on the
  //    web — wrapping it put our frame in the call stack of every
  //    React/Vue render and every library's DOM construction. Any
  //    Chrome console warning emitted during an element creation
  //    (deprecated elements, CSP violations, etc.) was attributed to
  //    dist/inject.js.
  // 2. The detection signal was weak. Every modern site creates
  //    iframes for videos, ads, analytics, chat widgets, and social
  //    embeds — "createElement('iframe')" on its own was not
  //    meaningful fingerprinting evidence.
  // 3. The actual font metrics iframe technique still gets caught by
  //    the dimension-probing hooks above (offsetWidth/offsetHeight),
  //    which is where the fingerprint signal actually lives.
}
