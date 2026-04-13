// hooks/canvas.js — Canvas fingerprinting detection
export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 1. Canvas Fingerprinting ──────────────────────────────────────────

  // Data extraction — these are the high-value calls that read the fingerprint.
  // Access-based hooks: keeps our frame out of the call stack when native
  // code emits console warnings/errors (e.g. Chrome's Canvas2D
  // willReadFrequently warning from getImageData, seen on facebook.com).
  // Without this the extension gets blamed for page perf issues in the
  // Errors panel. toDataURL / toBlob use the same pattern defensively.
  hookMethodViaAccess(CanvasRenderingContext2D.prototype, "getImageData", "Canvas", "getImageData");
  hookMethodViaAccess(HTMLCanvasElement.prototype, "toDataURL", "Canvas", "HTMLCanvasElement.toDataURL");
  hookMethodViaAccess(HTMLCanvasElement.prototype, "toBlob", "Canvas", "HTMLCanvasElement.toBlob");

  // Text rendering — the most common canvas fingerprint technique draws text
  // with specific fonts/styles and then extracts the pixel data
  hookMethodHot(CanvasRenderingContext2D.prototype, "fillText", "Canvas", "fillText");
  hookMethodHot(CanvasRenderingContext2D.prototype, "strokeText", "Canvas", "strokeText");
  hookMethodHot(CanvasRenderingContext2D.prototype, "measureText", "Canvas", "measureText");

  // Path-based fingerprinting — isPointInPath/Stroke results vary by rendering
  hookMethodHot(CanvasRenderingContext2D.prototype, "isPointInPath", "Canvas", "isPointInPath");
  hookMethodHot(CanvasRenderingContext2D.prototype, "isPointInStroke", "Canvas", "isPointInStroke");

  // drawImage from another canvas — used to copy canvas content for extraction
  hookMethodHot(CanvasRenderingContext2D.prototype, "drawImage", "Canvas", "drawImage");

  // createImageBitmap — alternative to toDataURL for reading canvas pixels
  if (typeof window.createImageBitmap === "function") {
    const origCIB = window.createImageBitmap;
    window.createImageBitmap = function (source) {
      // Only flag when source is a canvas (not an image/video)
      if (source instanceof HTMLCanvasElement ||
          (typeof OffscreenCanvas !== "undefined" && source instanceof OffscreenCanvas)) {
        recordHot("Canvas", "createImageBitmap(canvas)", "");
      }
      return origCIB.apply(this, arguments);
    };
  }

  // Hook getContext to detect canvas context creation
  {
    const origGetContext = HTMLCanvasElement.prototype.getContext;
    // Separate fire-once flag so the attrs log isn't blocked by the
    // plain "getContext('webgl')" recordHot
    let webglAttrsLogged = false;
    HTMLCanvasElement.prototype.getContext = function (type, attrs) {
      if (typeof type === "string") {
        if (type === "2d") {
          recordHot("Canvas", "getContext('2d')", "2d");
        } else if (type === "webgl" || type === "webgl2" || type === "experimental-webgl") {
          recordHot("WebGL", "getContext('" + type + "')", type);
          // Explicit context attributes reveal GPU-profile probing:
          // { powerPreference: "high-performance" } asks the browser
          // to hand back the discrete GPU and is a strong fingerprint
          // signal. Log once per page with whatever attrs were passed.
          if (!webglAttrsLogged && attrs && typeof attrs === "object") {
            webglAttrsLogged = true;
            const parts = [];
            if (attrs.powerPreference) parts.push("powerPreference=" + attrs.powerPreference);
            if (attrs.antialias !== undefined) parts.push("antialias=" + attrs.antialias);
            if (attrs.preserveDrawingBuffer) parts.push("preserveDrawingBuffer=true");
            if (attrs.failIfMajorPerformanceCaveat) parts.push("failIfMajorPerformanceCaveat=true");
            if (attrs.desynchronized) parts.push("desynchronized=true");
            if (parts.length > 0) {
              record("WebGL", "getContext attrs", parts.join(", "));
            }
          }
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
      // Access-based: convertToBlob returns a promise and is often
      // called with wrong `this` — keep the extension out of the
      // "Illegal invocation" stack.
      hookMethodViaAccess(OffscreenCanvas.prototype, "convertToBlob", "Canvas", "OffscreenCanvas.convertToBlob");
    }
    if (OffscreenCanvas.prototype.transferToImageBitmap) {
      hookMethod(OffscreenCanvas.prototype, "transferToImageBitmap", "Canvas", "OffscreenCanvas.transferToImageBitmap");
    }
  }
}
