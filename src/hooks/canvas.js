// hooks/canvas.js — Canvas fingerprinting detection
export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 1. Canvas Fingerprinting ──────────────────────────────────────────

  // Data extraction — these are the high-value calls that read the fingerprint
  hookMethod(CanvasRenderingContext2D.prototype, "toDataURL", "Canvas", "toDataURL");
  hookMethod(CanvasRenderingContext2D.prototype, "toBlob", "Canvas", "toBlob");
  hookMethod(CanvasRenderingContext2D.prototype, "getImageData", "Canvas", "getImageData");
  hookMethod(HTMLCanvasElement.prototype, "toDataURL", "Canvas", "HTMLCanvasElement.toDataURL");
  hookMethod(HTMLCanvasElement.prototype, "toBlob", "Canvas", "HTMLCanvasElement.toBlob");

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
