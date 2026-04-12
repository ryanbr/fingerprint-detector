// hooks/canvas.js — Canvas fingerprinting detection
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
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
}
