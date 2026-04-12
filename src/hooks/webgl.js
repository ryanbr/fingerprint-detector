// hooks/webgl.js — WebGL/WebGL2 fingerprinting detection
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
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
}
