// hooks/privacy.js — Do Not Track, Headless/webdriver detection
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 18. Do Not Track ──────────────────────────────────────────────────
  hookGetter(Navigator.prototype, "doNotTrack", "DNT", "navigator.doNotTrack");

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
}
