// hooks/privacy.js — Do Not Track, Headless/automation detection, anti-spoofing
export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 18. Do Not Track ──────────────────────────────────────────────────
  hookGetter(Navigator.prototype, "doNotTrack", "DNT", "navigator.doNotTrack");

  // ── 29e. Headless / Automation Detection ──────────────────────────────
  // Sites probe these properties to detect automated browsers (Puppeteer,
  // Playwright, Selenium) and to verify the browser environment is genuine.

  // Core automation flag
  hookGetter(Navigator.prototype, "webdriver", "HeadlessDetect", "navigator.webdriver");

  // VisualViewport — mismatches with screen dimensions indicate headless
  if (typeof VisualViewport !== "undefined") {
    for (const prop of ["width", "height", "scale", "offsetTop", "offsetLeft"]) {
      hookGetter(VisualViewport.prototype, prop, "HeadlessDetect", "visualViewport." + prop);
    }
  }

  // navigator.share / canShare — absence indicates headless Chrome.
  // Access-based: share returns a promise and is often destructured.
  if (Navigator.prototype.share) {
    hookMethodViaAccess(Navigator.prototype, "share", "HeadlessDetect", "navigator.share");
  }
  if (Navigator.prototype.canShare) {
    hookMethodViaAccess(Navigator.prototype, "canShare", "HeadlessDetect", "navigator.canShare");
  }

  // Window dimensions — headless browsers often have outerWidth/outerHeight = 0
  hookGetter(Window.prototype, "outerWidth", "HeadlessDetect", "window.outerWidth");
  hookGetter(Window.prototype, "outerHeight", "HeadlessDetect", "window.outerHeight");
  hookGetter(Window.prototype, "screenX", "HeadlessDetect", "window.screenX");
  hookGetter(Window.prototype, "screenY", "HeadlessDetect", "window.screenY");
  hookGetter(Window.prototype, "innerWidth", "HeadlessDetect", "window.innerWidth");
  hookGetter(Window.prototype, "innerHeight", "HeadlessDetect", "window.innerHeight");

  // Document visibility — reveals backgrounded tabs, automation patterns
  hookGetter(Document.prototype, "hidden", "HeadlessDetect", "document.hidden");
  hookGetter(Document.prototype, "visibilityState", "HeadlessDetect", "document.visibilityState");

  // ── Anti-spoofing / prototype lie detection ───────────────────────────
  // Sites call Function.prototype.toString on native APIs to verify they
  // haven't been replaced by anti-fingerprinting extensions. If toString
  // returns something other than "[native code]", the environment is spoofed.
  {
    const origToString = Function.prototype.toString;
    let toStringProbed = false;
    Function.prototype.toString = function () {
      const result = origToString.call(this);
      // Only flag when toString is called on browser API prototypes
      // (sites specifically check navigator, canvas, WebGL functions)
      if (!toStringProbed && this !== Function.prototype.toString) {
        const name = this.name || "";
        // Flag calls on known fingerprinted API functions
        if (name === "getImageData" || name === "toDataURL" || name === "getParameter" ||
            name === "getExtension" || name === "getVoices" || name === "enumerateDevices" ||
            name === "getHighEntropyValues" || name === "hardwareConcurrency" ||
            name === "getBattery" || name === "getGamepads") {
          toStringProbed = true;
          record("HeadlessDetect", "Function.prototype.toString", "checking: " + name + " — anti-spoofing probe");
        }
      }
      return result;
    };
  }

  // ── ChromeDriver / automation tool artifacts ──────────────────────────
  // Puppeteer and ChromeDriver leave detectable globals on the window object.
  // We check for their presence at init time.
  {
    const automationGlobals = [
      "cdc_adoQpoasnfa76pfcZLmcfl",  // ChromeDriver
      "__webdriver_evaluate",          // Old WebDriver
      "__selenium_evaluate",           // Selenium
      "__webdriver_script_function",   // WebDriver
      "__webdriver_script_func",       // WebDriver
      "__webdriver_script_fn",         // WebDriver
      "__fxdriver_evaluate",           // Firefox WebDriver
      "__driver_unwrapped",            // WebDriver
      "__webdriver_unwrapped",         // WebDriver
      "__driver_evaluate",             // WebDriver
      "__lastWatirAlert",              // Watir
      "__lastWatirConfirm",            // Watir
      "__lastWatirPrompt",             // Watir
      "_phantom",                      // PhantomJS
      "__nightmare",                   // Nightmare.js
      "_selenium",                     // Selenium
      "callPhantom",                   // PhantomJS
      "callSelenium",                  // Selenium
      "domAutomation",                 // Chrome DevTools protocol
      "domAutomationController",       // Chrome DevTools protocol
    ];

    const found = automationGlobals.filter(g => g in window);
    if (found.length > 0) {
      record("HeadlessDetect", "automation globals detected", found.join(", "));
    }

    // Also check for $cdc_ prefixed properties (ChromeDriver)
    const cdcProps = Object.getOwnPropertyNames(document).filter(p => p.indexOf("$cdc_") === 0);
    if (cdcProps.length > 0) {
      record("HeadlessDetect", "ChromeDriver $cdc_ properties", cdcProps.join(", "));
    }
  }
}
