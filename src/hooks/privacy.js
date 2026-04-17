// hooks/privacy.js — Do Not Track, Headless/automation detection, anti-spoofing
export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent, fnWrapperMap }) {
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

  // Secure context detection — FingerprintJS reads this to branch
  // detection logic based on HTTPS vs HTTP.
  hookGetter(Window.prototype, "isSecureContext", "HeadlessDetect", "window.isSecureContext");

  // Fullscreen state — page state detection used alongside
  // fingerprinting for anti-embedding / frame-busting.
  hookGetter(Document.prototype, "fullscreenElement", "HeadlessDetect", "document.fullscreenElement");
  if (Object.getOwnPropertyDescriptor(Document.prototype, "fullscreenEnabled")) {
    hookGetter(Document.prototype, "fullscreenEnabled", "HeadlessDetect", "document.fullscreenEnabled");
  }

  // ── Anti-spoofing / prototype lie detection + counter-spoofing ───────
  // Sites call Function.prototype.toString on native APIs to verify
  // they haven't been replaced by anti-fingerprinting extensions. If
  // toString returns something other than "[native code]", the
  // environment is flagged as spoofed (seen on accounts.google.com:
  // "This browser or app may not be secure").
  //
  // We do TWO things here:
  // 1. Detect the probe — record it so the user knows the site is
  //    checking.
  // 2. Spoof the response — if `this` is one of our wrapper functions
  //    (looked up in fnWrapperMap), return the NATIVE toString of the
  //    wrapped original, not our wrapper source. This makes our hooks
  //    transparent to toString-based tamper detection.
  {
    const origToString = Function.prototype.toString;
    let toStringProbed = false;
    const newToString = function () {
      // Resolve effective target: if `this` is our wrapper, get the
      // native fn we wrapped; otherwise use `this` directly.
      const orig = fnWrapperMap && fnWrapperMap.get(this);
      const effective = orig || this;
      // Detection: flag probes on well-known fingerprint API functions.
      // Check the effective (native) fn's name since our wrappers are
      // anonymous (name === "").
      if (!toStringProbed && this !== newToString) {
        const name = (effective && effective.name) || "";
        if (name === "getImageData" || name === "toDataURL" || name === "getParameter" ||
            name === "getExtension" || name === "getVoices" || name === "enumerateDevices" ||
            name === "getHighEntropyValues" || name === "hardwareConcurrency" ||
            name === "getBattery" || name === "getGamepads") {
          toStringProbed = true;
          record("HeadlessDetect", "Function.prototype.toString", "checking: " + name + " — anti-spoofing probe");
        }
      }
      // Spoof: return the effective fn's toString (native source for
      // wrapped fns, normal behavior for everything else).
      return origToString.call(effective);
    };
    // Register our newToString itself so Function.prototype.toString
    // .toString() returns the native toString signature instead of our
    // wrapper source — otherwise sites could detect us via the meta
    // check `Function.prototype.toString.toString()`.
    if (fnWrapperMap) fnWrapperMap.set(newToString, origToString);
    // Spoof .name / .length on the wrapper to match native toString.
    // Without this, sites can detect us via
    //   Function.prototype.toString.name === "toString"
    // check (our wrapper would otherwise be "newToString").
    try { Object.defineProperty(newToString, "name", { value: "toString", configurable: true }); } catch { /* non-configurable */ }
    try { Object.defineProperty(newToString, "length", { value: 0, configurable: true }); } catch { /* non-configurable */ }
    Function.prototype.toString = newToString;
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
