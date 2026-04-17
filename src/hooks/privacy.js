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

  // navigator.userActivation — classic automation / bot detection.
  // Bots typically have hasBeenActive === false even on apparently-
  // loaded pages since they don't dispatch real user gestures.
  if (typeof UserActivation !== "undefined") {
    hookGetter(UserActivation.prototype, "isActive", "HeadlessDetect", "navigator.userActivation.isActive");
    hookGetter(UserActivation.prototype, "hasBeenActive", "HeadlessDetect", "navigator.userActivation.hasBeenActive");
  }

  // document.currentScript — returns the currently-executing <script>
  // element. Fingerprinting scripts read this to self-identify their
  // own loader URL and configure themselves. Legitimate apps rarely
  // access it outside of polyfills.
  hookGetter(Document.prototype, "currentScript", "HeadlessDetect", "document.currentScript");

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

  // ── Object.prototype.toString probe detection ────────────────────────
  // Anti-bot libraries (Akamai Bot Manager in particular) call
  // Object.prototype.toString.call(window) / .call(navigator) /
  // .call(document) to detect if any of those have been wrapped in a
  // Proxy — a Proxy would return "[object Object]" instead of the
  // expected "[object Window]" / etc.
  //
  // Object.prototype.toString is extremely hot (called by
  // JSON.stringify, template literals, Array.prototype.join, and many
  // libraries' type-check utilities). So we:
  // 1. Only report + self-unwrap on the first probe that hits a
  //    fingerprint-relevant target (window/navigator/document).
  // 2. Hard-deadline unwrap after 5s regardless — if no probe fires
  //    in that window, restore the native to stop paying wrapper
  //    overhead on hot paths.
  // 3. Register the wrapper in fnWrapperMap + fake name/length so
  //    the override itself is invisible to tamper checks.
  {
    const origOT = Object.prototype.toString;
    let fired = false;
    const newOT = function () {
      if (!fired && (this === window || this === navigator || this === document)) {
        fired = true;
        const targetName = this === window ? "window" :
                           this === navigator ? "navigator" : "document";
        record("HeadlessDetect", "Object.prototype.toString probe",
          "called on " + targetName + " — proxy-tamper detection");
        // Self-unwrap on successful detection
        try {
          if (Object.prototype.toString === newOT) {
            Object.prototype.toString = origOT;
          }
        } catch { /* non-writable */ }
      }
      return origOT.call(this);
    };
    if (fnWrapperMap) fnWrapperMap.set(newOT, origOT);
    try { Object.defineProperty(newOT, "name", { value: "toString", configurable: true }); } catch { /* noop */ }
    try { Object.defineProperty(newOT, "length", { value: 0, configurable: true }); } catch { /* noop */ }
    try { Object.prototype.toString = newOT; } catch { /* noop */ }
    // Hard-deadline unwrap — even if no probe fired, restore native
    // so hot paths (JSON.stringify, template literals, etc.) aren't
    // paying per-call wrapper overhead for the remainder of the page.
    setTimeout(() => {
      try {
        if (Object.prototype.toString === newOT) {
          Object.prototype.toString = origOT;
        }
      } catch { /* noop */ }
    }, 5000);
  }

  // ── Error.stack / Error.captureStackTrace engine fingerprinting ──────
  // Anti-bot libraries read stack traces and inspect the format to
  // identify the JS engine (V8 uses "    at X (url:line:col)",
  // SpiderMonkey and JSC use "X@url:line:col"). Sites compare the
  // inferred engine against navigator.userAgent to detect spoofing.
  //
  // Two detection paths to cover both engine families:
  //
  // 1. Firefox / Safari: Error.prototype.stack is an own accessor on
  //    Error.prototype — hookGetter catches every read.
  // 2. V8 (Chrome / Edge): stack is set per-instance lazily via C++
  //    APIs, so Error.prototype.stack has no JS-visible accessor and
  //    hookGetter(1) silently bails. Instead we hook the JS-visible
  //    Error.captureStackTrace static method — fingerprint scripts
  //    that want consistent cross-engine behavior call this
  //    explicitly (V8's internal new Error() path does NOT go
  //    through this function, so we only catch explicit JS calls,
  //    which is exactly the signal we want).
  {
    const stackDesc = Object.getOwnPropertyDescriptor(Error.prototype, "stack");
    if (stackDesc && stackDesc.get) {
      hookGetter(Error.prototype, "stack", "HeadlessDetect", "Error.stack");
    }
    // V8-only — Error.captureStackTrace is Chrome/Edge-specific
    if (typeof Error.captureStackTrace === "function") {
      hookMethodHot(Error, "captureStackTrace", "HeadlessDetect", "Error.captureStackTrace");
    }
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
