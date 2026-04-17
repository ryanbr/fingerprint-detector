// hooks/navigator.js — Navigator/UA fingerprinting, Workers, SharedArrayBuffer, Atomics
export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 4. Navigator / UA Fingerprinting ──────────────────────────────────
  const navProps = [
    // Core UA strings
    "userAgent", "appVersion", "appName", "appCodeName", "product",
    // Platform/hardware
    "platform", "oscpu", "cpuClass",
    // Language
    "language", "languages",
    // Hardware capabilities
    "hardwareConcurrency", "deviceMemory", "maxTouchPoints",
    // Vendor
    "vendor", "productSub", "vendorSub",
    // Firefox-specific
    "buildID",
    // Connection object access
    "connection",
    // Online state — FingerprintJS reads this as a low-entropy signal
    "onLine",
  ];
  for (const prop of navProps) {
    hookGetter(Navigator.prototype, prop, "Navigator", "navigator." + prop);
  }
  // Access-based: getBattery is commonly destructured; we don't want the
  // wrapper in the stack when page code calls it with wrong `this`.
  hookMethodViaAccess(Navigator.prototype, "getBattery", "Navigator", "navigator.getBattery");
  if (Navigator.prototype.getGamepads) {
    hookMethod(Navigator.prototype, "getGamepads", "Navigator", "navigator.getGamepads");
  }
  // Legacy probes
  if (Navigator.prototype.javaEnabled) {
    hookMethod(Navigator.prototype, "javaEnabled", "Navigator", "navigator.javaEnabled");
  }
  if (Navigator.prototype.taintEnabled) {
    hookMethod(Navigator.prototype, "taintEnabled", "Navigator", "navigator.taintEnabled");
  }
  // Worker creation — sites run fingerprinting in Workers to cross-check
  // UA/hardwareConcurrency against main thread (detects spoofing).
  // Also detects timing-based core counting via Worker pool spawning.
  if (typeof Worker !== "undefined") {
    const OrigWorker = Worker;
    let workerCount = 0;
    let workerBurstStart = 0;
    const WORKER_BURST_WINDOW = 2000;
    const WORKER_BURST_THRESHOLD = 4; // > typical app usage = probing
    let workerBurstReported = false;

    window.Worker = function (url, opts) {
      const urlStr = typeof url === "string" ? url : "";
      const now = Date.now();

      if (now - workerBurstStart > WORKER_BURST_WINDOW) {
        workerCount = 0;
        workerBurstStart = now;
      }
      workerCount++;

      if (workerCount === 1) {
        record("Navigator", "new Worker", urlStr);
      }
      if (workerCount >= WORKER_BURST_THRESHOLD && !workerBurstReported) {
        workerBurstReported = true;
        record("Navigator", "Worker pool burst",
          workerCount + " workers in " + WORKER_BURST_WINDOW +
          "ms (possible hardware concurrency probing)");
      }

      return opts ? new OrigWorker(url, opts) : new OrigWorker(url);
    };
    window.Worker.prototype = OrigWorker.prototype;
  }
  if (typeof SharedWorker !== "undefined") {
    const OrigSW = SharedWorker;
    window.SharedWorker = function (url, opts) {
      recordHot("Navigator", "new SharedWorker", typeof url === "string" ? url : "");
      return opts ? new OrigSW(url, opts) : new OrigSW(url);
    };
    window.SharedWorker.prototype = OrigSW.prototype;
  }

  // ServiceWorker — registration reveals PWA state, getRegistrations
  // enumerates installed SWs (browsing history signal), and SWs can run
  // fingerprinting code in a separate context to cross-validate values.
  //
  // IMPORTANT: We hook ServiceWorkerContainer.prototype directly without
  // ever accessing navigator.serviceWorker. Sandboxed iframes (lacking
  // allow-same-origin) throw SecurityError on navigator.serviceWorker
  // access — even inside try/catch in some execution contexts. The
  // prototype is always accessible regardless of sandbox state.
  if (typeof ServiceWorkerContainer !== "undefined" &&
      typeof ServiceWorkerContainer.prototype === "object") {
    // Access-based: all three return promises and frequently lose
    // `this` when used via destructuring.
    hookMethodViaAccess(ServiceWorkerContainer.prototype, "register", "Navigator", "serviceWorker.register");
    hookMethodViaAccess(ServiceWorkerContainer.prototype, "getRegistrations", "Navigator", "serviceWorker.getRegistrations");
    hookMethodViaAccess(ServiceWorkerContainer.prototype, "getRegistration", "Navigator", "serviceWorker.getRegistration");
    hookGetter(ServiceWorkerContainer.prototype, "ready", "Navigator", "serviceWorker.ready");
    hookGetter(ServiceWorkerContainer.prototype, "controller", "Navigator", "serviceWorker.controller");
  }

  // Cache API — caches.keys() enumerates cache names which can reveal
  // browsing history, installed PWAs, and previously visited sites.
  if (typeof CacheStorage !== "undefined") {
    hookMethod(CacheStorage.prototype, "keys", "Storage", "caches.keys");
    hookMethod(CacheStorage.prototype, "open", "Storage", "caches.open");
    hookMethod(CacheStorage.prototype, "has", "Storage", "caches.has");
    hookMethod(CacheStorage.prototype, "match", "Storage", "caches.match");
  }

  // SharedArrayBuffer + Atomics — used for timing-based core counting.
  // Sites create SABs and use Atomics.wait/notify across Workers to
  // measure parallel execution throughput, inferring actual core count
  // even when hardwareConcurrency is spoofed.
  if (typeof SharedArrayBuffer !== "undefined") {
    const OrigSAB = SharedArrayBuffer;
    window.SharedArrayBuffer = function (length) {
      recordHot("Navigator", "new SharedArrayBuffer",
        "size=" + length + " (possible timing-based core counting)");
      return new OrigSAB(length);
    };
    window.SharedArrayBuffer.prototype = OrigSAB.prototype;
  }
  if (typeof Atomics !== "undefined") {
    const atomicMethods = ["wait", "notify", "waitAsync"];
    for (const method of atomicMethods) {
      if (typeof Atomics[method] === "function") {
        const orig = Atomics[method];
        Atomics[method] = function () {
          recordHot("Navigator", "Atomics." + method,
            "cross-worker synchronization (core counting)");
          return orig.apply(this, arguments);
        };
      }
    }
  }
}
