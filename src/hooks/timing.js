// hooks/timing.js — Performance Timing, high-res timers, hardware benchmarking
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 22. Performance Timing ────────────────────────────────────────────
  // High-resolution timers are used for:
  // - Timing attacks (cache probing, keystroke timing)
  // - Hardware fingerprinting (benchmark GPU/CPU speed)
  // - Timer precision detection (privacy browsers reduce resolution)

  // performance.now — called 1000s of times/sec by frameworks
  hookMethodHot(Performance.prototype, "now", "Timing", "performance.now");

  // Performance entries — resource/navigation/paint timing data
  if (Performance.prototype.getEntries) {
    hookMethodHot(Performance.prototype, "getEntries", "Timing", "performance.getEntries");
    hookMethodHot(Performance.prototype, "getEntriesByType", "Timing", "performance.getEntriesByType");
    hookMethodHot(Performance.prototype, "getEntriesByName", "Timing", "performance.getEntriesByName");
  }

  // performance.mark / measure — sites benchmark operations to profile hardware
  if (Performance.prototype.mark) {
    hookMethodHot(Performance.prototype, "mark", "Timing", "performance.mark");
  }
  if (Performance.prototype.measure) {
    hookMethodHot(Performance.prototype, "measure", "Timing", "performance.measure");
  }

  // performance.timeOrigin — high-precision page start timestamp
  hookGetter(Performance.prototype, "timeOrigin", "Timing", "performance.timeOrigin");

  // Navigation Timing L1 (deprecated but still probed)
  // performance.timing reveals detailed page load timing characteristics
  hookGetter(Performance.prototype, "timing", "Timing", "performance.timing");
  hookGetter(Performance.prototype, "navigation", "Timing", "performance.navigation");

  // performance.memory (Chrome-only) — reveals heap size / memory limits
  // jsHeapSizeLimit varies by device RAM, making it a hardware fingerprint
  {
    const memDesc = Object.getOwnPropertyDescriptor(Performance.prototype, "memory");
    if (memDesc && memDesc.get) {
      const origGet = memDesc.get;
      Object.defineProperty(Performance.prototype, "memory", {
        ...memDesc,
        get() {
          recordHot("Timing", "performance.memory", "heap size / memory limits");
          return origGet.call(this);
        },
      });
    }
  }

  // PerformanceObserver — async performance data collection
  if (typeof PerformanceObserver !== "undefined") {
    const OrigPO = PerformanceObserver;
    window.PerformanceObserver = function (callback) {
      recordHot("Timing", "new PerformanceObserver", "");
      return new OrigPO(callback);
    };
    window.PerformanceObserver.prototype = OrigPO.prototype;
    if (OrigPO.supportedEntryTypes) {
      Object.defineProperty(window.PerformanceObserver, "supportedEntryTypes", {
        get: () => OrigPO.supportedEntryTypes,
      });
    }
  }
}
