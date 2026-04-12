// hooks/timing.js — Performance Timing hooks
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 22. Performance Timing ────────────────────────────────────────────
  // High-resolution timers can be used for timing attacks and hardware fingerprinting.
  // Hot path — called 1000s of times per second by frameworks/animations
  hookMethodHot(Performance.prototype, "now", "Timing", "performance.now");
  if (Performance.prototype.getEntries) {
    hookMethodHot(Performance.prototype, "getEntries", "Timing", "performance.getEntries");
    hookMethodHot(Performance.prototype, "getEntriesByType", "Timing", "performance.getEntriesByType");
    hookMethodHot(Performance.prototype, "getEntriesByName", "Timing", "performance.getEntriesByName");
  }
  if (typeof PerformanceObserver !== "undefined") {
    const OrigPO = PerformanceObserver;
    window.PerformanceObserver = function (callback) {
      record("Timing", "new PerformanceObserver", "");
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
