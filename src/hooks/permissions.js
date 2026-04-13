// hooks/permissions.js — Notification, Clipboard, Geolocation, Wake Lock,
// Idle Detection, Badging API, Push API — permission probing and
// capability detection.
//
// Detection philosophy: all of these APIs reveal user consent state
// or device capability, which is high-entropy fingerprinting signal.
// The user doesn't have to accept the prompt — simply *asking* reveals
// that the site is probing, and the returned permission state
// (granted / denied / default / prompt) partitions the user base.
//
// All promise-returning methods use hookMethodViaAccess so the
// extension isn't in the call stack when page code calls them with
// destructured references (standard Web IDL "Illegal invocation"
// avoidance pattern).

export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── Notification API ──────────────────────────────────────────────────
  if (typeof Notification !== "undefined") {
    // requestPermission — triggers the prompt or returns cached answer
    hookMethodViaAccess(Notification, "requestPermission", "Permissions", "Notification.requestPermission");

    // maxActions — static integer that varies by browser/OS version
    const maxActionsDesc = Object.getOwnPropertyDescriptor(Notification, "maxActions");
    if (maxActionsDesc && maxActionsDesc.get) {
      const origGet = maxActionsDesc.get;
      try {
        Object.defineProperty(Notification, "maxActions", {
          ...maxActionsDesc,
          get() {
            recordHot("Permissions", "Notification.maxActions", "static integer varies by browser/OS");
            return origGet.call(this);
          },
        });
      } catch { /* non-configurable */ }
    }

    // new Notification(title, options) — real notification creation.
    // Fire-once recording via recordHot; skip the constructor wrap
    // itself since it would put us in the stack for every instantiation.
    // Instead we detect via a Proxy-like approach: hook the prototype's
    // `close` method which fires right after construction, or simply
    // accept a constructor wrap since Notification isn't called at
    // high frequency.
    const OrigNotification = Notification;
    try {
      window.Notification = function (title, options) {
        recordHot("Permissions", "new Notification", typeof title === "string" ? title.slice(0, 60) : "");
        return options ? new OrigNotification(title, options) : new OrigNotification(title);
      };
      // Preserve static properties (permission, maxActions, requestPermission)
      window.Notification.prototype = OrigNotification.prototype;
      for (const k of Object.getOwnPropertyNames(OrigNotification)) {
        if (k === "length" || k === "name" || k === "prototype") continue;
        try {
          const d = Object.getOwnPropertyDescriptor(OrigNotification, k);
          if (d) Object.defineProperty(window.Notification, k, d);
        } catch { /* skip non-transferable */ }
      }
    } catch { /* non-writable global */ }
  }

  // ── ServiceWorkerRegistration: showNotification / getNotifications ────
  // Persistent notifications routed through the service worker. Different
  // permission model from window Notification, so worth tracking
  // separately.
  if (typeof ServiceWorkerRegistration !== "undefined") {
    hookMethodViaAccess(ServiceWorkerRegistration.prototype, "showNotification", "Permissions", "serviceWorker.showNotification");
    hookMethodViaAccess(ServiceWorkerRegistration.prototype, "getNotifications", "Permissions", "serviceWorker.getNotifications");
  }

  // ── Push API ──────────────────────────────────────────────────────────
  // pushManager.subscribe / getSubscription reveal push permission state
  // and the subscription endpoint URL (if granted).
  if (typeof PushManager !== "undefined") {
    hookMethodViaAccess(PushManager.prototype, "subscribe", "Permissions", "pushManager.subscribe");
    hookMethodViaAccess(PushManager.prototype, "getSubscription", "Permissions", "pushManager.getSubscription");
    hookMethodViaAccess(PushManager.prototype, "permissionState", "Permissions", "pushManager.permissionState");
  }

  // ── Clipboard API ─────────────────────────────────────────────────────
  // All four methods return promises and require the clipboard-read or
  // clipboard-write permission. Sites probe these to detect permission
  // state; we flag any access.
  if (typeof Clipboard !== "undefined") {
    hookMethodViaAccess(Clipboard.prototype, "read", "Permissions", "clipboard.read");
    hookMethodViaAccess(Clipboard.prototype, "readText", "Permissions", "clipboard.readText");
    hookMethodViaAccess(Clipboard.prototype, "write", "Permissions", "clipboard.write");
    hookMethodViaAccess(Clipboard.prototype, "writeText", "Permissions", "clipboard.writeText");
  }

  // ── Geolocation API ───────────────────────────────────────────────────
  // High-value fingerprinting/tracking surface. The methods are
  // synchronous (they return undefined and call callbacks), so use
  // hookMethodHot for fire-once logging that self-unwraps.
  if (typeof Geolocation !== "undefined") {
    hookMethodHot(Geolocation.prototype, "getCurrentPosition", "Permissions", "geolocation.getCurrentPosition");
    hookMethodHot(Geolocation.prototype, "watchPosition", "Permissions", "geolocation.watchPosition");
    hookMethodHot(Geolocation.prototype, "clearWatch", "Permissions", "geolocation.clearWatch");
  }

  // ── Wake Lock API ─────────────────────────────────────────────────────
  // navigator.wakeLock.request('screen') — prevents display sleep and
  // reveals the Screen Wake Lock permission state.
  if (typeof WakeLock !== "undefined") {
    hookMethodViaAccess(WakeLock.prototype, "request", "Permissions", "wakeLock.request");
  }

  // ── Idle Detection API ────────────────────────────────────────────────
  // IdleDetector.requestPermission() + new IdleDetector() — very
  // privacy-sensitive. Reveals whether the user is present at their
  // device.
  if (typeof IdleDetector !== "undefined") {
    hookMethodViaAccess(IdleDetector, "requestPermission", "Permissions", "IdleDetector.requestPermission");
    // Constructor wrap — fire-once
    const OrigID = IdleDetector;
    try {
      window.IdleDetector = function (opts) {
        recordHot("Permissions", "new IdleDetector", "");
        return opts ? new OrigID(opts) : new OrigID();
      };
      window.IdleDetector.prototype = OrigID.prototype;
      for (const k of Object.getOwnPropertyNames(OrigID)) {
        if (k === "length" || k === "name" || k === "prototype") continue;
        try {
          const d = Object.getOwnPropertyDescriptor(OrigID, k);
          if (d) Object.defineProperty(window.IdleDetector, k, d);
        } catch { /* skip */ }
      }
    } catch { /* non-writable */ }
  }

  // ── Badging API ───────────────────────────────────────────────────────
  // navigator.setAppBadge() / clearAppBadge() — reveals PWA install state.
  // Both return promises.
  if (typeof Navigator !== "undefined") {
    if (typeof Navigator.prototype.setAppBadge === "function") {
      hookMethodViaAccess(Navigator.prototype, "setAppBadge", "Permissions", "navigator.setAppBadge");
    }
    if (typeof Navigator.prototype.clearAppBadge === "function") {
      hookMethodViaAccess(Navigator.prototype, "clearAppBadge", "Permissions", "navigator.clearAppBadge");
    }
  }
}
