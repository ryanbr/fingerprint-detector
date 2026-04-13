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

  // ── MediaDevices: camera / mic / screen capture ───────────────────────
  // Complements MediaDevices.enumerateDevices (hooked in media.js).
  // All four return promises and are commonly destructured; using
  // access-based keeps our frame out of rejection stacks if the user
  // denies the permission prompt or the device is unavailable.
  if (typeof MediaDevices !== "undefined") {
    if (typeof MediaDevices.prototype.getUserMedia === "function") {
      hookMethodViaAccess(MediaDevices.prototype, "getUserMedia", "Permissions", "mediaDevices.getUserMedia");
    }
    if (typeof MediaDevices.prototype.getDisplayMedia === "function") {
      hookMethodViaAccess(MediaDevices.prototype, "getDisplayMedia", "Permissions", "mediaDevices.getDisplayMedia");
    }
    if (typeof MediaDevices.prototype.selectAudioOutput === "function") {
      hookMethodViaAccess(MediaDevices.prototype, "selectAudioOutput", "Permissions", "mediaDevices.selectAudioOutput");
    }
    if (typeof MediaDevices.prototype.getSupportedConstraints === "function") {
      hookMethodViaAccess(MediaDevices.prototype, "getSupportedConstraints", "Permissions", "mediaDevices.getSupportedConstraints");
    }
  }

  // ── File System Access API ────────────────────────────────────────────
  // showOpenFilePicker / showSaveFilePicker / showDirectoryPicker —
  // all prompt the user for local file/directory access. Very high
  // privacy signal. Defined on Window.prototype in Chromium.
  if (typeof Window !== "undefined") {
    if (typeof Window.prototype.showOpenFilePicker === "function") {
      hookMethodViaAccess(Window.prototype, "showOpenFilePicker", "Permissions", "window.showOpenFilePicker");
    }
    if (typeof Window.prototype.showSaveFilePicker === "function") {
      hookMethodViaAccess(Window.prototype, "showSaveFilePicker", "Permissions", "window.showSaveFilePicker");
    }
    if (typeof Window.prototype.showDirectoryPicker === "function") {
      hookMethodViaAccess(Window.prototype, "showDirectoryPicker", "Permissions", "window.showDirectoryPicker");
    }
  }
  // FileSystemHandle.requestPermission / queryPermission — called on
  // individual handles after the picker resolves. Both return promises.
  if (typeof FileSystemHandle !== "undefined") {
    if (typeof FileSystemHandle.prototype.requestPermission === "function") {
      hookMethodViaAccess(FileSystemHandle.prototype, "requestPermission", "Permissions", "FileSystemHandle.requestPermission");
    }
    if (typeof FileSystemHandle.prototype.queryPermission === "function") {
      hookMethodViaAccess(FileSystemHandle.prototype, "queryPermission", "Permissions", "FileSystemHandle.queryPermission");
    }
  }

  // ── WebAuthn capability detection ─────────────────────────────────────
  // PublicKeyCredential static methods that reveal biometric hardware
  // and passkey support. Both return promises.
  if (typeof PublicKeyCredential !== "undefined") {
    if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
      hookMethodViaAccess(PublicKeyCredential, "isUserVerifyingPlatformAuthenticatorAvailable", "Permissions", "PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable");
    }
    if (typeof PublicKeyCredential.isConditionalMediationAvailable === "function") {
      hookMethodViaAccess(PublicKeyCredential, "isConditionalMediationAvailable", "Permissions", "PublicKeyCredential.isConditionalMediationAvailable");
    }
  }

  // ── Payment Request API ───────────────────────────────────────────────
  // new PaymentRequest(methods, details) — initiates a payment flow.
  // show() opens the native payment sheet; canMakePayment() is a pure
  // capability probe that doesn't prompt the user.
  if (typeof PaymentRequest !== "undefined") {
    // Instance methods (access-based: show returns a promise)
    if (typeof PaymentRequest.prototype.show === "function") {
      hookMethodViaAccess(PaymentRequest.prototype, "show", "Permissions", "PaymentRequest.show");
    }
    if (typeof PaymentRequest.prototype.canMakePayment === "function") {
      hookMethodViaAccess(PaymentRequest.prototype, "canMakePayment", "Permissions", "PaymentRequest.canMakePayment");
    }
    // Constructor wrap — fire-once recording, since the constructor
    // itself is a strong signal that a payment flow is starting.
    const OrigPR = PaymentRequest;
    try {
      window.PaymentRequest = function (methods, details, options) {
        recordHot("Permissions", "new PaymentRequest", "");
        return options ? new OrigPR(methods, details, options) : new OrigPR(methods, details);
      };
      window.PaymentRequest.prototype = OrigPR.prototype;
      for (const k of Object.getOwnPropertyNames(OrigPR)) {
        if (k === "length" || k === "name" || k === "prototype") continue;
        try {
          const d = Object.getOwnPropertyDescriptor(OrigPR, k);
          if (d) Object.defineProperty(window.PaymentRequest, k, d);
        } catch { /* skip */ }
      }
    } catch { /* non-writable */ }
  }

  // ── iOS Sensor permissions (iOS 13+) ──────────────────────────────────
  // DeviceOrientationEvent.requestPermission() and DeviceMotionEvent
  // .requestPermission() are static methods that Safari requires for
  // accelerometer/gyroscope access. Calling either is also a strong
  // "site detects iOS Safari" signal — these methods are undefined
  // on desktop Chrome, so sites use feature detection as a UA probe.
  if (typeof DeviceOrientationEvent !== "undefined" &&
      typeof DeviceOrientationEvent.requestPermission === "function") {
    hookMethodViaAccess(DeviceOrientationEvent, "requestPermission", "Permissions", "DeviceOrientationEvent.requestPermission");
  }
  if (typeof DeviceMotionEvent !== "undefined" &&
      typeof DeviceMotionEvent.requestPermission === "function") {
    hookMethodViaAccess(DeviceMotionEvent, "requestPermission", "Permissions", "DeviceMotionEvent.requestPermission");
  }

  // ── Web MIDI ──────────────────────────────────────────────────────────
  // navigator.requestMIDIAccess() returns a promise that resolves with
  // a MIDIAccess object if the user grants the permission. Reveals
  // MIDI hardware (attached synths, controllers).
  if (typeof Navigator !== "undefined" &&
      typeof Navigator.prototype.requestMIDIAccess === "function") {
    hookMethodViaAccess(Navigator.prototype, "requestMIDIAccess", "Permissions", "navigator.requestMIDIAccess");
  }
}
