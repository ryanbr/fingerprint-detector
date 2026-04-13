// hooks/misc.js — Permissions, ClientRects, Plugins, PDF Viewer, Touch, Credentials,
//                  Notification, Math, Architecture, Apple Pay, Private Click Measurement,
//                  TouchEvent creation, Color depth matchMedia
export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 8. Permissions API ────────────────────────────────────────────────
  if (typeof Permissions !== "undefined" && Permissions.prototype.query) {
    // Access-based: Permissions.query returns a promise and frequently
    // gets destructured — keep our frame out of the rejection stack.
    hookMethodViaAccess(Permissions.prototype, "query", "Permissions", "Permissions.query");
  }

  // ── 9. ClientRects Fingerprinting ─────────────────────────────────────
  // Hot path — called 1000s of times by UI frameworks
  hookMethodHot(Element.prototype, "getClientRects", "ClientRects", "getClientRects");
  hookMethodHot(Element.prototype, "getBoundingClientRect", "ClientRects", "getBoundingClientRect");

  // ── 15. Plugin Enumeration ────────────────────────────────────────────
  hookGetter(Navigator.prototype, "plugins", "Plugins", "navigator.plugins");
  hookGetter(Navigator.prototype, "mimeTypes", "Plugins", "navigator.mimeTypes");

  // ── 26. PDF Viewer detection ──────────────────────────────────────────
  hookGetter(Navigator.prototype, "pdfViewerEnabled", "Navigator", "navigator.pdfViewerEnabled");

  // ── 27. Touch support detection ───────────────────────────────────────
  // ontouchstart and TouchEvent presence are commonly probed.
  {
    const touchDesc = Object.getOwnPropertyDescriptor(window, "ontouchstart");
    if (touchDesc) {
      const origGet = touchDesc.get;
      const origSet = touchDesc.set;
      Object.defineProperty(window, "ontouchstart", {
        get() {
          record("Touch", "window.ontouchstart", "get");
          return origGet ? origGet.call(this) : undefined;
        },
        set(v) {
          record("Touch", "window.ontouchstart", "set");
          if (origSet) origSet.call(this, v);
        },
        configurable: true,
        enumerable: true,
      });
    }
  }

  // ── 28. Credential Management ─────────────────────────────────────────
  // All four return promises and are commonly destructured — use
  // access-based to keep the extension out of rejection stacks when
  // a credential prompt is dismissed or a WebAuthn assertion fails.
  if (typeof CredentialsContainer !== "undefined") {
    hookMethodViaAccess(CredentialsContainer.prototype, "get", "Credentials", "credentials.get");
    hookMethodViaAccess(CredentialsContainer.prototype, "create", "Credentials", "credentials.create");
    if (typeof CredentialsContainer.prototype.store === "function") {
      hookMethodViaAccess(CredentialsContainer.prototype, "store", "Credentials", "credentials.store");
    }
    if (typeof CredentialsContainer.prototype.preventSilentAccess === "function") {
      hookMethodViaAccess(CredentialsContainer.prototype, "preventSilentAccess", "Credentials", "credentials.preventSilentAccess");
    }
  }

  // ── 29. Notification permission probe ─────────────────────────────────
  if (typeof Notification !== "undefined") {
    hookGetter(Notification, "permission", "Permissions", "Notification.permission");
  }

  // ── 30. Math Fingerprinting ───────────────────────────────────────────
  // Math functions are called millions of times by normal code. We use
  // recordHot (fire-once) so the wrapper is effectively free after first call.
  {
    const mathFns = [
      "acos", "acosh", "asin", "asinh", "atan", "atanh",
      "cos", "cosh", "exp", "expm1", "log1p",
      "sin", "sinh", "tan", "tanh",
    ];
    for (const fn of mathFns) {
      if (typeof Math[fn] === "function") {
        const orig = Math[fn];
        const label = "Math." + fn;
        Math[fn] = function () {
          recordHot("Math", label, fn);
          return orig.apply(this, arguments);
        };
      }
    }
  }

  // ── 31. Architecture Detection (NaN bit pattern) ──────────────────────
  // FingerprintJS creates NaN via Float32Array and reads the sign bit
  // through a Uint8Array view to distinguish x86 vs ARM.
  {
    const OrigFloat32 = Float32Array;
    const origF32From = Float32Array.from;
    // Hook the constructor — architecture probing always creates new Float32Array(1)
    window.Float32Array = function (arg0, arg1, arg2) {
      if (arg0 === 1) {
        recordHot("Architecture", "new Float32Array", "size=1 (possible NaN bit pattern probe)");
      }
      // Fast path for common constructor signatures
      if (arg2 !== undefined) return new OrigFloat32(arg0, arg1, arg2);
      if (arg1 !== undefined) return new OrigFloat32(arg0, arg1);
      return new OrigFloat32(arg0);
    };
    window.Float32Array.prototype = OrigFloat32.prototype;
    window.Float32Array.BYTES_PER_ELEMENT = OrigFloat32.BYTES_PER_ELEMENT;
    if (origF32From) window.Float32Array.from = origF32From;
    if (OrigFloat32.of) window.Float32Array.of = OrigFloat32.of;
  }

  // ── 35. Apple Pay ─────────────────────────────────────────────────────
  if (typeof window.ApplePaySession !== "undefined") {
    hookMethod(window.ApplePaySession, "canMakePayments", "ApplePay", "ApplePaySession.canMakePayments");
  }

  // ── 36. Private Click Measurement (Safari attribution) ────────────────
  // FingerprintJS reads <a>.attributionSourceId to detect Safari's
  // Privacy Preserving Ad Measurement.
  {
    const aProto = HTMLAnchorElement.prototype;
    for (const prop of ["attributionSourceId", "attributionsourceid"]) {
      const desc = Object.getOwnPropertyDescriptor(aProto, prop);
      if (desc && desc.get) {
        hookGetter(aProto, prop, "PrivateClick", `<a>.${prop}`);
      }
    }
  }

  // ── 42. TouchEvent creation probe ─────────────────────────────────────
  {
    const origCreateEvent = document.createEvent;
    document.createEvent = function (type) {
      if (typeof type === "string" && (type.charCodeAt(0) === 84 || type.charCodeAt(0) === 116) && /touch/i.test(type)) {
        recordHot("Touch", "document.createEvent", type);
      }
      return origCreateEvent.call(this, type);
    };
  }

  // ── 43. Color depth via matchMedia ────────────────────────────────────
  // FingerprintJS probes specific media features. We already hook matchMedia
  // generically (section 20), so those calls will appear in the log.
  // But we also want to flag the high-value fingerprint queries specifically.
  // (Already handled — matchMedia hook captures the query string.)

  // ── 44. document.referrer ─────────────────────────────────────────────
  // Reveals the referring page. Commonly read by analytics, ad
  // networks, and fingerprint scripts for attribution + tracking.
  hookGetter(Document.prototype, "referrer", "Navigator", "document.referrer");

  // ── 45. window.name ───────────────────────────────────────────────────
  // A writable string that persists across same-origin navigations
  // within the same tab. Fingerprint scripts use it as a tracking
  // channel that survives page transitions. Hook both get and set.
  {
    // name is defined on Window.prototype in Chromium
    const proto = typeof Window !== "undefined" ? Window.prototype : null;
    const desc = proto && Object.getOwnPropertyDescriptor(proto, "name");
    if (desc && desc.get && desc.configurable !== false) {
      const origGet = desc.get;
      const origSet = desc.set;
      try {
        Object.defineProperty(proto, "name", {
          configurable: true,
          enumerable: desc.enumerable,
          get() {
            recordHot("Navigator", "window.name", "get (cross-navigation tracking channel)");
            return origGet.call(this);
          },
          set(v) {
            recordHot("Navigator", "window.name", "set");
            if (origSet) origSet.call(this, v);
          },
        });
      } catch { /* non-configurable */ }
    }
  }

  // ── 46. document.hasFocus ─────────────────────────────────────────────
  // Page focus state probing — used for interaction tracking and bot
  // detection. hookMethodHot self-unwraps after first fire so animation
  // loops that poll focus state pay no ongoing overhead.
  if (Document.prototype.hasFocus) {
    hookMethodHot(Document.prototype, "hasFocus", "HeadlessDetect", "document.hasFocus");
  }
}
