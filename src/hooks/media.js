// hooks/media.js — MediaDevices, SpeechSynthesis, matchMedia
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 12. Media Devices ─────────────────────────────────────────────────
  if (typeof MediaDevices !== "undefined" && MediaDevices.prototype.enumerateDevices) {
    hookMethod(MediaDevices.prototype, "enumerateDevices", "MediaDevices", "enumerateDevices");
  }

  // ── 13. Speech Synthesis (voice enumeration) ──────────────────────────
  // Sites enumerate installed TTS voices — the list varies by OS, language
  // packs, and browser. Some sites also speak silently at volume 0 and
  // measure timing differences across voices.
  if (typeof speechSynthesis !== "undefined") {
    hookMethod(speechSynthesis, "getVoices", "SpeechSynthesis", "getVoices");
    hookMethodHot(speechSynthesis, "speak", "SpeechSynthesis", "speechSynthesis.speak");
    hookMethodHot(speechSynthesis, "cancel", "SpeechSynthesis", "speechSynthesis.cancel");

    // onvoiceschanged — sites listen for this to trigger getVoices()
    const ovDesc = Object.getOwnPropertyDescriptor(speechSynthesis, "onvoiceschanged") ||
                   Object.getOwnPropertyDescriptor(SpeechSynthesis.prototype, "onvoiceschanged");
    if (ovDesc && ovDesc.set) {
      const origSet = ovDesc.set;
      Object.defineProperty(speechSynthesis, "onvoiceschanged", {
        get: ovDesc.get ? ovDesc.get.bind(speechSynthesis) : undefined,
        set(handler) {
          recordHot("SpeechSynthesis", "onvoiceschanged", "listener set");
          return origSet.call(this, handler);
        },
        configurable: true,
        enumerable: true,
      });
    }

    // State property checks
    for (const prop of ["pending", "speaking", "paused"]) {
      hookGetter(SpeechSynthesis.prototype, prop, "SpeechSynthesis", "speechSynthesis." + prop);
    }
  }

  // SpeechSynthesisUtterance — creating utterances to probe voice/lang support
  if (typeof SpeechSynthesisUtterance !== "undefined") {
    const OrigSSU = SpeechSynthesisUtterance;
    window.SpeechSynthesisUtterance = function (text) {
      recordHot("SpeechSynthesis", "new SpeechSynthesisUtterance", "");
      return text !== undefined ? new OrigSSU(text) : new OrigSSU();
    };
    window.SpeechSynthesisUtterance.prototype = OrigSSU.prototype;

    // voice and lang setters — reveals which voices/languages are being tested
    const voiceDesc = Object.getOwnPropertyDescriptor(OrigSSU.prototype, "voice");
    if (voiceDesc && voiceDesc.set) {
      const origSet = voiceDesc.set;
      Object.defineProperty(OrigSSU.prototype, "voice", {
        ...voiceDesc,
        set(v) {
          record("SpeechSynthesis", "utterance.voice =", v && v.name ? v.name : "");
          return origSet.call(this, v);
        },
      });
    }
    const langDesc = Object.getOwnPropertyDescriptor(OrigSSU.prototype, "lang");
    if (langDesc && langDesc.set) {
      const origSet = langDesc.set;
      Object.defineProperty(OrigSSU.prototype, "lang", {
        ...langDesc,
        set(v) {
          record("SpeechSynthesis", "utterance.lang =", v || "");
          return origSet.call(this, v);
        },
      });
    }
  }

  // ── 20. matchMedia (CSS media query probing) ──────────────────────────
  // Sites probe prefers-color-scheme, prefers-reduced-motion, display-mode,
  // forced-colors, etc. to build a media feature fingerprint.
  {
    const origMatchMedia = window.matchMedia;
    if (typeof origMatchMedia === "function") {
      window.matchMedia = function (query) {
        record("MediaQuery", "matchMedia", query);
        return origMatchMedia.call(this, query);
      };
    }
  }
}
