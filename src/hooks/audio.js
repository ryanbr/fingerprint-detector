// hooks/audio.js — AudioContext fingerprinting detection
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 3. AudioContext Fingerprinting ────────────────────────────────────
  if (typeof AudioContext !== "undefined" || typeof webkitAudioContext !== "undefined") {
    const AudioCtx = typeof AudioContext !== "undefined" ? AudioContext : webkitAudioContext;
    hookMethod(AudioCtx.prototype, "createOscillator", "Audio", "createOscillator");
    hookMethod(AudioCtx.prototype, "createDynamicsCompressor", "Audio", "createDynamicsCompressor");
    hookMethod(AudioCtx.prototype, "createAnalyser", "Audio", "createAnalyser");
    if (typeof OfflineAudioContext !== "undefined") {
      hookMethod(OfflineAudioContext.prototype, "startRendering", "Audio", "OfflineAudioContext.startRendering");
    }
  }

  // ── 40. AudioContext.baseLatency ───────────────────────────────────────
  if (typeof AudioContext !== "undefined") {
    hookGetter(AudioContext.prototype, "baseLatency", "Audio", "audioContext.baseLatency");
  }
}
