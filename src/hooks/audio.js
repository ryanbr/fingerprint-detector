// hooks/audio.js — AudioContext fingerprinting detection
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 3. AudioContext Fingerprinting ────────────────────────────────────
  // Audio fingerprinting works by creating an OfflineAudioContext, connecting
  // an oscillator → compressor → analyser chain, rendering audio, then reading
  // the output buffer. Tiny floating-point differences in audio processing
  // produce a unique hash per OS/browser/hardware combo.

  if (typeof AudioContext !== "undefined" || typeof webkitAudioContext !== "undefined") {
    const AudioCtx = typeof AudioContext !== "undefined" ? AudioContext : webkitAudioContext;

    // Constructor — detect AudioContext creation with sample rate
    const OrigAC = AudioCtx;
    window[typeof AudioContext !== "undefined" ? "AudioContext" : "webkitAudioContext"] = function (options) {
      recordHot("Audio", "new AudioContext",
        options && options.sampleRate ? "sampleRate=" + options.sampleRate : "");
      return options ? new OrigAC(options) : new OrigAC();
    };
    window[typeof AudioContext !== "undefined" ? "AudioContext" : "webkitAudioContext"].prototype = OrigAC.prototype;

    // Audio node creation — the fingerprinting pipeline
    hookMethodHot(AudioCtx.prototype, "createOscillator", "Audio", "createOscillator");
    hookMethodHot(AudioCtx.prototype, "createDynamicsCompressor", "Audio", "createDynamicsCompressor");
    hookMethodHot(AudioCtx.prototype, "createAnalyser", "Audio", "createAnalyser");
    hookMethodHot(AudioCtx.prototype, "createGain", "Audio", "createGain");
    hookMethodHot(AudioCtx.prototype, "createBiquadFilter", "Audio", "createBiquadFilter");
    hookMethodHot(AudioCtx.prototype, "createBuffer", "Audio", "createBuffer");
    hookMethodHot(AudioCtx.prototype, "createBufferSource", "Audio", "createBufferSource");
    hookMethodHot(AudioCtx.prototype, "createScriptProcessor", "Audio", "createScriptProcessor");

    // Properties that reveal audio hardware
    hookGetter(AudioCtx.prototype, "sampleRate", "Audio", "audioContext.sampleRate");
    hookGetter(AudioCtx.prototype, "baseLatency", "Audio", "audioContext.baseLatency");
    hookGetter(AudioCtx.prototype, "outputLatency", "Audio", "audioContext.outputLatency");
    hookGetter(AudioCtx.prototype, "destination", "Audio", "audioContext.destination");
    hookGetter(AudioCtx.prototype, "state", "Audio", "audioContext.state");
  }

  // OfflineAudioContext — the primary fingerprinting context
  if (typeof OfflineAudioContext !== "undefined") {
    const OrigOAC = OfflineAudioContext;
    window.OfflineAudioContext = function (channels, length, sampleRate) {
      record("Audio", "new OfflineAudioContext",
        "channels=" + channels + " length=" + length + " sampleRate=" + sampleRate);
      return new OrigOAC(channels, length, sampleRate);
    };
    window.OfflineAudioContext.prototype = OrigOAC.prototype;

    // startRendering — triggers the audio processing that produces the fingerprint
    hookMethod(OfflineAudioContext.prototype, "startRendering", "Audio", "OfflineAudioContext.startRendering");
  }

  // AudioBuffer.getChannelData — reads the rendered audio samples
  // This is the extraction step (like toDataURL for canvas)
  if (typeof AudioBuffer !== "undefined") {
    hookMethod(AudioBuffer.prototype, "getChannelData", "Audio", "AudioBuffer.getChannelData");
    if (AudioBuffer.prototype.copyFromChannel) {
      hookMethod(AudioBuffer.prototype, "copyFromChannel", "Audio", "AudioBuffer.copyFromChannel");
    }
  }

  // AnalyserNode data extraction — frequency/time domain data
  if (typeof AnalyserNode !== "undefined") {
    hookMethodHot(AnalyserNode.prototype, "getFloatFrequencyData", "Audio", "AnalyserNode.getFloatFrequencyData");
    hookMethodHot(AnalyserNode.prototype, "getByteFrequencyData", "Audio", "AnalyserNode.getByteFrequencyData");
    hookMethodHot(AnalyserNode.prototype, "getFloatTimeDomainData", "Audio", "AnalyserNode.getFloatTimeDomainData");
    hookMethodHot(AnalyserNode.prototype, "getByteTimeDomainData", "Audio", "AnalyserNode.getByteTimeDomainData");
  }

  // AudioNode.connect — wiring the fingerprinting chain
  if (typeof AudioNode !== "undefined") {
    hookMethodHot(AudioNode.prototype, "connect", "Audio", "AudioNode.connect");
  }
}
