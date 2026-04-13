// Fingerprint Detector — injected into page MAIN world at document_start
// Entry point: core infrastructure + imports all hook modules.
// Built into dist/inject.js via esbuild before packaging.

import { register as canvas } from './hooks/canvas.js';
import { register as webgl } from './hooks/webgl.js';
import { register as audio } from './hooks/audio.js';
import { register as navigator_ } from './hooks/navigator.js';
import { register as vendor } from './hooks/vendor.js';
import { register as clientHints } from './hooks/client-hints.js';
import { register as screen_ } from './hooks/screen.js';
import { register as fonts } from './hooks/fonts.js';
import { register as webrtc } from './hooks/webrtc.js';
import { register as network } from './hooks/network.js';
import { register as media } from './hooks/media.js';
import { register as storage } from './hooks/storage.js';
import { register as timing } from './hooks/timing.js';
import { register as privacy } from './hooks/privacy.js';
import { register as hardware } from './hooks/hardware.js';
import { register as adblock } from './hooks/adblock.js';
import { register as extension } from './hooks/extension.js';
import { register as intl } from './hooks/intl.js';
import { register as misc } from './hooks/misc.js';
import { register as behavior } from './hooks/behavior.js';

(function () {
  "use strict";

  const LOG_KEY = "__fpDetector";

  // ── Batched event dispatch ────────────────────────────────────────────
  // Visible tabs flush every 250ms; hidden tabs flush every 2s to cut
  // IPC traffic from background tabs that are still running fingerprinting
  // loops (ad networks, analytics). Chrome already clamps setTimeout to
  // ~1s in hidden tabs after 5 min, so this layers further on top of that.
  let eventBatch = [];
  let flushTimer = 0;
  const FLUSH_INTERVAL_VISIBLE = 250;
  const FLUSH_INTERVAL_HIDDEN = 2000;
  const MAX_BATCH_SIZE = 50;
  let flushInterval = (typeof document !== "undefined" && document.hidden)
    ? FLUSH_INTERVAL_HIDDEN
    : FLUSH_INTERVAL_VISIBLE;

  function flushBatch() {
    flushTimer = 0;
    if (eventBatch.length === 0) return;
    const batch = eventBatch;
    eventBatch = [];
    window.dispatchEvent(
      new CustomEvent(LOG_KEY, { detail: JSON.stringify(batch) })
    );
  }

  function queueEvent(entry) {
    eventBatch.push(entry);
    if (eventBatch.length >= MAX_BATCH_SIZE) {
      clearTimeout(flushTimer);
      flushTimer = 0;
      flushBatch();
    } else if (!flushTimer) {
      flushTimer = setTimeout(flushBatch, flushInterval);
    }
  }

  // Adjust flush cadence based on tab visibility. Flush immediately on
  // becoming visible so any pending hidden-tab events show up right away.
  if (typeof document !== "undefined") {
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        flushInterval = FLUSH_INTERVAL_HIDDEN;
      } else {
        flushInterval = FLUSH_INTERVAL_VISIBLE;
        if (eventBatch.length > 0) {
          clearTimeout(flushTimer);
          flushTimer = 0;
          flushBatch();
        }
      }
    });
  }

  // Drain the buffer on page teardown so events queued during the 2s
  // hidden-tab window (or a 250ms foreground window) don't get lost on
  // navigation or tab close. pagehide fires before unload, is bfcache-
  // compatible, and works in both main and iframe contexts.
  window.addEventListener("pagehide", () => {
    if (eventBatch.length > 0) {
      clearTimeout(flushTimer);
      flushTimer = 0;
      flushBatch();
    }
  });

  // ── Mute state (synced from extension storage via bridge) ─────────────
  const mutedMethodsSet = new Set();
  const mutedCategoriesSet = new Set();

  window.addEventListener("__fpDetector_mutes", (e) => {
    try {
      const { mutedMethods, mutedCategories } = JSON.parse(e.detail);
      mutedMethodsSet.clear();
      mutedCategoriesSet.clear();
      for (const m of (mutedMethods || [])) mutedMethodsSet.add(m);
      for (const c of (mutedCategories || [])) mutedCategoriesSet.add(c);
    } catch { /* ignore malformed mute data */ }
  });

  // ── Rate limiting per method ──────────────────────────────────────────
  const methodIdMap = {};
  const methodCountArr = [];
  let nextMethodId = 0;
  const METHOD_LOG_FIRST = 3;
  const METHOD_LOG_EVERY = 100;

  // ── V8 optimization: Error.captureStackTrace ─────────────────────────
  const hasCapture = typeof Error.captureStackTrace === "function";
  // Truncate captured stacks to this many frames — saves ~70% of storage
  // since most fingerprinting happens within a few caller frames.
  const MAX_STACK_FRAMES = 8;

  function captureStack() {
    let stack;
    if (hasCapture) {
      const obj = {};
      Error.captureStackTrace(obj, captureStack);
      stack = obj.stack;
    } else {
      stack = new Error().stack;
    }
    if (!stack) return "";
    // Trim to N frames — the first few callers are enough to identify
    // the source script, and sites don't have call stacks > 50 frames deep
    // for fingerprinting code anyway.
    const lines = stack.split("\n");
    if (lines.length > MAX_STACK_FRAMES + 1) {
      return lines.slice(0, MAX_STACK_FRAMES + 1).join("\n") + "\n    ...";
    }
    return stack;
  }

  function extractSource(stack) {
    if (!stack) return "";
    const lines = stack.split("\n");
    let fallback = ""; // first non-URL context found (eval/blob/data/anon)

    // Single pass — check all patterns at once, return URL as soon as found
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (line.length < 10) continue;
      if (line.indexOf("inject.js") !== -1) continue;

      // Try URL first (most common case)
      let idx = line.indexOf("https://");
      if (idx === -1) idx = line.indexOf("http://");
      if (idx !== -1) {
        let end = idx;
        while (end < line.length && line.charCodeAt(end) !== 32 && line.charCodeAt(end) !== 41) end++;
        const url = line.substring(idx, end);
        if (url.charCodeAt(0) === 99 && url.indexOf("chrome-extension://") === 0) continue;
        return url;
      }

      // Record alternative context — keep looking for a URL but save this
      if (!fallback) {
        if (line.indexOf("<anonymous>") !== -1) fallback = "<anonymous> (inline script or eval)";
        else if (line.indexOf("blob:") !== -1) fallback = "blob: (dynamic script)";
        else if (line.indexOf("data:") !== -1) fallback = "data: (data URL script)";
        else if (line.indexOf("eval") !== -1) fallback = "eval() (runtime-generated code)";
        else if (line.indexOf("Function") !== -1) fallback = "new Function() (runtime-generated)";
      }
    }

    if (fallback) return fallback;
    return location.href ? "inline on " + location.href : "";
  }

  // Main record function.
  // Optional `precomputedKey` skips the string concat when the caller
  // already has the rate-limit key cached (hookMethod/hookGetter do this).
  function record(category, method, detail, precomputedKey) {
    if (mutedCategoriesSet.has(category)) return;
    if (mutedMethodsSet.has(method)) return;

    const key = precomputedKey || (category + "|" + method);
    let id = methodIdMap[key];
    if (id === undefined) {
      id = nextMethodId++;
      methodIdMap[key] = id;
      methodCountArr[id] = 0;
    }
    const count = ++methodCountArr[id];

    if (count > METHOD_LOG_FIRST && count % METHOD_LOG_EVERY !== 0) return;

    const stack = captureStack();
    const source = extractSource(stack);
    const countLabel = count > METHOD_LOG_FIRST ? " (call #" + count + ")" : "";
    queueEvent({
      category, method,
      detail: detail + countLabel,
      source, ts: Date.now(), stack,
    });
  }

  // Fire-once record for high-frequency APIs
  const hotMethodFirstSeen = {};

  function recordHot(category, method, detail) {
    if (mutedCategoriesSet.has(category)) return;
    if (mutedMethodsSet.has(method)) return;

    const key = category + "|" + method;
    if (hotMethodFirstSeen[key]) return;
    hotMethodFirstSeen[key] = true;

    const stack = captureStack();
    const source = extractSource(stack);
    queueEvent({
      category, method, detail, source, ts: Date.now(), stack,
    });
  }

  // ── Hook helpers with inlined mute checks ────────────────────────────

  function hookGetter(obj, prop, category, method) {
    const desc = Object.getOwnPropertyDescriptor(obj, prop);
    if (!desc || !desc.get) return;
    // Some browsers (Brave, Tor) mark privacy-sensitive props as
    // non-configurable to prevent spoofing — skip those silently.
    if (desc.configurable === false) return;
    const origGet = desc.get;
    // Precompute the rate-limit key once at hook install time
    const key = category + "|" + method;
    try {
      Object.defineProperty(obj, prop, {
        ...desc,
        get() {
          if (!mutedCategoriesSet.has(category) && !mutedMethodsSet.has(method)) {
            record(category, method, prop, key);
          }
          return origGet.call(this);
        },
      });
    } catch { /* property frozen by another extension or the browser */ }
  }

  function hookMethod(obj, prop, category, method) {
    const orig = obj[prop];
    if (typeof orig !== "function") return;
    // Precompute key once at hook install time
    const key = category + "|" + method;
    try {
      obj[prop] = function () {
        if (!mutedCategoriesSet.has(category) && !mutedMethodsSet.has(method)) {
          record(category, method, prop, key);
        }
        return orig.apply(this, arguments);
      };
    } catch { /* property is non-writable — leave it alone */ }
  }

  // Access-based hook. Records on property *access* instead of *call*
  // and returns the native function unchanged, so we don't sit in the
  // call stack when the native throws. Use this for async/promise-
  // returning Web IDL methods that page code commonly calls with the
  // wrong `this` (e.g. destructured refs), which would otherwise blame
  // the extension for "Illegal invocation" errors in the devtools
  // Errors panel.
  function hookMethodViaAccess(obj, prop, category, method) {
    const desc = Object.getOwnPropertyDescriptor(obj, prop);
    if (!desc || typeof desc.value !== "function") return;
    if (desc.configurable === false) return;
    let orig = desc.value;
    const key = category + "|" + method;
    try {
      Object.defineProperty(obj, prop, {
        configurable: true,
        enumerable: desc.enumerable,
        get() {
          if (!mutedCategoriesSet.has(category) && !mutedMethodsSet.has(method)) {
            record(category, method, prop, key);
          }
          return orig;
        },
        set(v) { orig = v; },
      });
    } catch { /* property frozen by another extension or the browser */ }
  }

  function hookMethodHot(obj, prop, category, method) {
    const orig = obj[prop];
    if (typeof orig !== "function") return;
    const hotKey = category + "|" + method;
    try {
      obj[prop] = function () {
        if (!hotMethodFirstSeen[hotKey] &&
            !mutedCategoriesSet.has(category) &&
            !mutedMethodsSet.has(method)) {
          hotMethodFirstSeen[hotKey] = true;
          const stack = captureStack();
          const source = extractSource(stack);
          queueEvent({ category, method, detail: prop, source, ts: Date.now(), stack });
        }
        return orig.apply(this, arguments);
      };
    } catch { /* property is non-writable — leave it alone */ }
  }

  // ── Register all hook modules ────────────────────────────────────────
  const helpers = { hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent };

  canvas(helpers);
  webgl(helpers);
  audio(helpers);
  navigator_(helpers);
  vendor(helpers);
  clientHints(helpers);
  screen_(helpers);
  fonts(helpers);
  webrtc(helpers);
  network(helpers);
  media(helpers);
  storage(helpers);
  timing(helpers);
  privacy(helpers);
  hardware(helpers);
  adblock(helpers);
  extension(helpers);
  intl(helpers);
  misc(helpers);
  behavior(helpers);

})();
