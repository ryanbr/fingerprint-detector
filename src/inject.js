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

(function () {
  "use strict";

  const LOG_KEY = "__fpDetector";

  // ── Batched event dispatch ────────────────────────────────────────────
  let eventBatch = [];
  let flushTimer = 0;
  const FLUSH_INTERVAL = 250;
  const MAX_BATCH_SIZE = 50;

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
      flushTimer = setTimeout(flushBatch, FLUSH_INTERVAL);
    }
  }

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

  function captureStack() {
    if (hasCapture) {
      const obj = {};
      Error.captureStackTrace(obj, captureStack);
      return obj.stack;
    }
    return new Error().stack;
  }

  function extractSource(stack) {
    if (!stack) return "";
    const lines = stack.split("\n");
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (line.length < 10) continue;
      let idx = line.indexOf("https://");
      if (idx === -1) idx = line.indexOf("http://");
      if (idx === -1) continue;
      let end = idx;
      while (end < line.length && line.charCodeAt(end) !== 32 && line.charCodeAt(end) !== 41) end++;
      const url = line.substring(idx, end);
      if (url.indexOf("inject.js") !== -1) continue;
      if (url.charCodeAt(0) === 99 && url.indexOf("chrome-extension://") === 0) continue;
      return url;
    }
    return "";
  }

  // Main record function
  function record(category, method, detail) {
    if (mutedCategoriesSet.size > 0 && mutedCategoriesSet.has(category)) return;
    if (mutedMethodsSet.size > 0 && mutedMethodsSet.has(method)) return;

    const key = category + "|" + method;
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
    if (mutedCategoriesSet.size > 0 && mutedCategoriesSet.has(category)) return;
    if (mutedMethodsSet.size > 0 && mutedMethodsSet.has(method)) return;

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
    const origGet = desc.get;
    Object.defineProperty(obj, prop, {
      ...desc,
      get() {
        if (!(mutedCategoriesSet.size > 0 && mutedCategoriesSet.has(category)) &&
            !(mutedMethodsSet.size > 0 && mutedMethodsSet.has(method))) {
          record(category, method, prop);
        }
        return origGet.call(this);
      },
    });
  }

  function hookMethod(obj, prop, category, method) {
    const orig = obj[prop];
    if (typeof orig !== "function") return;
    obj[prop] = function () {
      if (!(mutedCategoriesSet.size > 0 && mutedCategoriesSet.has(category)) &&
          !(mutedMethodsSet.size > 0 && mutedMethodsSet.has(method))) {
        record(category, method, prop);
      }
      return orig.apply(this, arguments);
    };
  }

  function hookMethodHot(obj, prop, category, method) {
    const orig = obj[prop];
    if (typeof orig !== "function") return;
    const hotKey = category + "|" + method;
    obj[prop] = function () {
      if (!hotMethodFirstSeen[hotKey] &&
          !(mutedCategoriesSet.size > 0 && mutedCategoriesSet.has(category)) &&
          !(mutedMethodsSet.size > 0 && mutedMethodsSet.has(method))) {
        hotMethodFirstSeen[hotKey] = true;
        const stack = captureStack();
        const source = extractSource(stack);
        queueEvent({ category, method, detail: prop, source, ts: Date.now(), stack });
      }
      return orig.apply(this, arguments);
    };
  }

  // ── Register all hook modules ────────────────────────────────────────
  const helpers = { hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent };

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

})();
