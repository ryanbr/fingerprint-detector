// Background service worker — stores per-tab fingerprinting detections
// and streams new events to connected popup ports.
//
// Performance notes:
// - Per-tab storage keys (`fp_tab_<id>`) instead of one giant tabData object,
//   so only changed tabs are serialized on save.
// - Only dirty tabs get written — tracked in a dirtyTabs Set.
// - Lower per-tab caps to keep total memory bounded across many tabs.
// - SW can be killed after 30s idle; data is restored from session storage.

const tabData = {};
const popupPorts = new Map();
const portWatchedTabs = new Map();

const MAX_DETECTIONS_PER_TAB = 2000;  // was 5000 — reduces per-tab memory
const MAX_PER_CATEGORY = 300;         // was 500
const MAX_TOTAL_TABS_STORED = 50;     // cap on tabs kept in memory
const SAVE_DEBOUNCE = 1000;           // was 500 — less aggressive
const TAB_KEY_PREFIX = "fp_tab_";     // per-tab session storage keys

// ── Per-tab dirty tracking ────────────────────────────────────────────
// Only write the tabs whose data has changed since the last save.
const dirtyTabs = new Set();
let saveTimer = 0;

function markDirty(tabId) {
  dirtyTabs.add(tabId);
  if (!saveTimer) {
    saveTimer = setTimeout(flushDirty, SAVE_DEBOUNCE);
  }
}

// ── Compression via CompressionStream (gzip) ─────────────────────────
// Chrome's session storage stores strings. Compressing the JSON
// payload cuts storage usage by 60-80% and reduces IPC transfer time.
const USE_COMPRESSION = typeof CompressionStream === "function";

async function compressJSON(obj) {
  if (!USE_COMPRESSION) return { json: JSON.stringify(obj), compressed: false };
  try {
    const json = JSON.stringify(obj);
    // Skip compression for tiny payloads — overhead isn't worth it
    if (json.length < 1024) return { json, compressed: false };
    const stream = new Blob([json]).stream().pipeThrough(new CompressionStream("gzip"));
    const buf = await new Response(stream).arrayBuffer();
    // Convert to base64 for string storage
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return { json: btoa(bin), compressed: true };
  } catch {
    return { json: JSON.stringify(obj), compressed: false };
  }
}

async function decompressJSON(stored) {
  if (!stored || !stored.compressed) return stored && stored.json ? JSON.parse(stored.json) : stored;
  try {
    const bin = atob(stored.json);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
    const text = await new Response(stream).text();
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function flushDirty() {
  saveTimer = 0;
  if (dirtyTabs.size === 0) return;
  const removes = [];
  const writes = {};
  const dirtyList = [...dirtyTabs];
  dirtyTabs.clear();

  // Compress each dirty tab in parallel
  await Promise.all(dirtyList.map(async (tabId) => {
    const key = TAB_KEY_PREFIX + tabId;
    if (tabData[tabId]) {
      writes[key] = await compressJSON(tabData[tabId]);
    } else {
      removes.push(key);
    }
  }));

  // Batch write + remove
  if (Object.keys(writes).length > 0) {
    chrome.storage.session.set(writes).catch(() => {
      // Storage quota exceeded — drop the oldest tab and retry
      evictOldestTab();
    });
  }
  if (removes.length > 0) {
    chrome.storage.session.remove(removes).catch(() => {});
  }
}

function evictOldestTab() {
  // Find the tab with the fewest recent detections and drop it
  const ids = Object.keys(tabData);
  if (ids.length === 0) return;
  let oldestId = ids[0];
  let oldestTs = Infinity;
  for (const id of ids) {
    const detections = tabData[id] && tabData[id].detections;
    if (!detections || detections.length === 0) { oldestId = id; break; }
    const lastTs = detections[detections.length - 1].ts || 0;
    if (lastTs < oldestTs) {
      oldestTs = lastTs;
      oldestId = id;
    }
  }
  delete tabData[oldestId];
  chrome.storage.session.remove(TAB_KEY_PREFIX + oldestId).catch(() => {});
  chrome.action.setBadgeText({ text: "", tabId: Number(oldestId) }).catch(() => {});
}

// ── Restore on service worker startup ─────────────────────────────────
// Read all fp_tab_* keys at once and decompress. Message handlers are
// registered synchronously below and will start receiving detections
// the instant the SW wakes — before this async restore finishes. If a
// detection arrives during the restore window it creates a fresh
// tabData entry; we must merge (not overwrite) so those events survive.
(async () => {
  const stored = await chrome.storage.session.get(null);
  if (!stored) return;
  for (const key of Object.keys(stored)) {
    if (key.indexOf(TAB_KEY_PREFIX) !== 0) continue;
    const tabId = Number(key.slice(TAB_KEY_PREFIX.length));
    if (isNaN(tabId)) continue;
    const raw = stored[key];
    // Support both legacy (raw object) and new (compressed wrapper) formats
    let data;
    if (raw && typeof raw === "object" && "json" in raw) {
      data = await decompressJSON(raw);
    } else {
      data = raw;
    }
    if (!data || !data.categories) continue;

    const live = tabData[tabId];
    if (!live) {
      // Common case: no detections arrived during restore — just adopt.
      tabData[tabId] = data;
    } else {
      // A detection arrived during the restore await. Merge: restored
      // data is older, so prepend it to the live detections. Cap at
      // MAX_DETECTIONS_PER_TAB / MAX_PER_CATEGORY.
      const mergedDetections = data.detections.concat(live.detections);
      if (mergedDetections.length > MAX_DETECTIONS_PER_TAB) {
        mergedDetections.splice(0, mergedDetections.length - MAX_DETECTIONS_PER_TAB);
      }
      const mergedCategories = {};
      const catKeys = new Set(Object.keys(data.categories));
      for (const k of Object.keys(live.categories)) catKeys.add(k);
      for (const cat of catKeys) {
        const a = data.categories[cat] || [];
        const b = live.categories[cat] || [];
        const combined = a.concat(b);
        if (combined.length > MAX_PER_CATEGORY) {
          combined.splice(0, combined.length - MAX_PER_CATEGORY);
        }
        mergedCategories[cat] = combined;
      }
      tabData[tabId] = { detections: mergedDetections, categories: mergedCategories };
      // The merged state differs from the stored snapshot — mark dirty
      // so the next flush persists it.
      markDirty(tabId);
    }
    updateBadge(tabId, tabData[tabId]);
  }
})();

// Grant cross-context access so popup/compare can read session storage
chrome.storage.session.setAccessLevel?.({
  accessLevel: "TRUSTED_AND_UNTRUSTED_CONTEXTS",
});

// ── Port management ───────────────────────────────────────────────────
chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "fp-log") return;

  portWatchedTabs.set(port, new Set());

  port.onDisconnect.addListener(() => {
    const watched = portWatchedTabs.get(port);
    if (watched) {
      for (const tabId of watched) {
        popupPorts.get(tabId)?.delete(port);
        if (popupPorts.get(tabId)?.size === 0) popupPorts.delete(tabId);
      }
    }
    portWatchedTabs.delete(port);
  });

  port.onMessage.addListener((msg) => {
    if (msg.type === "watch-tab") {
      const tabId = msg.tabId;
      if (!popupPorts.has(tabId)) popupPorts.set(tabId, new Set());
      popupPorts.get(tabId).add(port);
      portWatchedTabs.get(port)?.add(tabId);

      const existing = tabData[tabId];
      if (existing && existing.detections.length > 0) {
        port.postMessage({ type: "fp-batch", tabId, data: existing.detections });
      }
    }

    if (msg.type === "unwatch-tab") {
      const tabId = msg.tabId;
      popupPorts.get(tabId)?.delete(port);
      if (popupPorts.get(tabId)?.size === 0) popupPorts.delete(tabId);
      portWatchedTabs.get(port)?.delete(tabId);
    }
  });
});

// ── Detection storage ─────────────────────────────────────────────────
function storeDetection(tabId, d) {
  if (!tabData[tabId]) {
    // Enforce global tab cap
    const tabCount = Object.keys(tabData).length;
    if (tabCount >= MAX_TOTAL_TABS_STORED) {
      evictOldestTab();
    }
    tabData[tabId] = { detections: [], categories: {} };
  }
  const tab = tabData[tabId];
  if (tab.detections.length < MAX_DETECTIONS_PER_TAB) {
    tab.detections.push(d);
  }
  if (!tab.categories[d.category]) {
    tab.categories[d.category] = [];
  }
  const catArr = tab.categories[d.category];
  if (catArr.length < MAX_PER_CATEGORY) {
    catArr.push(d);
  }
}

function broadcastToWatchers(tabId, events) {
  const ports = popupPorts.get(tabId);
  if (ports) {
    for (const p of ports) {
      p.postMessage({ type: "fp-batch", tabId, data: events });
    }
  }
}

// ── Message handling ──────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "fp-detection-batch" && sender.tab) {
    const tabId = sender.tab.id;
    for (const d of msg.data) {
      storeDetection(tabId, d);
    }
    updateBadge(tabId, tabData[tabId]);
    broadcastToWatchers(tabId, msg.data);
    markDirty(tabId);
  }

  if (msg.type === "fp-detection" && sender.tab) {
    const tabId = sender.tab.id;
    storeDetection(tabId, msg.data);
    updateBadge(tabId, tabData[tabId]);
    broadcastToWatchers(tabId, [msg.data]);
    markDirty(tabId);
  }

  if (msg.type === "get-detections") {
    const tabId = msg.tabId;
    if (tabId) {
      sendResponse(tabData[tabId] || { detections: [], categories: {} });
    } else {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const id = tabs[0]?.id;
        sendResponse(tabData[id] || { detections: [], categories: {} });
      });
      return true;
    }
  }

  if (msg.type === "get-ext-ids") {
    const tabId = msg.tabId;
    if (tabId) {
      chrome.tabs.sendMessage(tabId, { type: "get-ext-ids" }, (response) => {
        if (chrome.runtime.lastError) {
          sendResponse(null);
          return;
        }
        sendResponse(response);
      });
      return true;
    }
  }
});

// ── Badge ─────────────────────────────────────────────────────────────
function updateBadge(tabId, data) {
  if (!data) return;
  const count = Object.keys(data.categories || {}).length;
  const text = count > 0 ? String(count) : "";
  chrome.action.setBadgeText({ text, tabId }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({
    color: count >= 5 ? "#e53935" : count >= 3 ? "#fb8c00" : "#43a047",
    tabId,
  }).catch(() => {});
}

// ── Cleanup ───────────────────────────────────────────────────────────
chrome.webNavigation?.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    delete tabData[details.tabId];
    chrome.action.setBadgeText({ text: "", tabId: details.tabId }).catch(() => {});
    markDirty(details.tabId);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabData[tabId];
  popupPorts.delete(tabId);
  markDirty(tabId);
});

// Chrome fires onReplaced when a prerendered/prefetched tab swaps into
// the visible tab slot — no onRemoved/onCreated pair is emitted.
// Clear tabData for the dead tabId so we don't leak state; detection
// data for the old tab's content script instance is gone with it.
chrome.tabs.onReplaced.addListener((_addedTabId, removedTabId) => {
  delete tabData[removedTabId];
  popupPorts.delete(removedTabId);
  markDirty(removedTabId);
});
