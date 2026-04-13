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

function flushDirty() {
  saveTimer = 0;
  if (dirtyTabs.size === 0) return;
  const writes = {};
  const removes = [];
  for (const tabId of dirtyTabs) {
    const key = TAB_KEY_PREFIX + tabId;
    if (tabData[tabId]) {
      writes[key] = tabData[tabId];
    } else {
      removes.push(key);
    }
  }
  dirtyTabs.clear();

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
// Read all fp_tab_* keys at once.
chrome.storage.session.get(null, (stored) => {
  if (!stored) return;
  for (const key of Object.keys(stored)) {
    if (key.indexOf(TAB_KEY_PREFIX) !== 0) continue;
    const tabId = Number(key.slice(TAB_KEY_PREFIX.length));
    if (!isNaN(tabId)) {
      tabData[tabId] = stored[key];
      if (tabData[tabId] && tabData[tabId].categories) {
        updateBadge(tabId, tabData[tabId]);
      }
    }
  }
});

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

  if (msg.type === "get-tabs-with-data") {
    const tabIds = Object.keys(tabData).map(Number).filter(id => {
      return tabData[id] && tabData[id].detections.length > 0;
    });
    Promise.all(tabIds.map(id =>
      chrome.tabs.get(id).then(tab => ({
        tabId: id,
        title: tab.title || "Unknown",
        url: tab.url || "",
        favIconUrl: tab.favIconUrl || "",
        detectionCount: tabData[id].detections.length,
        categoryCount: Object.keys(tabData[id].categories).length,
      })).catch(() => null)
    )).then(tabs => {
      sendResponse(tabs.filter(Boolean));
    });
    return true;
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
