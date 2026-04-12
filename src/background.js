// Background service worker — stores per-tab fingerprinting detections
// and streams new events to connected popup ports.
// Handles batched events from bridge.js and caps stored detections per tab.
// Supports multi-tab watching from the popup.
//
// IMPORTANT: Chrome kills service workers after ~30s of inactivity.
// All tabData is persisted to chrome.storage.session so it survives restarts.

let tabData = {};
const popupPorts = new Map();
const portWatchedTabs = new Map();
const MAX_DETECTIONS_PER_TAB = 5000;
const MAX_PER_CATEGORY = 500;

// ── Persistence layer ─────────────────────────────────────────────────
// chrome.storage.session is RAM-only (cleared on browser close) but
// survives service worker restarts. Perfect for detection data.
let saveTimer = 0;
const SAVE_DEBOUNCE = 500; // ms — batch writes to avoid thrashing storage

function scheduleSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = 0;
    chrome.storage.session.set({ tabData });
  }, SAVE_DEBOUNCE);
}

// Restore tabData from session storage on service worker startup
chrome.storage.session.get(["tabData"], (stored) => {
  if (stored.tabData) {
    tabData = stored.tabData;
    // Restore badges for all tabs with data
    for (const tabId of Object.keys(tabData)) {
      const id = Number(tabId);
      if (tabData[id] && tabData[id].categories) {
        updateBadge(id, tabData[id]);
      }
    }
  }
});

// Increase session storage quota (default is 1MB, max 10MB)
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

      // Send existing detections as backlog
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
    scheduleSave();
  }

  if (msg.type === "fp-detection" && sender.tab) {
    const tabId = sender.tab.id;
    storeDetection(tabId, msg.data);
    updateBadge(tabId, tabData[tabId]);
    broadcastToWatchers(tabId, [msg.data]);
    scheduleSave();
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
        // Consume lastError to avoid "Unchecked runtime.lastError" console noise
        // when the tab has no content script (chrome://, about:, extension pages)
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
  const count = Object.keys(data.categories).length;
  const text = count > 0 ? String(count) : "";
  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({
    color: count >= 5 ? "#e53935" : count >= 3 ? "#fb8c00" : "#43a047",
    tabId,
  });
}

// ── Cleanup ───────────────────────────────────────────────────────────
chrome.webNavigation?.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    delete tabData[details.tabId];
    chrome.action.setBadgeText({ text: "", tabId: details.tabId });
    scheduleSave();
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabData[tabId];
  popupPorts.delete(tabId);
  scheduleSave();
});
