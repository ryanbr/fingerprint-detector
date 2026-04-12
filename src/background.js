// Background service worker — stores per-tab fingerprinting detections
// and streams new events to connected popup ports.
// Handles batched events from bridge.js and caps stored detections per tab.
// Supports multi-tab watching from the popup.

const tabData = {};
const popupPorts = new Map(); // tabId -> Set<port>
const portWatchedTabs = new Map(); // port -> Set<tabId>
const MAX_DETECTIONS_PER_TAB = 5000;

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

      // Send existing detections as backlog with tabId tagged
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

const MAX_PER_CATEGORY = 500;

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

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "fp-detection-batch" && sender.tab) {
    const tabId = sender.tab.id;
    for (const d of msg.data) {
      storeDetection(tabId, d);
    }
    updateBadge(tabId, tabData[tabId]);
    broadcastToWatchers(tabId, msg.data);
  }

  if (msg.type === "fp-detection" && sender.tab) {
    const tabId = sender.tab.id;
    storeDetection(tabId, msg.data);
    updateBadge(tabId, tabData[tabId]);
    broadcastToWatchers(tabId, [msg.data]);
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

  // List all tabs that have detection data
  if (msg.type === "get-tabs-with-data") {
    const tabIds = Object.keys(tabData).map(Number).filter(id => {
      return tabData[id] && tabData[id].detections.length > 0;
    });
    // Get tab info for each
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

function updateBadge(tabId, data) {
  const count = Object.keys(data.categories).length;
  const text = count > 0 ? String(count) : "";
  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({
    color: count >= 5 ? "#e53935" : count >= 3 ? "#fb8c00" : "#43a047",
    tabId,
  });
}

chrome.webNavigation?.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    delete tabData[details.tabId];
    chrome.action.setBadgeText({ text: "", tabId: details.tabId });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabData[tabId];
  popupPorts.delete(tabId);
});
