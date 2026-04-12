const CATEGORY_META = {
  Canvas:         { icon: "🎨", color: "#e94560", risk: "high",   desc: "Canvas image data extraction — unique per GPU/driver/OS" },
  WebGL:          { icon: "🔺", color: "#e94560", risk: "high",   desc: "WebGL renderer, vendor, and parameter fingerprinting" },
  Audio:          { icon: "🔊", color: "#e94560", risk: "high",   desc: "AudioContext processing differences reveal hardware" },
  Fonts:          { icon: "🔤", color: "#fb8c00", risk: "high",   desc: "Font enumeration via element dimension probing" },
  WebRTC:         { icon: "📡", color: "#e94560", risk: "high",   desc: "WebRTC can leak local/public IP addresses" },
  Navigator:      { icon: "🧭", color: "#fb8c00", risk: "medium", desc: "Browser and hardware properties via navigator API" },
  Screen:         { icon: "🖥️", color: "#43a047", risk: "low",    desc: "Screen resolution and color depth" },
  Timezone:       { icon: "🕐", color: "#43a047", risk: "low",    desc: "Timezone offset and locale data" },
  ClientRects:    { icon: "📐", color: "#fb8c00", risk: "medium", desc: "Element bounding rects vary by font rendering" },
  Storage:        { icon: "💾", color: "#43a047", risk: "low",    desc: "Storage availability probing (cookies, localStorage, IndexedDB)" },
  Permissions:    { icon: "🔒", color: "#fb8c00", risk: "medium", desc: "Permissions API querying reveals browser state" },
  MediaDevices:   { icon: "📷", color: "#e94560", risk: "high",   desc: "Enumerating cameras/microphones reveals hardware" },
  SpeechSynthesis:{ icon: "🗣️", color: "#fb8c00", risk: "medium", desc: "Voice list fingerprinting via speechSynthesis" },
  Network:        { icon: "🌐", color: "#43a047", risk: "low",    desc: "Network connection type and speed hints" },
  Plugins:        { icon: "🔌", color: "#fb8c00", risk: "medium", desc: "Browser plugin and MIME type enumeration" },
  ClientHints:    { icon: "🏷️", color: "#e94560", risk: "high",   desc: "User-Agent Client Hints (Sec-CH-UA) — high-entropy browser/OS/arch data" },
  GPC:            { icon: "🛡️", color: "#fb8c00", risk: "medium", desc: "Global Privacy Control signal — reveals privacy preference" },
  WebSocket:      { icon: "🔗", color: "#fb8c00", risk: "medium", desc: "WebSocket connections can reveal real IP behind VPN/proxy" },
  DNT:            { icon: "🚫", color: "#fb8c00", risk: "medium", desc: "Do Not Track signal — reveals privacy preference (1-bit fingerprint)" },
  MediaQuery:     { icon: "🎛️", color: "#fb8c00", risk: "medium", desc: "CSS media query probing — prefers-color-scheme, reduced-motion, display-mode, etc." },
  Keyboard:       { icon: "⌨️", color: "#e94560", risk: "high",   desc: "Keyboard layout reveals language/locale via getLayoutMap()" },
  Timing:         { icon: "⏱️", color: "#fb8c00", risk: "medium", desc: "High-resolution timers for timing attacks and hardware profiling" },
  WebGPU:         { icon: "🎮", color: "#e94560", risk: "high",   desc: "WebGPU adapter info exposes GPU hardware details" },
  Hardware:       { icon: "🔧", color: "#e94560", risk: "high",   desc: "Bluetooth/USB/Serial/HID device enumeration" },
  Sensors:        { icon: "📱", color: "#e94560", risk: "high",   desc: "Motion/orientation/light sensors reveal device hardware" },
  Touch:          { icon: "👆", color: "#43a047", risk: "low",    desc: "Touch support probing — distinguishes touch vs non-touch devices" },
  Credentials:    { icon: "🔑", color: "#fb8c00", risk: "medium", desc: "Credential Management API — probes stored credentials/WebAuthn" },
  Math:           { icon: "🔢", color: "#e94560", risk: "high",   desc: "Math function output differences across OS/arch reveal platform" },
  Architecture:   { icon: "🧬", color: "#e94560", risk: "high",   desc: "CPU architecture detection via Float32Array NaN bit pattern" },
  VendorDetect:   { icon: "🏢", color: "#fb8c00", risk: "medium", desc: "Browser-specific window globals to distinguish engines/vendors" },
  AdBlockDetect:  { icon: "🚧", color: "#e94560", risk: "high",   desc: "Ad blocker filter list fingerprinting — bait elements reveal which blockers are active" },
  ApplePay:       { icon: "🍎", color: "#fb8c00", risk: "medium", desc: "Apple Pay availability probing via ApplePaySession" },
  PrivateClick:   { icon: "🔏", color: "#fb8c00", risk: "medium", desc: "Safari Private Click Measurement via <a>.attributionSourceId" },
  Intl:           { icon: "🌍", color: "#fb8c00", risk: "medium", desc: "Intl locale/formatting APIs reveal language and region settings" },
};

// ── Utilities ──────────────────────────────────────────────────────────
function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function getRiskLevel(categories) {
  const cats = Object.keys(categories);
  const hasHigh = cats.some(c => CATEGORY_META[c]?.risk === "high");
  const count = cats.length;
  if (hasHigh && count >= 4) return { level: "high", label: "High Risk", cls: "high" };
  if (hasHigh || count >= 3) return { level: "medium", label: "Medium Risk", cls: "medium" };
  if (count > 0) return { level: "low", label: "Low Risk", cls: "low" };
  return { level: "none", label: "No Risk", cls: "none" };
}

function formatTime(ts) {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatTimePrecise(ts) {
  const d = new Date(ts);
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) + "." + ms;
}

function dedupeDetections(arr) {
  const seen = new Set();
  return arr.filter(d => {
    const key = `${d.method}|${d.detail}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function riskClass(category) {
  return "risk-" + (CATEGORY_META[category]?.risk || "low");
}

// Shorten a full URL to just origin + truncated path for display
function shortenUrl(url) {
  if (!url) return "";
  try {
    const u = new URL(url);
    let path = u.pathname;
    // Trim long paths
    if (path.length > 40) path = path.slice(0, 37) + "...";
    const loc = url.match(/:(\d+:\d+)$/);
    return u.origin + path + (loc ? ":" + loc[1] : "");
  } catch (_) {
    // Not a valid URL, just truncate
    return url.length > 80 ? url.slice(0, 77) + "..." : url;
  }
}

function cleanStack(stack) {
  if (!stack) return "(no stack)";
  // Remove the first line ("Error") and our inject.js hook frames
  return stack
    .split("\n")
    .filter(line => !line.includes("__fpDetector") && line.trim() !== "Error")
    .map(line => line.trim())
    .filter(Boolean)
    .join("\n") || "(no caller frames)";
}

// ── Tab Switching ──────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById(tab.dataset.panel).classList.add("active");
    if (typeof saveUIState === "function") saveUIState();
  });
});

// ── Summary Panel ──────────────────────────────────────────────────────
function renderSummary(response) {
  const content = document.getElementById("content");
  if (!response || Object.keys(response.categories).length === 0) return;

  const { categories } = response;
  const risk = getRiskLevel(categories);

  let html = `<div class="summary">
    <span class="badge ${risk.cls}">${risk.label}</span>
    <span class="badge none">${Object.keys(categories).length} techniques</span>
    <span class="badge none">${response.detections.length} total calls</span>
  </div>`;

  const riskOrder = { high: 0, medium: 1, low: 2 };
  const sortedCats = Object.keys(categories).sort((a, b) => {
    const ra = riskOrder[CATEGORY_META[a]?.risk] ?? 2;
    const rb = riskOrder[CATEGORY_META[b]?.risk] ?? 2;
    return ra - rb;
  });

  for (const cat of sortedCats) {
    const meta = CATEGORY_META[cat] || { icon: "?", color: "#78909c", risk: "low", desc: cat };
    const items = dedupeDetections(categories[cat]);
    const catMuted = mutedCategories.has(cat);

    html += `<div class="category${catMuted ? " is-muted" : ""}">
      <div class="category-header" data-cat="${cat}">
        <span class="category-name">
          <span class="category-icon" style="background:${meta.color}22;color:${meta.color}">${meta.icon}</span>
          ${cat}
        </span>
        <span class="category-right">
          <span class="count">${categories[cat].length} calls</span>
          <button class="summary-mute-btn${catMuted ? " is-muted" : ""}" data-mute-cat="${escapeHtml(cat)}" title="${catMuted ? "Unmute" : "Mute"} ${escapeHtml(cat)} category">&#x1F507;</button>
          <span class="arrow">&#9654;</span>
        </span>
      </div>
      <div class="category-body">
        <p style="color:#78909c;font-size:11px;margin-bottom:8px">${meta.desc}</p>`;

    for (const d of items) {
      const iframeTag = d.isIframe ? `<span class="iframe-tag">IFRAME</span>` : "";
      const mk = d.method.replace(/ \(call #\d+\)$/, "");
      const methodMuted = mutedMethods.has(mk);
      html += `<div class="detection${methodMuted ? " is-muted" : ""}">
        <span class="time">${formatTime(d.ts)}</span>
        <div class="method">
          ${escapeHtml(d.method)}${iframeTag}
          <button class="summary-mute-btn${methodMuted ? " is-muted" : ""}" data-mute-method="${escapeHtml(mk)}" title="${methodMuted ? "Unmute" : "Mute"} ${escapeHtml(mk)}">&#x1F507;</button>
        </div>
        ${d.detail ? `<div class="detail">${escapeHtml(d.detail)}</div>` : ""}
        ${d.source ? `<div class="source" title="${escapeHtml(d.source)}">${escapeHtml(shortenUrl(d.source))}</div>` : ""}
        ${d.isIframe && d.frameUrl ? `<div class="frame-url" title="${escapeHtml(d.frameUrl)}">iframe: ${escapeHtml(shortenUrl(d.frameUrl))}</div>` : ""}
      </div>`;
    }
    html += `</div></div>`;
  }

  // Preserve scroll position across re-renders
  const scrollParent = content.closest(".panel") || content.parentElement;
  const prevScroll = scrollParent.scrollTop;
  content.innerHTML = html;
  scrollParent.scrollTop = prevScroll;

  // Category expand/collapse
  content.querySelectorAll(".category-header").forEach(el => {
    el.addEventListener("click", (e) => {
      // Don't toggle if clicking the mute button
      if (e.target.closest(".summary-mute-btn")) return;
      el.parentElement.classList.toggle("open");
    });
  });

  // Category mute buttons
  content.querySelectorAll("[data-mute-cat]").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const cat = btn.dataset.muteCat;
      if (mutedCategories.has(cat)) {
        removeMute("category", cat);
      } else {
        addMute("category", cat);
      }
      // Re-render summary to update visual state
      chrome.runtime.sendMessage({ type: "get-detections" }, renderSummary);
    });
  });

  // Method mute buttons
  content.querySelectorAll("[data-mute-method]").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const method = btn.dataset.muteMethod;
      if (mutedMethods.has(method)) {
        removeMute("method", method);
      } else {
        addMute("method", method);
      }
      chrome.runtime.sendMessage({ type: "get-detections" }, renderSummary);
    });
  });
}

// ── Debug Log Panel ────────────────────────────────────────────────────
const logList = document.getElementById("log-list");
const logFilter = document.getElementById("log-filter");
const logCounter = document.getElementById("log-counter");
const logAutoscroll = document.getElementById("log-autoscroll");
const logClear = document.getElementById("log-clear");
const logPause = document.getElementById("log-pause");
const muteBar = document.getElementById("mute-bar");
const logEntriesByTab = {}; // tabId -> array of entries
const watchedTabs = new Set(); // tab IDs currently being watched (declared early for getAllLogEntries)
let logCount = 0;
let paused = false;
let pausedQueue = [];
const MAX_LOG_ENTRIES_PER_TAB = 10000;

// Flat view across all watched tabs (rebuilt on filter/refilter)
function getAllLogEntries() {
  const all = [];
  for (const tabId of watchedTabs) {
    const entries = logEntriesByTab[tabId];
    if (entries) all.push(...entries);
  }
  all.sort((a, b) => a.ts - b.ts);
  return all;
}

const MAX_DOM_NODES = 500;
let domNodeCount = 0;

// ── Mute System ───────────────────────────────────────────────────────
// Mute by method name (e.g. "performance.now") or by category (e.g. "Timing").
// Muted entries are still counted but not rendered.
// Persisted to chrome.storage.local so they survive popup close / browser restart.
const mutedMethods = new Set();
const mutedCategories = new Set();

function muteKey(d) {
  return d.method.replace(/ \(call #\d+\)$/, "");
}

function isMuted(d) {
  return mutedCategories.has(d.category) || mutedMethods.has(muteKey(d));
}

function saveMutes() {
  chrome.storage.local.set({
    mutedMethods: [...mutedMethods],
    mutedCategories: [...mutedCategories],
  });
}

function addMute(type, value) {
  if (type === "method") mutedMethods.add(value);
  else mutedCategories.add(value);
  saveMutes();
  renderMuteBar();
  refilterLog();
}

function removeMute(type, value) {
  if (type === "method") mutedMethods.delete(value);
  else mutedCategories.delete(value);
  saveMutes();
  renderMuteBar();
  refilterLog();
}

function renderMuteBar() {
  const hasMutes = mutedMethods.size > 0 || mutedCategories.size > 0;
  muteBar.classList.toggle("active", hasMutes);

  // Remove existing tags (keep the label)
  muteBar.querySelectorAll(".mute-tag").forEach(t => t.remove());

  for (const cat of mutedCategories) {
    const tag = document.createElement("span");
    tag.className = "mute-tag";
    tag.title = "Click to unmute category";
    tag.innerHTML = `${escapeHtml(cat)} <span class="x">&times;</span>`;
    tag.addEventListener("click", () => removeMute("category", cat));
    muteBar.appendChild(tag);
  }
  for (const method of mutedMethods) {
    const tag = document.createElement("span");
    tag.className = "mute-tag";
    tag.title = "Click to unmute method";
    tag.innerHTML = `${escapeHtml(method)} <span class="x">&times;</span>`;
    tag.addEventListener("click", () => removeMute("method", method));
    muteBar.appendChild(tag);
  }
}

// ── Pause ─────────────────────────────────────────────────────────────
logPause.addEventListener("click", () => {
  paused = !paused;
  logPause.textContent = paused ? "Resume" : "Pause";
  logPause.classList.toggle("paused", paused);

  if (!paused && pausedQueue.length > 0) {
    addLogBatch(pausedQueue);
    pausedQueue = [];
  }
  saveUIState();
});

// ── Batch add ─────────────────────────────────────────────────────────
function storeLogEntry(d) {
  const tabId = d._tabId || "unknown";
  if (!logEntriesByTab[tabId]) logEntriesByTab[tabId] = [];
  const arr = logEntriesByTab[tabId];
  arr.push(d);
  if (arr.length > MAX_LOG_ENTRIES_PER_TAB) arr.shift();
}

function addLogBatch(events) {
  const filter = logFilter.value.toLowerCase();
  const frag = document.createDocumentFragment();
  let added = 0;

  for (const d of events) {
    logCount++;
    storeLogEntry(d);
    if (isMuted(d)) continue;
    if (filter && !matchesFilter(d, filter)) continue;
    buildLogNode(d, frag);
    added++;
  }

  if (added > 0) {
    logList.appendChild(frag);
    domNodeCount += added;
    trimDOM();
    if (logAutoscroll.checked) {
      logList.scrollTop = logList.scrollHeight;
    }
  }

  updateCounter();
}

function addLogEntry(d) {
  if (paused) {
    pausedQueue.push(d);
    updateCounter();
    return;
  }

  logCount++;
  storeLogEntry(d);
  updateCounter();

  if (isMuted(d)) return;

  const filter = logFilter.value.toLowerCase();
  if (filter && !matchesFilter(d, filter)) return;

  const frag = document.createDocumentFragment();
  buildLogNode(d, frag);
  logList.appendChild(frag);
  domNodeCount++;
  trimDOM();

  if (logAutoscroll.checked) {
    logList.scrollTop = logList.scrollHeight;
  }
}

function updateCounter() {
  const muted = mutedMethods.size + mutedCategories.size;
  let text = `${logCount} events`;
  if (paused && pausedQueue.length > 0) text = `${logCount} + ${pausedQueue.length} queued`;
  if (muted > 0) text += ` (${muted} muted)`;
  logCounter.textContent = text;
}

function matchesFilter(d, filter) {
  const hay = `${d.category} ${d.method} ${d.detail || ""} ${d.source || ""} ${d.frameUrl || ""}`.toLowerCase();
  return hay.includes(filter);
}

function buildLogNode(d, parent) {
  const meta = CATEGORY_META[d.category];
  const icon = meta?.icon || "?";
  const iframeTag = d.isIframe ? ` <span class="iframe-tag">IFRAME</span>` : "";
  const mk = muteKey(d);
  // Show tab tag when watching multiple tabs
  const multiTab = watchedTabs.size > 1;
  const tabTag = multiTab && d._tabTitle
    ? ` <span class="log-tab-tag" title="Tab: ${escapeHtml(d._tabTitle)}">${escapeHtml(shortenTitle(d._tabTitle))}</span>`
    : "";

  const row = document.createElement("div");
  row.className = "log-entry";
  row.innerHTML =
    `<div class="log-row">` +
      `<span class="log-ts">${formatTimePrecise(d.ts)}</span>` +
      `<span class="log-cat ${riskClass(d.category)}">${icon} ${escapeHtml(d.category)}${iframeTag}${tabTag}</span>` +
      `<span class="log-method">${escapeHtml(d.method)}</span>` +
      `<span class="log-detail" title="${escapeHtml(d.detail || "")}">${escapeHtml(d.detail || "")}</span>` +
      `<button class="mute-btn" data-mute-method="${escapeHtml(mk)}" title="Mute ${escapeHtml(mk)}">&#x1F507;</button>` +
    `</div>` +
    (d.source ? `<div class="log-source" title="${escapeHtml(d.source)}">${escapeHtml(shortenUrl(d.source))}</div>` : "") +
    (d.isIframe && d.frameUrl ? `<div class="log-frame" title="${escapeHtml(d.frameUrl)}">iframe: ${escapeHtml(shortenUrl(d.frameUrl))}</div>` : "");

  // Mute button — mute this specific method
  const muteBtn = row.querySelector(".mute-btn");
  muteBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    addMute("method", mk);
  });

  // Right-click mute button — mute entire category
  muteBtn.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    e.stopPropagation();
    addMute("category", d.category);
  });

  // Stack trace — created lazily on click
  row.addEventListener("click", () => {
    let stackRow = row.nextElementSibling;
    if (!stackRow || !stackRow.classList.contains("log-stack-row")) {
      stackRow = document.createElement("div");
      stackRow.className = "log-stack-row";
      stackRow.textContent = cleanStack(d.stack);
      row.after(stackRow);
    }
    const isOpen = stackRow.style.display === "block";
    stackRow.style.display = isOpen ? "none" : "block";
    row.style.background = isOpen ? "" : "#12122a";
  });

  parent.appendChild(row);
}

// Remove oldest DOM entries when over the cap
function trimDOM() {
  while (domNodeCount > MAX_DOM_NODES) {
    const first = logList.firstElementChild;
    if (!first) break;
    const next = first.nextElementSibling;
    if (next && next.classList.contains("log-stack-row")) {
      next.remove();
    }
    first.remove();
    domNodeCount--;
  }
}

let filterDebounce = 0;
function refilterLog() {
  clearTimeout(filterDebounce);
  filterDebounce = setTimeout(() => {
    const filter = logFilter.value.toLowerCase();
    const prevScroll = logList.scrollTop;
    logList.innerHTML = "";
    domNodeCount = 0;
    const filtered = getAllLogEntries().filter(d => {
      if (isMuted(d)) return false;
      if (filter && !matchesFilter(d, filter)) return false;
      return true;
    });
    const tail = filtered.slice(-MAX_DOM_NODES);
    const frag = document.createDocumentFragment();
    for (const d of tail) {
      buildLogNode(d, frag);
      domNodeCount++;
    }
    logList.appendChild(frag);
    logList.scrollTop = prevScroll;
  }, 150);
}

logFilter.addEventListener("input", refilterLog);

logClear.addEventListener("click", () => {
  for (const tabId in logEntriesByTab) logEntriesByTab[tabId] = [];
  logCount = 0;
  domNodeCount = 0;
  pausedQueue = [];
  logList.innerHTML = "";
  updateCounter();
});

// ── Export ─────────────────────────────────────────────────────────────
const exportToggle = document.getElementById("export-toggle");
const exportMenu = document.getElementById("export-menu");

exportToggle.addEventListener("click", (e) => {
  e.stopPropagation();
  exportMenu.classList.toggle("open");
});
document.addEventListener("click", () => exportMenu.classList.remove("open"));
exportMenu.addEventListener("click", (e) => e.stopPropagation());

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  exportMenu.classList.remove("open");
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
}

function buildSummaryExport(callback) {
  chrome.runtime.sendMessage({ type: "get-detections", tabId: activeTabId }, (response) => {
    if (!response) { callback(null); return; }
    const { categories } = response;
    const riskOrder = { high: 0, medium: 1, low: 2 };
    const cats = Object.keys(categories).sort((a, b) => {
      const ra = riskOrder[CATEGORY_META[a]?.risk] ?? 2;
      const rb = riskOrder[CATEGORY_META[b]?.risk] ?? 2;
      return ra - rb;
    });

    const summary = {
      exportedAt: new Date().toISOString(),
      url: tabInfoMap[activeTabId]?.url || "",
      riskLevel: getRiskLevel(categories).label,
      totalTechniques: cats.length,
      totalCalls: response.detections.length,
      categories: {},
    };

    for (const cat of cats) {
      const meta = CATEGORY_META[cat] || {};
      const unique = dedupeDetections(categories[cat]);
      summary.categories[cat] = {
        risk: meta.risk || "unknown",
        description: meta.desc || "",
        totalCalls: categories[cat].length,
        uniqueMethods: unique.map(d => ({
          method: d.method,
          detail: d.detail || "",
          source: d.source || "",
          frameUrl: d.isIframe ? d.frameUrl : undefined,
        })),
      };
    }
    callback(summary);
  });
}

function buildLogExport() {
  return getAllLogEntries().map(d => ({
    timestamp: new Date(d.ts).toISOString(),
    category: d.category,
    method: d.method,
    detail: d.detail || "",
    source: d.source || "",
    frameUrl: d.frameUrl || "",
    isIframe: d.isIframe || false,
    tabTitle: d._tabTitle || "",
    stack: d.stack || "",
  }));
}

function buildLogCSV() {
  const headers = ["timestamp", "category", "method", "detail", "source", "frameUrl", "isIframe"];
  const rows = [headers.join(",")];
  for (const d of getAllLogEntries()) {
    const row = [
      new Date(d.ts).toISOString(),
      d.category,
      d.method,
      d.detail || "",
      d.source || "",
      d.frameUrl || "",
      d.isIframe ? "true" : "false",
    ].map(v => `"${v.replace(/"/g, '""')}"`);
    rows.push(row.join(","));
  }
  return rows.join("\n");
}

document.getElementById("export-summary-json").addEventListener("click", () => {
  buildSummaryExport((summary) => {
    if (!summary) return;
    downloadFile(
      `fp-summary-${timestamp()}.json`,
      JSON.stringify(summary, null, 2),
      "application/json"
    );
  });
});

document.getElementById("export-log-json").addEventListener("click", () => {
  const log = buildLogExport();
  downloadFile(
    `fp-log-${timestamp()}.json`,
    JSON.stringify(log, null, 2),
    "application/json"
  );
});

document.getElementById("export-log-csv").addEventListener("click", () => {
  downloadFile(
    `fp-log-${timestamp()}.csv`,
    buildLogCSV(),
    "text/csv"
  );
});

document.getElementById("export-all-json").addEventListener("click", () => {
  buildSummaryExport((summary) => {
    const report = {
      summary: summary || {},
      log: buildLogExport(),
    };
    downloadFile(
      `fp-report-${timestamp()}.json`,
      JSON.stringify(report, null, 2),
      "application/json"
    );
  });
});

// ── Multi-tab watching ─────────────────────────────────────────────────
const tabSelector = document.getElementById("tab-selector");
// watchedTabs declared earlier (near logEntriesByTab)
const tabInfoMap = {};         // tabId -> { title, url, favIconUrl }
let activeTabId = null;
let port = null;

function shortenTitle(title) {
  return title.length > 22 ? title.slice(0, 20) + "..." : title;
}

function watchTab(tabId) {
  if (watchedTabs.has(tabId)) return;
  watchedTabs.add(tabId);
  port.postMessage({ type: "watch-tab", tabId });
  renderTabSelector();
  saveUIState();
}

function unwatchTab(tabId) {
  if (!watchedTabs.has(tabId) || tabId === activeTabId) return;
  watchedTabs.delete(tabId);
  port.postMessage({ type: "unwatch-tab", tabId });
  renderTabSelector();
  saveUIState();
  refilterLog(); // remove entries from unwatched tab
}

function renderTabSelector() {
  // Only show if more than 1 tab has data
  const allTabs = Object.keys(tabInfoMap).map(Number);
  tabSelector.classList.toggle("active", allTabs.length > 1);
  if (allTabs.length <= 1) return;

  // Remove existing chips
  tabSelector.querySelectorAll(".tab-chip").forEach(c => c.remove());

  for (const id of allTabs) {
    const info = tabInfoMap[id];
    if (!info) continue;
    const isWatching = watchedTabs.has(id);

    const chip = document.createElement("span");
    chip.className = "tab-chip" + (isWatching ? " watching" : "");
    chip.title = `${info.url}\n${isWatching ? "Click to unwatch" : "Click to watch"} (${info.detectionCount} events)`;

    let inner = "";
    if (info.favIconUrl) {
      inner += `<img class="tab-chip-favicon" src="${escapeHtml(info.favIconUrl)}" onerror="this.style.display='none'">`;
    }
    inner += escapeHtml(shortenTitle(info.title));
    inner += ` <span class="chip-count">${info.detectionCount}</span>`;
    chip.innerHTML = inner;

    chip.addEventListener("click", () => {
      if (isWatching) {
        unwatchTab(id);
      } else {
        watchTab(id);
      }
    });

    tabSelector.appendChild(chip);
  }
}

function refreshTabList() {
  chrome.runtime.sendMessage({ type: "get-tabs-with-data" }, (tabs) => {
    if (!tabs) return;
    for (const t of tabs) {
      tabInfoMap[t.tabId] = t;
    }
    renderTabSelector();
  });
}

// ── Persist UI state across popup reopens ──────────────────────────────
// chrome.storage.session = RAM-only, survives popup close but not browser restart.
// Log data comes from the background backlog, so only UI prefs need saving.
const sessionStore = chrome.storage.session || chrome.storage.local; // session preferred, local fallback

function saveUIState() {
  sessionStore.set({
    uiPaused: paused,
    uiFilter: logFilter.value,
    uiAutoscroll: logAutoscroll.checked,
    uiWatchedTabs: [...watchedTabs],
    uiActivePanel: document.querySelector(".tab.active")?.dataset.panel || "summary-panel",
  });
}

// Save on every change
logFilter.addEventListener("input", saveUIState);
logAutoscroll.addEventListener("change", saveUIState);

// ── Load everything and connect ───────────────────────────────────────
chrome.storage.local.get(["mutedMethods", "mutedCategories"], (localStored) => {
  if (localStored.mutedMethods) {
    for (const m of localStored.mutedMethods) mutedMethods.add(m);
  }
  if (localStored.mutedCategories) {
    for (const c of localStored.mutedCategories) mutedCategories.add(c);
  }
  renderMuteBar();

  sessionStore.get(["uiPaused", "uiFilter", "uiAutoscroll", "uiWatchedTabs", "uiActivePanel"], (ui) => {
    // Restore UI state
    if (ui.uiPaused) {
      paused = true;
      logPause.textContent = "Resume";
      logPause.classList.add("paused");
    }
    if (ui.uiFilter) {
      logFilter.value = ui.uiFilter;
    }
    if (ui.uiAutoscroll === false) {
      logAutoscroll.checked = false;
    }
    if (ui.uiActivePanel) {
      document.querySelectorAll(".tab").forEach(t => {
        t.classList.toggle("active", t.dataset.panel === ui.uiActivePanel);
      });
      document.querySelectorAll(".panel").forEach(p => {
        p.classList.toggle("active", p.id === ui.uiActivePanel);
      });
    }

    const savedWatchedTabs = ui.uiWatchedTabs || [];

    updateCounter();

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      activeTabId = tabs[0]?.id;
      if (!activeTabId) return;

      port = chrome.runtime.connect({ name: "fp-log" });

      // Always watch the active tab
      port.postMessage({ type: "watch-tab", tabId: activeTabId });
      watchedTabs.add(activeTabId);

      // Restore previously watched extra tabs
      for (const tabId of savedWatchedTabs) {
        if (tabId !== activeTabId) {
          port.postMessage({ type: "watch-tab", tabId });
          watchedTabs.add(tabId);
        }
      }

      port.onMessage.addListener((msg) => {
        if (msg.type === "fp-batch") {
          const tabId = msg.tabId;
          for (const d of msg.data) {
            d._tabId = tabId;
            d._tabTitle = tabInfoMap[tabId]?.title || "";
          }
          if (paused) {
            pausedQueue.push(...msg.data);
            updateCounter();
          } else {
            addLogBatch(msg.data);
          }
        }
      });

      chrome.runtime.sendMessage({ type: "get-detections", tabId: activeTabId }, renderSummary);

      refreshTabList();
      setInterval(refreshTabList, 3000);
    });
  });
});
