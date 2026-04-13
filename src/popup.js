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
  HeadlessDetect: { icon: "🤖", color: "#e94560", risk: "high",   desc: "Headless/automation detection — navigator.webdriver, visualViewport, share API" },
  ExtensionDetect:{ icon: "🧩", color: "#e94560", risk: "high",   desc: "Extension detection — probing chrome-extension:// URLs, injected CSS, or DOM changes" },
  Behavior:       { icon: "🖱️", color: "#e94560", risk: "high",   desc: "Behavioral biometrics — mouse movement, keystroke dynamics, touch, pointer, scroll tracking" },
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
  } catch {
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

// ── Version from manifest ─────────────────────────────────────────────
document.getElementById("footer").textContent =
  "Fingerprint Detector v" + chrome.runtime.getManifest().version;

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

  // Category mute buttons — click = domain, right-click = global
  content.querySelectorAll("[data-mute-cat]").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const cat = btn.dataset.muteCat;
      if (mutedCategories.has(cat)) {
        removeMute("category", cat);
      } else {
        addMute("category", cat, "domain");
      }
      chrome.runtime.sendMessage({ type: "get-detections" }, renderSummary);
    });
    btn.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const cat = btn.dataset.muteCat;
      if (!mutedCategories.has(cat)) {
        addMute("category", cat, "global");
        chrome.runtime.sendMessage({ type: "get-detections" }, renderSummary);
      }
    });
  });

  // Method mute buttons — click = domain, right-click = global
  content.querySelectorAll("[data-mute-method]").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const method = btn.dataset.muteMethod;
      if (mutedMethods.has(method)) {
        removeMute("method", method);
      } else {
        addMute("method", method, "domain");
      }
      chrome.runtime.sendMessage({ type: "get-detections" }, renderSummary);
    });
    btn.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const method = btn.dataset.muteMethod;
      if (!mutedMethods.has(method)) {
        addMute("method", method, "global");
        chrome.runtime.sendMessage({ type: "get-detections" }, renderSummary);
      }
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
// Flat list of entries for the single watched tab. Multi-tab watching
// was removed — the popup always shows the currently active browser
// tab, and switching tabs closes the popup (MV3 behavior), so each
// popup session is scoped to one tab.
const logEntries = [];
let logCount = 0;
let paused = false;
let pausedQueue = [];
const MAX_LOG_ENTRIES = 3000;

function getAllLogEntries() {
  return logEntries;
}

const MAX_DOM_NODES = 500;
let domNodeCount = 0;

// ── Mute System ───────────────────────────────────────────────────────
// Two layers: global mutes (apply everywhere) and per-domain mutes
// (apply only on that domain). Both persist via chrome.storage.local.
//
// Storage format:
//   mutedGlobal:   { methods: [...], categories: [...] }
//   mutedByDomain: { "google.com": { methods: [...], categories: [...] }, ... }
//
// Active mutes = global + current domain merged.

const mutedMethods = new Set();     // effective set (global + domain merged)
const mutedCategories = new Set();

// Raw stored data
let mutedGlobal = { methods: [], categories: [] };
let mutedByDomain = {}; // domain -> { methods: [], categories: [] }
let currentDomain = ""; // set once we know the active tab URL

function muteKey(d) {
  return d.method.replace(/ \(call #\d+\)$/, "");
}

function isMuted(d) {
  if (mutedCategories.has(d.category)) return true;
  // _muteKey is precomputed in storeLogEntry; fall back for safety.
  return mutedMethods.has(d._muteKey || muteKey(d));
}

function rebuildEffectiveMutes() {
  mutedMethods.clear();
  mutedCategories.clear();
  for (const m of mutedGlobal.methods) mutedMethods.add(m);
  for (const c of mutedGlobal.categories) mutedCategories.add(c);
  const domainMutes = mutedByDomain[currentDomain];
  if (domainMutes) {
    for (const m of domainMutes.methods) mutedMethods.add(m);
    for (const c of domainMutes.categories) mutedCategories.add(c);
  }
}

function saveMutes() {
  chrome.storage.local.set({ mutedGlobal, mutedByDomain });
}

// scope: "global" or "domain"
function addMute(type, value, scope) {
  scope = scope || "domain"; // default to per-domain
  if (scope === "global") {
    if (type === "method") { if (!mutedGlobal.methods.includes(value)) mutedGlobal.methods.push(value); }
    else { if (!mutedGlobal.categories.includes(value)) mutedGlobal.categories.push(value); }
  } else {
    if (!mutedByDomain[currentDomain]) mutedByDomain[currentDomain] = { methods: [], categories: [] };
    const dm = mutedByDomain[currentDomain];
    if (type === "method") { if (!dm.methods.includes(value)) dm.methods.push(value); }
    else { if (!dm.categories.includes(value)) dm.categories.push(value); }
  }
  rebuildEffectiveMutes();
  saveMutes();
  renderMuteBar();
  refilterLog();
}

function removeMute(type, value) {
  // Remove from both global and domain
  if (type === "method") {
    mutedGlobal.methods = mutedGlobal.methods.filter(m => m !== value);
    if (mutedByDomain[currentDomain]) {
      mutedByDomain[currentDomain].methods = mutedByDomain[currentDomain].methods.filter(m => m !== value);
    }
  } else {
    mutedGlobal.categories = mutedGlobal.categories.filter(c => c !== value);
    if (mutedByDomain[currentDomain]) {
      mutedByDomain[currentDomain].categories = mutedByDomain[currentDomain].categories.filter(c => c !== value);
    }
  }
  rebuildEffectiveMutes();
  saveMutes();
  renderMuteBar();
  refilterLog();
}

function isGlobalMute(type, value) {
  if (type === "method") return mutedGlobal.methods.includes(value);
  return mutedGlobal.categories.includes(value);
}


function renderMuteBar() {
  const hasMutes = mutedMethods.size > 0 || mutedCategories.size > 0;
  muteBar.classList.toggle("active", hasMutes);

  // Remove existing tags (keep the label)
  muteBar.querySelectorAll(".mute-tag").forEach(t => t.remove());

  for (const cat of mutedCategories) {
    const isGlobal = isGlobalMute("category", cat);
    const tag = document.createElement("span");
    tag.className = "mute-tag";
    tag.title = `Click to unmute (${isGlobal ? "global" : currentDomain})`;
    tag.innerHTML = `${escapeHtml(cat)} <span style="opacity:0.5;font-size:9px">${isGlobal ? "all" : escapeHtml(currentDomain)}</span> <span class="x">&times;</span>`;
    tag.addEventListener("click", () => removeMute("category", cat));
    muteBar.appendChild(tag);
  }
  for (const method of mutedMethods) {
    const isGlobal = isGlobalMute("method", method);
    const tag = document.createElement("span");
    tag.className = "mute-tag";
    tag.title = `Click to unmute (${isGlobal ? "global" : currentDomain})`;
    tag.innerHTML = `${escapeHtml(method)} <span style="opacity:0.5;font-size:9px">${isGlobal ? "all" : escapeHtml(currentDomain)}</span> <span class="x">&times;</span>`;
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
  // Precompute derived fields once at store time so the filter loop
  // and buildLogNode don't have to recompute them on every render /
  // refilter keystroke:
  //   _hay     — lowercased haystack used by matchesFilter
  //   _muteKey — string used by isMuted and the mute button
  // On a 3000-entry buffer, refilter-on-keystroke would otherwise
  // rebuild these strings 3000 times per keystroke.
  if (!d._hay) {
    d._hay = (d.category + " " + d.method + " " + (d.detail || "") + " " +
              (d.source || "") + " " + (d.frameUrl || "")).toLowerCase();
  }
  if (!d._muteKey) {
    d._muteKey = muteKey(d);
  }
  logEntries.push(d);
  if (logEntries.length > MAX_LOG_ENTRIES) logEntries.shift();
}

function addLogBatch(events) {
  const filter = logFilter.value.toLowerCase();
  const frag = document.createDocumentFragment();
  let added = 0;

  // Fast path: when a giant batch arrives (popup open / tab switch
  // dumps up to 2000 existing detections at once), only build DOM
  // nodes for events that would actually remain after trimDOM. This
  // avoids ~1500 wasted buildLogNode + trimDOM cycles on the common
  // "open popup on a heavy-fingerprinting site" path.
  let startIdx = 0;
  if (events.length > MAX_DOM_NODES) {
    // Everything that was already in the DOM will be trimmed out anyway.
    logList.innerHTML = "";
    domNodeCount = 0;
    // Store the skipped events in the buffer but don't build nodes.
    const skipUntil = events.length - MAX_DOM_NODES;
    for (let i = 0; i < skipUntil; i++) {
      logCount++;
      storeLogEntry(events[i]);
    }
    startIdx = skipUntil;
  }

  for (let i = startIdx; i < events.length; i++) {
    const d = events[i];
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
      setScrollTop(logList, logList.scrollHeight);
    }
  }

  updateCounter();
}

// Auto-disable auto-scroll when user scrolls up manually
let userScrolling = false;
logList.addEventListener("scroll", () => {
  if (userScrolling) return;
  // If scrolled more than 50px from the bottom, user is reading — disable auto-scroll
  const atBottom = logList.scrollHeight - logList.scrollTop - logList.clientHeight < 50;
  if (!atBottom && logAutoscroll.checked) {
    logAutoscroll.checked = false;
    saveUIState();
  } else if (atBottom && !logAutoscroll.checked) {
    logAutoscroll.checked = true;
    saveUIState();
  }
});

// Flag programmatic scrolls so the scroll listener doesn't interfere
const _origScrollTop = Object.getOwnPropertyDescriptor(Element.prototype, "scrollTop");
function setScrollTop(el, val) {
  userScrolling = true;
  el.scrollTop = val;
  requestAnimationFrame(() => { userScrolling = false; });
}

function updateCounter() {
  const muted = mutedMethods.size + mutedCategories.size;
  let text = `${logCount} events`;
  if (paused && pausedQueue.length > 0) text = `${logCount} + ${pausedQueue.length} queued`;
  if (muted > 0) text += ` (${muted} muted)`;
  logCounter.textContent = text;
}

function matchesFilter(d, filter) {
  // _hay is precomputed in storeLogEntry; fall back for any entry
  // that hasn't gone through storeLogEntry yet (shouldn't happen).
  const hay = d._hay || (d._hay = (d.category + " " + d.method + " " +
    (d.detail || "") + " " + (d.source || "") + " " + (d.frameUrl || "")).toLowerCase());
  return hay.includes(filter);
}

function buildLogNode(d, parent) {
  const meta = CATEGORY_META[d.category];
  const icon = meta?.icon || "?";
  const iframeTag = d.isIframe ? ` <span class="iframe-tag">IFRAME</span>` : "";
  const mk = d._muteKey || muteKey(d);

  const row = document.createElement("div");
  row.className = "log-entry";
  row.innerHTML =
    `<div class="log-row">` +
      `<span class="log-ts">${formatTimePrecise(d.ts)}</span>` +
      `<span class="log-cat ${riskClass(d.category)}">${icon} ${escapeHtml(d.category)}${iframeTag}</span>` +
      `<span class="log-method">${escapeHtml(d.method)}</span>` +
      `<span class="log-detail" title="${escapeHtml(d.detail || "")}">${escapeHtml(d.detail || "")}</span>` +
      `<button class="mute-btn" data-mute-method="${escapeHtml(mk)}" title="Click: mute on this site | Right-click: mute on all sites">&#x1F507;</button>` +
    `</div>` +
    (d.source ? `<div class="log-source" title="${escapeHtml(d.source)}">${escapeHtml(shortenUrl(d.source))}</div>` : "") +
    (d.isIframe && d.frameUrl ? `<div class="log-frame" title="${escapeHtml(d.frameUrl)}">iframe: ${escapeHtml(shortenUrl(d.frameUrl))}</div>` : "");

  // Mute button — click = mute method on this domain
  const muteBtn = row.querySelector(".mute-btn");
  muteBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    addMute("method", mk, "domain");
  });

  // Right-click mute button — mute entire category on all sites
  muteBtn.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    e.stopPropagation();
    addMute("category", d.category, "global");
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
    const prevScroll = logList.scrollTop; // save before rebuild
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
    setScrollTop(logList, prevScroll);
  }, 150);
}

logFilter.addEventListener("input", refilterLog);

logClear.addEventListener("click", () => {
  logEntries.length = 0;
  logCount = 0;
  domNodeCount = 0;
  pausedQueue = [];
  logList.innerHTML = "";
  updateCounter();
});

// ── Compare ────────────────────────────────────────────────────────────
// Opens compare.html in a new browser tab with the current summary pre-loaded.
document.getElementById("compare-btn").addEventListener("click", () => {
  buildSummaryExport((summary) => {
    if (!summary) {
      alert("No fingerprinting data to compare — visit a site first.");
      return;
    }
    // Save to session storage so compare.html can pick it up
    chrome.storage.session.set({ compareLeftData: summary }, () => {
      chrome.tabs.create({ url: chrome.runtime.getURL("src/compare.html") });
    });
  });
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

// Build a filesystem-safe site slug from the current tab URL.
// "https://www.google.com/search?q=..." → "google.com"
// Strips protocol, www, path, query, and any filesystem-unsafe characters.
function siteSlug() {
  const url = activeTabInfo.url || "";
  if (!url) return "";
  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    // Replace any remaining unsafe filename chars with underscore
    return host.replace(/[^a-z0-9.-]/gi, "_");
  } catch {
    return "";
  }
}

// Compose a filename with optional site slug
function makeFilename(prefix, ext) {
  const slug = siteSlug();
  return slug
    ? `${prefix}-${slug}-${timestamp()}.${ext}`
    : `${prefix}-${timestamp()}.${ext}`;
}

// Extract domain from a URL string (preserves subdomain)
function extractDomain(url) {
  if (!url) return "";
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

// Build a domain breakdown from detections: { "ads.google.com": { categories: [...], calls: N }, ... }
function buildDomainSummary(detections) {
  const domains = {};
  for (const d of detections) {
    const sources = [d.source, d.frameUrl].map(extractDomain).filter(Boolean);
    for (const domain of sources) {
      if (!domains[domain]) {
        domains[domain] = { calls: 0, categories: new Set(), methods: new Set(), isThirdParty: false };
      }
      domains[domain].calls++;
      domains[domain].categories.add(d.category);
      domains[domain].methods.add(d.method);
    }
  }

  // Determine first-party domain from the page URL
  const pageUrl = activeTabInfo.url || "";
  const pageDomain = extractDomain(pageUrl);
  // Get the registrable domain (last two parts) for comparison
  const pageBase = pageDomain.split(".").slice(-2).join(".");

  // Convert Sets to arrays and flag third-party
  const result = {};
  const sortedDomains = Object.keys(domains).sort((a, b) => domains[b].calls - domains[a].calls);
  for (const domain of sortedDomains) {
    const info = domains[domain];
    const domainBase = domain.split(".").slice(-2).join(".");
    result[domain] = {
      calls: info.calls,
      categories: [...info.categories].sort(),
      methods: [...info.methods].sort(),
      isThirdParty: domainBase !== pageBase,
    };
  }
  return result;
}

function buildSummaryExport(callback) {
  chrome.runtime.sendMessage({ type: "get-detections", tabId: activeTabId }, (response) => {
    if (!response) { callback(null); return; }
    const { categories, detections } = response;
    const riskOrder = { high: 0, medium: 1, low: 2 };
    const cats = Object.keys(categories).sort((a, b) => {
      const ra = riskOrder[CATEGORY_META[a]?.risk] ?? 2;
      const rb = riskOrder[CATEGORY_META[b]?.risk] ?? 2;
      return ra - rb;
    });

    const summary = {
      exportedAt: new Date().toISOString(),
      url: activeTabInfo.url || "",
      riskLevel: getRiskLevel(categories).label,
      totalTechniques: cats.length,
      totalCalls: detections.length,
      domains: buildDomainSummary(detections),
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
          sourceDomain: extractDomain(d.source),
          frameUrl: d.isIframe ? d.frameUrl : undefined,
          frameDomain: d.isIframe ? extractDomain(d.frameUrl) : undefined,
        })),
      };
    }

    // Fetch full extension probe list from the page's inject.js
    chrome.runtime.sendMessage({ type: "get-ext-ids", tabId: activeTabId }, (extData) => {
      if (extData && extData.ids && extData.ids.length > 0) {
        summary.extensionProbes = {
          totalProbes: extData.total,
          uniqueExtensionIds: extData.ids,
        };
      }
      callback(summary);
    });
  });
}

function buildLogExport() {
  const entries = getAllLogEntries().map(d => ({
    timestamp: new Date(d.ts).toISOString(),
    category: d.category,
    method: d.method,
    detail: d.detail || "",
    source: d.source || "",
    sourceDomain: extractDomain(d.source),
    frameUrl: d.frameUrl || "",
    frameDomain: extractDomain(d.frameUrl),
    isIframe: d.isIframe || false,
    stack: d.stack || "",
  }));
  return {
    exportedAt: new Date().toISOString(),
    url: activeTabInfo.url || "",
    tabTitle: activeTabInfo.title || "",
    totalEntries: entries.length,
    entries,
  };
}

function buildLogCSV() {
  const url = activeTabInfo.url || "";
  const exportedAt = new Date().toISOString();
  // Prepend metadata as CSV comments (Excel/Sheets treat # lines as data, so
  // use a header row approach instead — two metadata rows before the data header)
  const rows = [
    `# Fingerprint Detector Export`,
    `# Exported: ${exportedAt}`,
    `# URL: ${url}`,
    `# Total entries: ${getAllLogEntries().length}`,
    "",
  ];
  const headers = ["timestamp", "category", "method", "detail", "source", "sourceDomain", "frameUrl", "frameDomain", "isIframe"];
  rows.push(headers.join(","));
  for (const d of getAllLogEntries()) {
    const row = [
      new Date(d.ts).toISOString(),
      d.category,
      d.method,
      d.detail || "",
      d.source || "",
      extractDomain(d.source),
      d.frameUrl || "",
      extractDomain(d.frameUrl),
      d.isIframe ? "true" : "false",
    ].map(v => `"${String(v).replace(/"/g, '""')}"`);
    rows.push(row.join(","));
  }
  return rows.join("\n");
}

document.getElementById("export-summary-json").addEventListener("click", () => {
  buildSummaryExport((summary) => {
    if (!summary) return;
    downloadFile(
      makeFilename("fp-summary", "json"),
      JSON.stringify(summary, null, 2),
      "application/json"
    );
  });
});

document.getElementById("export-log-json").addEventListener("click", () => {
  const log = buildLogExport();
  downloadFile(
    makeFilename("fp-log", "json"),
    JSON.stringify(log, null, 2),
    "application/json"
  );
});

document.getElementById("export-log-csv").addEventListener("click", () => {
  downloadFile(
    makeFilename("fp-log", "csv"),
    buildLogCSV(),
    "text/csv"
  );
});

document.getElementById("export-all-json").addEventListener("click", () => {
  buildSummaryExport((summary) => {
    const report = {
      exportedAt: new Date().toISOString(),
      url: activeTabInfo.url || "",
      tabTitle: activeTabInfo.title || "",
      summary: summary || {},
      log: buildLogExport(),
    };
    downloadFile(
      makeFilename("fp-report", "json"),
      JSON.stringify(report, null, 2),
      "application/json"
    );
  });
});

// ── Active tab tracking ────────────────────────────────────────────────
// The popup is scoped to the currently-active browser tab for its
// entire lifetime (MV3 popups close when the user switches tabs).
// No multi-tab watching, no polling, no tab switcher.
let activeTabId = null;
const activeTabInfo = { url: "", title: "", favIconUrl: "" };
let port = null;

// ── Persist UI state across popup reopens ──────────────────────────────
// chrome.storage.session = RAM-only, survives popup close but not browser restart.
// Log data comes from the background backlog, so only UI prefs need saving.
const sessionStore = chrome.storage.session || chrome.storage.local; // session preferred, local fallback

function saveUIState() {
  sessionStore.set({
    uiPaused: paused,
    uiFilter: logFilter.value,
    uiAutoscroll: logAutoscroll.checked,
    uiActivePanel: document.querySelector(".tab.active")?.dataset.panel || "summary-panel",
  });
}

// Save on every change
logFilter.addEventListener("input", saveUIState);
logAutoscroll.addEventListener("change", saveUIState);

// ── Load everything and connect ───────────────────────────────────────
chrome.storage.local.get(["mutedGlobal", "mutedByDomain"], (localStored) => {
  if (localStored.mutedGlobal) {
    mutedGlobal = localStored.mutedGlobal;
  }
  if (localStored.mutedByDomain) {
    mutedByDomain = localStored.mutedByDomain;
  }

  sessionStore.get(["uiPaused", "uiFilter", "uiAutoscroll", "uiActivePanel"], (ui) => {
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

    updateCounter();

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      activeTabId = tabs[0]?.id;
      if (!activeTabId) return;

      // Set current domain for per-domain mutes
      try {
        currentDomain = new URL(tabs[0].url).hostname;
      } catch {
        currentDomain = "";
      }
      rebuildEffectiveMutes();
      renderMuteBar();

      activeTabInfo.url = tabs[0].url || "";
      activeTabInfo.title = tabs[0].title || "";
      activeTabInfo.favIconUrl = tabs[0].favIconUrl || "";

      port = chrome.runtime.connect({ name: "fp-log" });
      port.postMessage({ type: "watch-tab", tabId: activeTabId });

      port.onMessage.addListener((msg) => {
        if (msg.type === "fp-batch") {
          if (paused) {
            pausedQueue.push(...msg.data);
            updateCounter();
          } else {
            addLogBatch(msg.data);
          }
        }
      });

      chrome.runtime.sendMessage({ type: "get-detections", tabId: activeTabId }, renderSummary);
    });
  });
});
