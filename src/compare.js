// compare.js — Compare two fingerprint summaries side-by-side

// ── Cached DOM references (queried once at init) ──────────────────────
const $container = document.querySelector(".container");
const $diffSummary = document.getElementById("diff-summary");
const $domainsSection = document.getElementById("domains-section");

// Side element cache — built once per load, reused on every render
const $sides = {
  left: {
    url: document.getElementById("left-url"),
    body: document.getElementById("left-body"),
    file: document.getElementById("left-file"),
    load: document.getElementById("left-load"),
  },
  right: {
    url: document.getElementById("right-url"),
    body: document.getElementById("right-body"),
    file: document.getElementById("right-file"),
    load: document.getElementById("right-load"),
  },
  center: {
    url: document.getElementById("center-url"),
    body: document.getElementById("center-body"),
    file: document.getElementById("center-file"),
    load: document.getElementById("center-load"),
  },
};

// ── Theme (read-only) ─────────────────────────────────────────────────
// The popup owns the theme toggle. Compare follows it: load the
// current value at init and live-update if the user flips it from the
// popup while compare is open.
function applyTheme(theme) {
  document.body.classList.toggle("light", theme === "light");
}

chrome.storage.local.get(["theme"], (stored) => {
  applyTheme(stored.theme || "dark");
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.theme) applyTheme(changes.theme.newValue);
});

const CATEGORY_META = {
  Canvas:         { icon: "\u{1F3A8}", color: "#e94560", risk: "high" },
  WebGL:          { icon: "\u{1F53A}", color: "#e94560", risk: "high" },
  Audio:          { icon: "\u{1F50A}", color: "#e94560", risk: "high" },
  Fonts:          { icon: "\u{1F524}", color: "#fb8c00", risk: "high" },
  WebRTC:         { icon: "\u{1F4E1}", color: "#e94560", risk: "high" },
  Navigator:      { icon: "\u{1F9ED}", color: "#fb8c00", risk: "medium" },
  Screen:         { icon: "\u{1F5A5}", color: "#43a047", risk: "low" },
  Timezone:       { icon: "\u{1F550}", color: "#43a047", risk: "low" },
  ClientRects:    { icon: "\u{1F4D0}", color: "#fb8c00", risk: "medium" },
  Storage:        { icon: "\u{1F4BE}", color: "#43a047", risk: "low" },
  Permissions:    { icon: "\u{1F512}", color: "#fb8c00", risk: "medium" },
  MediaDevices:   { icon: "\u{1F4F7}", color: "#e94560", risk: "high" },
  SpeechSynthesis:{ icon: "\u{1F5E3}", color: "#fb8c00", risk: "medium" },
  Network:        { icon: "\u{1F310}", color: "#43a047", risk: "low" },
  Plugins:        { icon: "\u{1F50C}", color: "#fb8c00", risk: "medium" },
  ClientHints:    { icon: "\u{1F3F7}", color: "#e94560", risk: "high" },
  GPC:            { icon: "\u{1F6E1}", color: "#fb8c00", risk: "medium" },
  WebSocket:      { icon: "\u{1F517}", color: "#fb8c00", risk: "medium" },
  DNT:            { icon: "\u{1F6AB}", color: "#fb8c00", risk: "medium" },
  MediaQuery:     { icon: "\u{1F39B}", color: "#fb8c00", risk: "medium" },
  Keyboard:       { icon: "\u2328",   color: "#e94560", risk: "high" },
  Timing:         { icon: "\u23F1",   color: "#fb8c00", risk: "medium" },
  WebGPU:         { icon: "\u{1F3AE}", color: "#e94560", risk: "high" },
  Hardware:       { icon: "\u{1F527}", color: "#e94560", risk: "high" },
  Sensors:        { icon: "\u{1F4F1}", color: "#e94560", risk: "high" },
  Touch:          { icon: "\u{1F446}", color: "#43a047", risk: "low" },
  Credentials:    { icon: "\u{1F511}", color: "#fb8c00", risk: "medium" },
  Math:           { icon: "\u{1F522}", color: "#e94560", risk: "high" },
  Architecture:   { icon: "\u{1F9EC}", color: "#e94560", risk: "high" },
  VendorDetect:   { icon: "\u{1F3E2}", color: "#fb8c00", risk: "medium" },
  AdBlockDetect:  { icon: "\u{1F6A7}", color: "#e94560", risk: "high" },
  ApplePay:       { icon: "\u{1F34E}", color: "#fb8c00", risk: "medium" },
  PrivateClick:   { icon: "\u{1F50F}", color: "#fb8c00", risk: "medium" },
  Intl:           { icon: "\u{1F30D}", color: "#fb8c00", risk: "medium" },
  HeadlessDetect: { icon: "\u{1F916}", color: "#e94560", risk: "high" },
  ExtensionDetect:{ icon: "\u{1F9E9}", color: "#e94560", risk: "high" },
  Behavior:       { icon: "\u{1F5B1}", color: "#e94560", risk: "high" },
  Crypto:         { icon: "\u{1F510}", color: "#fb8c00", risk: "medium" },
  FingerprintJSDetect: { icon: "\u{1F575}\u{FE0F}", color: "#e94560", risk: "high" },
  MatomoDetect:   { icon: "\u{1F4CA}", color: "#fb8c00", risk: "medium" },
  AkamaiBotManagerDetect: { icon: "\u{1F6E1}\u{FE0F}", color: "#e94560", risk: "high" },
  CloudflareBotManagementDetect: { icon: "\u{2601}\u{FE0F}", color: "#fb8c00", risk: "medium" },
  DataDomeDetect: { icon: "\u{1F3DB}\u{FE0F}", color: "#e94560", risk: "high" },
  PerimeterXDetect: { icon: "\u{1F6A7}", color: "#e94560", risk: "high" },
  ImpervaDetect: { icon: "\u{1F512}", color: "#fb8c00", risk: "medium" },
  KasadaDetect: { icon: "\u{1F3EF}", color: "#e94560", risk: "high" },
  PianoDetect:  { icon: "\u{1F3B9}", color: "#fb8c00", risk: "medium" },
  HotjarDetect: { icon: "\u{1F525}", color: "#fb8c00", risk: "medium" },
  MetaPixelDetect: { icon: "\u{1F4D8}", color: "#fb8c00", risk: "medium" },
  BingUETDetect: { icon: "\u{1F171}\u{FE0F}", color: "#fb8c00", risk: "medium" },
  ParselyDetect: { icon: "\u{1F4F0}", color: "#fb8c00", risk: "medium" },
  NewRelicBrowserDetect: { icon: "\u{1F4C8}", color: "#fb8c00", risk: "medium" },
  BlockthroughDetect: { icon: "\u{1F9E8}", color: "#e94560", risk: "high" },
  AdmiralDetect: { icon: "\u{2693}", color: "#e94560", risk: "high" },
  PubliftFuseDetect: { icon: "\u{1F3AF}", color: "#fb8c00", risk: "medium" },
  MediaNetDetect: { icon: "\u{1F310}", color: "#fb8c00", risk: "medium" },
  TealiumDetect: { icon: "\u{1F3F7}\u{FE0F}", color: "#fb8c00", risk: "medium" },
  WPComStatsDetect: { icon: "\u{1F4DD}", color: "#fb8c00", risk: "medium" },
  ScorecardResearchDetect: { icon: "\u{1F4FA}", color: "#fb8c00", risk: "medium" },
  GoogleTagDetect: { icon: "\u{1F50E}", color: "#fb8c00", risk: "medium" },
  GoogleGPTDetect: { icon: "\u{1F4E3}", color: "#fb8c00", risk: "medium" },
  YahooOathDetect: { icon: "\u{1F49C}", color: "#fb8c00", risk: "medium" },
  KameleoonDetect: { icon: "\u{1F9EA}", color: "#fb8c00", risk: "medium" },
  WebtrekkMappDetect: { icon: "\u{1F1E9}\u{1F1EA}", color: "#fb8c00", risk: "medium" },
  PushlyDetect: { icon: "\u{1F514}", color: "#fb8c00", risk: "medium" },
  QuantcastDetect: { icon: "\u{1F4D0}", color: "#fb8c00", risk: "medium" },
  ClarityDetect: { icon: "\u{1F3A5}", color: "#fb8c00", risk: "medium" },
  RUMVisionDetect: { icon: "\u{1F441}\u{FE0F}", color: "#fb8c00", risk: "medium" },
  NativoDetect: { icon: "\u{1FAB6}", color: "#fb8c00", risk: "medium" },
  GeniuslinkDetect: { icon: "\u{1F517}", color: "#fb8c00", risk: "medium" },
  GoogleFundingChoicesDetect: { icon: "\u{1F4B0}", color: "#fb8c00", risk: "medium" },
  ChartbeatDetect: { icon: "\u{1F4E1}", color: "#fb8c00", risk: "medium" },
  ZiffDavisDetect: { icon: "\u{1F5DE}\u{FE0F}", color: "#fb8c00", risk: "medium" },
  HubSpotDetect: { icon: "\u{1F9F2}", color: "#fb8c00", risk: "medium" },
  LinkedInInsightDetect: { icon: "\u{1F4BC}", color: "#fb8c00", risk: "medium" },
  NoibuDetect: { icon: "\u{1F6D2}", color: "#fb8c00", risk: "medium" },
  CriteoDetect: { icon: "\u{1F3AA}", color: "#fb8c00", risk: "medium" },
  OneTrustDetect: { icon: "\u{1F36A}", color: "#fb8c00", risk: "medium" },
  TranscendDetect: { icon: "\u{1F6E1}\u{FE0F}", color: "#fb8c00", risk: "medium" },
  AkamaiMPulseDetect: { icon: "\u{1FA83}", color: "#fb8c00", risk: "medium" },
  LogRocketDetect: { icon: "\u{1F680}", color: "#fb8c00", risk: "medium" },
  ThreatMetrixDetect: { icon: "\u{1F578}\u{FE0F}", color: "#e94560", risk: "high" },
  SpeedCurveLUXDetect: { icon: "\u{26A1}", color: "#fb8c00", risk: "medium" },
  InsiderDetect: { icon: "\u{1F381}", color: "#fb8c00", risk: "medium" },
  BrightEdgeDetect: { icon: "\u{1F9ED}", color: "#fb8c00", risk: "medium" },
  QualtricsDetect: { icon: "\u{1F4CB}", color: "#fb8c00", risk: "medium" },
  KlaviyoDetect: { icon: "\u{1F4E7}", color: "#fb8c00", risk: "medium" },
  AdobeDTMDetect: { icon: "\u{1F170}\u{FE0F}", color: "#fb8c00", risk: "medium" },
  AdobeCommerceEventsDetect: { icon: "\u{1F6CD}\u{FE0F}", color: "#fb8c00", risk: "medium" },
  AdobeCommerceRecsDetect: { icon: "\u{2728}", color: "#fb8c00", risk: "medium" },
  OsanoDetect: { icon: "\u{1F960}", color: "#fb8c00", risk: "medium" },
  SalesforceMCDetect: { icon: "\u{1F329}\u{FE0F}", color: "#fb8c00", risk: "medium" },
  AdobeHelixRUMDetect: { icon: "\u{1F332}", color: "#fb8c00", risk: "medium" },
  ElasticAPMDetect: { icon: "\u{1F50C}", color: "#fb8c00", risk: "medium" },
  SentryDetect: { icon: "\u{1FAB2}", color: "#fb8c00", risk: "medium" },
  AwinDetect: { icon: "\u{1FA9F}", color: "#fb8c00", risk: "medium" },
  BazaarvoiceDetect: { icon: "\u{2B50}", color: "#fb8c00", risk: "medium" },
  FigPiiDetect: { icon: "\u{1F9EB}", color: "#fb8c00", risk: "medium" },
  IubendaDetect: { icon: "\u{1F1EE}\u{1F1F9}", color: "#fb8c00", risk: "medium" },
  AccessiBeDetect: { icon: "\u{267F}", color: "#fb8c00", risk: "medium" },
  UsercentricsDetect: { icon: "\u{1F1EA}\u{1F1FA}", color: "#fb8c00", risk: "medium" },
  SwanDetect: { icon: "\u{1F9A2}", color: "#fb8c00", risk: "medium" },
  GlobalEDetect: { icon: "\u{1F6EB}", color: "#fb8c00", risk: "medium" },
  TrueVaultPolarisDetect: { icon: "\u{1F31F}", color: "#fb8c00", risk: "medium" },
  ListrakDetect: { icon: "\u{2709}\u{FE0F}", color: "#fb8c00", risk: "medium" },
  TrustedSiteDetect: { icon: "\u{1F6C2}", color: "#fb8c00", risk: "medium" },
  IntegralAdScienceDetect: { icon: "\u{1F52C}", color: "#fb8c00", risk: "medium" },
  AdobeAnalyticsDetect: { icon: "\u{1F150}", color: "#fb8c00", risk: "medium" },
  DynatraceDetect: { icon: "\u{1F409}", color: "#fb8c00", risk: "medium" },
  BranchDetect: { icon: "\u{1F33F}", color: "#fb8c00", risk: "medium" },
  CloudflareAnalyticsDetect: { icon: "\u{26C5}", color: "#fb8c00", risk: "medium" },
  SourcepointDetect: { icon: "\u{1F50F}", color: "#fb8c00", risk: "medium" },
  YotpoDetect: { icon: "\u{1F4AC}", color: "#fb8c00", risk: "medium" },
};

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = String(str);
  return div.innerHTML;
}

// ── State ─────────────────────────────────────────────────────────────
let leftData = null;
let rightData = null;
let centerData = null;
let leftFilename = ""; // filename of loaded file (or "current tab")
let rightFilename = "";
let centerFilename = "";
// 3-way mode is opt-in. Toggled via the "+ Add Site C" button in the
// header. When true, body.three-way is set so the layout switches to
// 3 columns and Site C is shown; the diff classification expands from
// 2-way (only A / only B / shared) to 7-way membership.
let threeWayMode = false;

// ── Loaders ───────────────────────────────────────────────────────────
// Convert a Debug Log JSON (flat entries array) into a Summary JSON
// (categories object) so the compare view can handle it.
function convertLogToSummary(logData) {
  const entries = logData.entries || [];
  const categories = {};
  const domains = {};

  for (const e of entries) {
    // Group by category
    if (!categories[e.category]) {
      categories[e.category] = {
        totalCalls: 0,
        uniqueMethods: [],
      };
    }
    const cat = categories[e.category];
    cat.totalCalls++;

    // Dedupe methods by method+detail combo
    const key = e.method + "|" + (e.detail || "");
    if (!cat._seen) cat._seen = new Set();
    if (!cat._seen.has(key)) {
      cat._seen.add(key);
      cat.uniqueMethods.push({
        method: e.method,
        detail: e.detail || "",
        source: e.source || "",
        frameUrl: e.isIframe ? e.frameUrl : undefined,
      });
    }

    // Accumulate domains
    if (e.sourceDomain) {
      if (!domains[e.sourceDomain]) {
        domains[e.sourceDomain] = { calls: 0, categories: new Set() };
      }
      domains[e.sourceDomain].calls++;
      domains[e.sourceDomain].categories.add(e.category);
    }
  }

  // Clean up dedupe state
  for (const cat of Object.values(categories)) {
    delete cat._seen;
  }
  // Convert domain Sets to arrays
  for (const d of Object.keys(domains)) {
    domains[d].categories = [...domains[d].categories];
  }

  // Compute risk level from category mix
  const catNames = Object.keys(categories);
  const highRiskCats = ["Canvas", "WebGL", "Audio", "Fonts", "WebRTC", "ClientHints",
    "MediaDevices", "Math", "Architecture", "WebGPU", "Hardware", "Sensors",
    "Keyboard", "AdBlockDetect", "ExtensionDetect", "HeadlessDetect", "Behavior"];
  const hasHigh = catNames.some(c => highRiskCats.includes(c));
  let riskLevel = "No Risk";
  if (hasHigh && catNames.length >= 4) riskLevel = "High Risk";
  else if (hasHigh || catNames.length >= 3) riskLevel = "Medium Risk";
  else if (catNames.length > 0) riskLevel = "Low Risk";

  return {
    exportedAt: logData.exportedAt,
    url: logData.url || "",
    riskLevel,
    totalTechniques: catNames.length,
    totalCalls: entries.length,
    domains,
    categories,
    _convertedFromLog: true,
  };
}

// Convert a Trackers JSON ({ libraries: [...] }) into a Summary JSON
// (categories object). Each detected library becomes a synthetic
// category whose uniqueMethods are its signals.
//
// Trackers signals share generic method labels ("Cookie key",
// "Global variable", "Script URL match"), so the bare label isn't
// distinctive enough for the diff — two sites both seeing different
// cookies would still count as a "shared method". To match on the
// actual values, we fold the detail into the method field as
// "method: detail" so the diff sees the full signal as the identifier.
// The original detail is preserved separately for the per-row UI.
function convertTrackersToSummary(trackersData) {
  const libs = trackersData.libraries || [];
  const categories = {};
  let totalCalls = 0;

  for (const lib of libs) {
    const cat = lib.category || lib.name;
    if (!cat) continue;
    const signals = Array.isArray(lib.signals) ? lib.signals : [];
    categories[cat] = {
      totalCalls: lib.totalEvents || signals.length,
      uniqueMethods: signals.map(s => {
        const m = s.method || "";
        const d = s.detail || "";
        return {
          method: d ? (m ? m + ": " + d : d) : m,
          detail: d,
          source: "",
        };
      }),
    };
    totalCalls += categories[cat].totalCalls;
  }

  const catNames = Object.keys(categories);
  let riskLevel = "No Risk";
  if (catNames.length >= 4) riskLevel = "High Risk";
  else if (catNames.length >= 2) riskLevel = "Medium Risk";
  else if (catNames.length > 0) riskLevel = "Low Risk";

  return {
    exportedAt: trackersData.exportedAt,
    url: trackersData.url || "",
    riskLevel,
    totalTechniques: catNames.length,
    totalCalls,
    domains: {},
    categories,
    _convertedFromTrackers: true,
  };
}

function loadFromFile(file, side) {
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const json = JSON.parse(e.target.result);
      // Detect format and convert if needed:
      // 1. Full report: { summary: {...}, log: [...] } → use summary
      // 2. Summary: { categories: {...} } → use as-is
      // 3. Debug log: { entries: [...] } → convert to summary shape
      // 4. Trackers: { libraries: [...] } → convert to summary shape
      let data;
      if (json.summary && json.summary.categories) {
        data = json.summary;
      } else if (json.categories) {
        data = json;
      } else if (Array.isArray(json.libraries)) {
        data = convertTrackersToSummary(json);
      } else if (Array.isArray(json.entries)) {
        data = convertLogToSummary(json);
      } else if (Array.isArray(json)) {
        // Legacy: bare array of log entries
        data = convertLogToSummary({ entries: json });
      } else {
        alert("This file doesn't look like a Fingerprint Detector export.");
        return;
      }
      if (!data.categories) {
        alert("This file doesn't look like a Fingerprint Detector export.");
        return;
      }
      if (side === "left") {
        leftData = data;
        leftFilename = file.name;
        renderSide("left", data, file.name);
      } else if (side === "center") {
        centerData = data;
        centerFilename = file.name;
        renderSide("center", data, file.name);
      } else {
        rightData = data;
        rightFilename = file.name;
        renderSide("right", data, file.name);
      }
      maybeRenderDiff();
    } catch (err) {
      alert("Failed to parse file: " + err.message);
    }
  };
  reader.readAsText(file);
}

// ── Rendering ─────────────────────────────────────────────────────────
function renderSide(side, data, filename) {
  const refs = $sides[side];
  const urlEl = refs.url;
  const bodyEl = refs.body;

  // Show URL + filename in brackets (if loaded from a file)
  const url = data.url || "(unknown URL)";
  const fname = filename || (
    side === "left" ? leftFilename :
    side === "center" ? centerFilename :
    rightFilename
  );
  urlEl.textContent = fname ? url + " [" + fname + "]" : url;
  urlEl.title = fname ? url + "\nFile: " + fname : url;

  // Also show exportedAt timestamp if present
  const exportedAt = data.exportedAt ? " — exported " + new Date(data.exportedAt).toLocaleString() : "";

  const cats = Object.keys(data.categories || {});
  const risk = data.riskLevel || "unknown";

  const convertedBadge = data._convertedFromLog
    ? `<span class="badge none" title="Converted from debug log format — some metadata may be approximated">from log</span>`
    : "";

  const html = `<div class="summary-stats">
    <span class="badge ${riskClass(risk)}">${escapeHtml(risk)}</span>
    <span class="badge none">${cats.length} techniques</span>
    <span class="badge none">${data.totalCalls || 0} total calls</span>
    ${convertedBadge}
    ${exportedAt ? `<span class="badge none" title="${escapeHtml(data.exportedAt)}">${escapeHtml(exportedAt)}</span>` : ""}
  </div>
  <div class="categories" id="${side}-categories"></div>`;

  bodyEl.innerHTML = html;
}

function riskClass(label) {
  const l = String(label).toLowerCase();
  if (l.indexOf("high") !== -1) return "high";
  if (l.indexOf("medium") !== -1) return "medium";
  if (l.indexOf("low") !== -1) return "low";
  return "none";
}

// Per-side view filter — "all" | "fingerprinting" | "trackers". Applied
// only to what's rendered in each side's category list; the diff
// classifications (only-A / only-B / shared) and the diff-summary stats
// continue to use the full underlying data, so per-row labels remain
// accurate even when filtered.
let leftView = "all";
let rightView = "all";
let centerView = "all";

// Tracker-vs-fingerprinting heuristic. Tracker-library categories all
// follow the *Detect naming convention. The four exclusions are
// fingerprinting-side categories that also end in "Detect".
const NON_TRACKER_DETECT = new Set([
  "AdBlockDetect", "ExtensionDetect", "HeadlessDetect", "VendorDetect",
]);

function isTrackerCategory(cat) {
  return cat.endsWith("Detect") && !NON_TRACKER_DETECT.has(cat);
}

function filterCatsByView(cats, view) {
  if (view === "trackers") return cats.filter(isTrackerCategory);
  if (view === "fingerprinting") return cats.filter(c => !isTrackerCategory(c));
  return cats;
}

// Wire up per-side view toggles. Re-renders the affected side using
// whatever data is currently loaded — diff data unchanged.
document.querySelectorAll(".view-toggle").forEach(group => {
  const side = group.dataset.side;
  group.querySelectorAll("button").forEach(btn => {
    btn.addEventListener("click", () => {
      group.querySelectorAll("button").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      if (side === "left") leftView = btn.dataset.view;
      else if (side === "center") centerView = btn.dataset.view;
      else rightView = btn.dataset.view;
      const data = side === "left" ? leftData :
                   side === "center" ? centerData : rightData;
      if (!data) return;
      // Re-render the affected side. If the diff is already populated
      // (both sides loaded), use the diff renderer so labels stay
      // intact; otherwise fall back to the standalone single-side view.
      if (leftData && rightData) {
        // Trigger a full re-render so 2-way / 3-way classification stays
        // consistent — cheaper than partial-recomputing membership here.
        maybeRenderDiff();
      } else {
        renderCategoriesStandalone(side, data);
      }
    });
  });
});

// Cached method sets per side, recomputed when data changes
let leftMethodCache = null;
let rightMethodCache = null;
let centerMethodCache = null;
// 3-way membership map cat → "A"|"B"|"C"|"AB"|"AC"|"BC"|"ABC".
// Built in maybeRenderDiff when 3-way mode is on, consumed by render
// helpers + export.
let membership3 = null;

function buildMethodCache(data) {
  const cache = {};
  const cats = data.categories || {};
  for (const cat of Object.keys(cats)) {
    const s = new Set();
    const methods = cats[cat].uniqueMethods || [];
    for (let i = 0; i < methods.length; i++) s.add(methods[i].method);
    cache[cat] = s;
  }
  return cache;
}

// Track whether methods have been rendered — lazy on first Show methods toggle
let methodsRendered = false;

function maybeRenderDiff() {
  if (!leftData || !rightData) {
    if (leftData) renderCategoriesStandalone("left", leftData);
    if (rightData) renderCategoriesStandalone("right", rightData);
    if (centerData) renderCategoriesStandalone("center", centerData);
    return;
  }

  // Invalidate caches — fresh data means fresh method sets
  leftMethodCache = buildMethodCache(leftData);
  rightMethodCache = buildMethodCache(rightData);
  centerMethodCache = centerData ? buildMethodCache(centerData) : null;
  methodsRendered = false; // reset lazy render flag

  const leftCats = new Set(Object.keys(leftData.categories || {}));
  const rightCats = new Set(Object.keys(rightData.categories || {}));
  const centerCats = centerData ? new Set(Object.keys(centerData.categories || {})) : null;

  const useThreeWay = threeWayMode && centerData !== null;
  const allCats = new Set([...leftCats, ...rightCats, ...(centerCats || [])]);
  const onlyLeft = [...leftCats].filter(c => !rightCats.has(c) && !(centerCats && centerCats.has(c)));
  const onlyRight = [...rightCats].filter(c => !leftCats.has(c) && !(centerCats && centerCats.has(c)));

  // 3-way membership: build cat → "A"/"B"/"C"/"AB"/"AC"/"BC"/"ABC"
  if (useThreeWay) {
    membership3 = new Map();
    for (const cat of allCats) {
      let m = "";
      if (leftCats.has(cat)) m += "A";
      if (rightCats.has(cat)) m += "B";
      if (centerCats.has(cat)) m += "C";
      membership3.set(cat, m);
    }
  } else {
    membership3 = null;
  }

  const onlyCenter = useThreeWay
    ? [...centerCats].filter(c => !leftCats.has(c) && !rightCats.has(c))
    : [];
  const sharedAll = useThreeWay
    ? [...leftCats].filter(c => rightCats.has(c) && centerCats.has(c))
    : [...leftCats].filter(c => rightCats.has(c));

  // Diff summary bar — varies between 2-way and 3-way
  $diffSummary.style.display = "flex";
  let summaryHtml = `
    <div class="stat">
      <div class="stat-label">${useThreeWay ? "Shared by all" : "Shared Techniques"}</div>
      <div class="stat-value">${sharedAll.length}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Unique to A</div>
      <div class="stat-value high">${onlyLeft.length}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Unique to B</div>
      <div class="stat-value low">${onlyRight.length}</div>
    </div>`;
  if (useThreeWay) {
    summaryHtml += `
    <div class="stat">
      <div class="stat-label">Unique to C</div>
      <div class="stat-value">${onlyCenter.length}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Total (A / B / C)</div>
      <div class="stat-value">${leftCats.size} / ${rightCats.size} / ${centerCats.size}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Calls (A / B / C)</div>
      <div class="stat-value">${leftData.totalCalls || 0} / ${rightData.totalCalls || 0} / ${centerData.totalCalls || 0}</div>
    </div>`;
  } else {
    summaryHtml += `
    <div class="stat">
      <div class="stat-label">Total (A / B)</div>
      <div class="stat-value">${leftCats.size} / ${rightCats.size}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Calls (A / B)</div>
      <div class="stat-value">${leftData.totalCalls || 0} / ${rightData.totalCalls || 0}</div>
    </div>`;
  }
  summaryHtml += `
    <div class="actions">
      <label>
        <input type="checkbox" id="diffs-only"> Show only differences
      </label>
      <label>
        <input type="checkbox" id="show-methods"> Show methods
      </label>
      <button id="export-diffs">Export differences</button>
    </div>
  `;
  $diffSummary.innerHTML = summaryHtml;

  // Wire up toggles and export button
  const diffsOnlyCb = document.getElementById("diffs-only");
  diffsOnlyCb.addEventListener("change", () => {
    $container.classList.toggle("diffs-only", diffsOnlyCb.checked);
  });
  const showMethodsCb = document.getElementById("show-methods");
  showMethodsCb.addEventListener("change", () => {
    $container.classList.toggle("show-methods", showMethodsCb.checked);
    // Lazy render: only build method sub-rows on first activation
    if (showMethodsCb.checked && !methodsRendered) {
      methodsRendered = true;
      renderCategoriesDiff("left", leftData, allCats, onlyLeft, onlyRight, "left", true);
      renderCategoriesDiff("right", rightData, allCats, onlyLeft, onlyRight, "right", true);
      if (useThreeWay) renderCategoriesDiff("center", centerData, allCats, onlyLeft, onlyRight, "center", true);
    }
  });
  document.getElementById("export-diffs").addEventListener("click", exportDifferences);

  // Render category lists with diff labels
  renderCategoriesDiff("left", leftData, allCats, onlyLeft, onlyRight, "left");
  renderCategoriesDiff("right", rightData, allCats, onlyLeft, onlyRight, "right");
  if (useThreeWay) renderCategoriesDiff("center", centerData, allCats, onlyLeft, onlyRight, "center");

  // Domain comparison
  renderDomainDiff();
}

function renderCategoriesStandalone(side, data) {
  const container = document.getElementById(side + "-categories");
  if (!container) return;
  const view = side === "left" ? leftView : side === "center" ? centerView : rightView;
  const cats = filterCatsByView(Object.keys(data.categories || {}), view).sort();
  const parts = [];
  for (let i = 0; i < cats.length; i++) {
    const cat = cats[i];
    const meta = CATEGORY_META[cat] || { icon: "?", color: "#78909c", risk: "low" };
    const calls = data.categories[cat].totalCalls || 0;
    parts.push(
      `<div class="category-row both">` +
      `<div class="category-main">` +
      `<span class="name">` +
      `<span class="icon" style="background:${meta.color}22;color:${meta.color}">${meta.icon}</span>` +
      escapeHtml(cat) +
      `</span>` +
      `<span class="count">${calls} calls</span>` +
      `</div>` +
      `</div>`
    );
  }
  container.innerHTML = parts.length ? parts.join("") : `<div class="placeholder">No detections</div>`;
}

function renderCategoriesDiff(side, data, allCats, onlyLeft, onlyRight, sideLabel, withMethods) {
  const container = document.getElementById(side + "-categories");
  if (!container) return;

  const onlyLeftSet = new Set(onlyLeft);
  const onlyRightSet = new Set(onlyRight);
  const useThreeWay = membership3 !== null;

  // For per-method classification we treat "any other side has this method"
  // as method-both. In 3-way mode we union both other-side caches.
  let otherMethodCacheA = null, otherMethodCacheB = null;
  if (sideLabel === "left") {
    otherMethodCacheA = rightMethodCache;
    otherMethodCacheB = useThreeWay ? centerMethodCache : null;
  } else if (sideLabel === "right") {
    otherMethodCacheA = leftMethodCache;
    otherMethodCacheB = useThreeWay ? centerMethodCache : null;
  } else { // center
    otherMethodCacheA = leftMethodCache;
    otherMethodCacheB = rightMethodCache;
  }

  const view = sideLabel === "left" ? leftView : sideLabel === "center" ? centerView : rightView;
  const thisSideCats = filterCatsByView(Object.keys(data.categories || {}), view);
  const sorted = thisSideCats.sort((a, b) => {
    // Sort by membership specificity: unique to this side first.
    const aIsUnique = (sideLabel === "left" && onlyLeftSet.has(a)) ||
                      (sideLabel === "right" && onlyRightSet.has(a)) ||
                      (sideLabel === "center" && useThreeWay && membership3.get(a) === "C");
    const bIsUnique = (sideLabel === "left" && onlyLeftSet.has(b)) ||
                      (sideLabel === "right" && onlyRightSet.has(b)) ||
                      (sideLabel === "center" && useThreeWay && membership3.get(b) === "C");
    if (aIsUnique && !bIsUnique) return -1;
    if (!aIsUnique && bIsUnique) return 1;
    return a.localeCompare(b);
  });

  let html = "";
  for (const cat of sorted) {
    const inThisSide = data.categories[cat];
    const meta = CATEGORY_META[cat] || { icon: "?", color: "#78909c", risk: "low" };
    const calls = inThisSide.totalCalls || 0;

    // Classification
    let diffClass = "both";
    let label = "";
    if (useThreeWay) {
      const m = membership3.get(cat) || "";
      if (m === "A") {
        diffClass = "only-left";
        label = `<span class="diff-label unique-left">only A</span>`;
      } else if (m === "B") {
        diffClass = "only-right";
        label = `<span class="diff-label unique-right">only B</span>`;
      } else if (m === "C") {
        diffClass = "only-center";
        label = `<span class="diff-label unique-center">only C</span>`;
      } else if (m === "ABC") {
        diffClass = "both";
        label = `<span class="diff-label shared">A+B+C</span>`;
      } else {
        // 2-of-3
        diffClass = "in-two";
        label = `<span class="diff-label partial">${m.split("").join("+")}</span>`;
      }
    } else {
      const isUniqueLeft = onlyLeftSet.has(cat);
      const isUniqueRight = onlyRightSet.has(cat);
      if (sideLabel === "left" && isUniqueLeft) {
        diffClass = "only-left";
        label = `<span class="diff-label unique-left">only A</span>`;
      } else if (sideLabel === "right" && isUniqueRight) {
        diffClass = "only-right";
        label = `<span class="diff-label unique-right">only B</span>`;
      } else {
        label = `<span class="diff-label shared">shared</span>`;
      }
    }

    let methodsHtml = "";
    // Lazy: only build method sub-list when requested
    if (withMethods) {
      const thisMethods = inThisSide.uniqueMethods || [];
      const setA = (otherMethodCacheA && otherMethodCacheA[cat]) || null;
      const setB = (otherMethodCacheB && otherMethodCacheB[cat]) || null;

      if (thisMethods.length > 0) {
        const inOtherFn = (mname) => (setA && setA.has(mname)) || (setB && setB.has(mname));
        const sortedMethods = thisMethods.slice().sort((a, b) => {
          const aInOther = inOtherFn(a.method);
          const bInOther = inOtherFn(b.method);
          if (!aInOther && bInOther) return -1;
          if (aInOther && !bInOther) return 1;
          return a.method.localeCompare(b.method);
        });

        const parts = ["<div class=\"methods-list\">"];
        for (let i = 0; i < sortedMethods.length; i++) {
          const m = sortedMethods[i];
          const inOther = inOtherFn(m.method);
          let methodClass;
          if (diffClass === "only-left" || diffClass === "only-right" || diffClass === "only-center") {
            methodClass = diffClass;
          } else {
            methodClass = inOther ? "method-both" : (
              sideLabel === "left" ? "method-only-left" :
              sideLabel === "center" ? "method-only-center" :
              "method-only-right"
            );
          }
          const detailStr = m.detail || "";
          const detailHtml = detailStr ? escapeHtml(detailStr) : "";
          parts.push(
            `<div class="method-row ${methodClass}" title="${escapeHtml(m.method)}${detailStr ? ' — ' + escapeHtml(detailStr) : ''}">` +
            `<span class="method-name">${escapeHtml(m.method)}</span>` +
            (detailHtml ? `<span class="method-detail">${detailHtml}</span>` : "") +
            `</div>`
          );
        }
        parts.push("</div>");
        methodsHtml = parts.join("");
      }
    }

    html += `<div class="category-row ${diffClass}">
      <div class="category-main">
        <span class="name">
          <span class="icon" style="background:${meta.color}22;color:${meta.color}">${meta.icon}</span>
          ${escapeHtml(cat)}${label}
        </span>
        <span class="count">${calls} calls</span>
      </div>
      ${methodsHtml}
    </div>`;
  }
  container.innerHTML = html;
}

const $domainsTbody = $domainsSection.querySelector("tbody");

function renderDomainDiff() {
  const section = $domainsSection;
  const tbody = $domainsTbody;
  const useThreeWay = threeWayMode && centerData !== null;
  const leftDomains = leftData.domains || {};
  const rightDomains = rightData.domains || {};
  const centerDomains = useThreeWay ? (centerData.domains || {}) : {};
  const allDomains = new Set([
    ...Object.keys(leftDomains),
    ...Object.keys(rightDomains),
    ...Object.keys(centerDomains),
  ]);

  if (allDomains.size === 0) {
    section.style.display = "none";
    return;
  }
  section.style.display = "block";

  const sorted = [...allDomains].sort((a, b) => {
    const aTotal = (leftDomains[a]?.calls || 0) + (rightDomains[a]?.calls || 0) + (centerDomains[a]?.calls || 0);
    const bTotal = (leftDomains[b]?.calls || 0) + (rightDomains[b]?.calls || 0) + (centerDomains[b]?.calls || 0);
    return bTotal - aTotal;
  });

  function fmt(d) {
    return d ? d.calls + " calls / " + (d.categories?.length || 0) + " cats" : "—";
  }

  let html = "";
  for (const domain of sorted) {
    const left = leftDomains[domain];
    const right = rightDomains[domain];
    const center = centerDomains[domain];
    const isThird = left?.isThirdParty || right?.isThirdParty || center?.isThirdParty;

    let rowClass = "both";
    let present = "shared";
    if (useThreeWay) {
      let mark = "";
      if (left) mark += "A";
      if (right) mark += "B";
      if (center) mark += "C";
      present = mark.length === 3 ? "shared" : mark.split("").join("+");
      if (mark === "A") rowClass = "only-left";
      else if (mark === "B") rowClass = "only-right";
      else if (mark === "C") rowClass = "only-center";
      else if (mark.length === 2) rowClass = "in-two";
    } else {
      if (left && !right) { rowClass = "only-left"; present = "A only"; }
      else if (!left && right) { rowClass = "only-right"; present = "B only"; }
    }

    html += `<tr class="${rowClass}">
      <td class="domain-name">${escapeHtml(domain)}${isThird ? '<span class="third-party">3rd-party</span>' : ''}</td>
      <td>${fmt(left)}</td>
      <td>${fmt(right)}</td>
      <td class="col-c">${fmt(center)}</td>
      <td>${present}</td>
    </tr>`;
  }
  tbody.innerHTML = html;
}

// ── Export differences ────────────────────────────────────────────────
function exportDifferences() {
  if (!leftData || !rightData) {
    alert("Load both sides before exporting differences.");
    return;
  }

  const useThreeWay = threeWayMode && centerData !== null;
  if (useThreeWay) {
    exportDifferences3Way();
    return;
  }

  const leftCats = leftData.categories || {};
  const rightCats = rightData.categories || {};
  const leftKeys = new Set(Object.keys(leftCats));
  const rightKeys = new Set(Object.keys(rightCats));

  const onlyA = [];
  const onlyB = [];
  const shared = [];

  for (const cat of leftKeys) {
    if (rightKeys.has(cat)) {
      // Shared category — diff the methods within it
      const aMethods = leftCats[cat].uniqueMethods || [];
      const bMethods = rightCats[cat].uniqueMethods || [];
      const aMethodNames = new Set(aMethods.map(m => m.method));
      const bMethodNames = new Set(bMethods.map(m => m.method));

      const methodsOnlyA = aMethods.filter(m => !bMethodNames.has(m.method));
      const methodsOnlyB = bMethods.filter(m => !aMethodNames.has(m.method));
      const sharedMethodNames = [...aMethodNames].filter(n => bMethodNames.has(n));

      shared.push({
        category: cat,
        callsA: leftCats[cat].totalCalls || 0,
        callsB: rightCats[cat].totalCalls || 0,
        methodsOnlyA,
        methodsOnlyB,
        sharedMethods: sharedMethodNames,
      });
    } else {
      onlyA.push({
        category: cat,
        totalCalls: leftCats[cat].totalCalls || 0,
        risk: leftCats[cat].risk,
        description: leftCats[cat].description,
        uniqueMethods: leftCats[cat].uniqueMethods,
      });
    }
  }
  for (const cat of rightKeys) {
    if (!leftKeys.has(cat)) {
      onlyB.push({
        category: cat,
        totalCalls: rightCats[cat].totalCalls || 0,
        risk: rightCats[cat].risk,
        description: rightCats[cat].description,
        uniqueMethods: rightCats[cat].uniqueMethods,
      });
    }
  }

  // Domain diff
  const leftDomains = leftData.domains || {};
  const rightDomains = rightData.domains || {};
  const domainsOnlyA = {};
  const domainsOnlyB = {};
  const domainsShared = {};
  for (const d of Object.keys(leftDomains)) {
    if (rightDomains[d]) {
      domainsShared[d] = { A: leftDomains[d], B: rightDomains[d] };
    } else {
      domainsOnlyA[d] = leftDomains[d];
    }
  }
  for (const d of Object.keys(rightDomains)) {
    if (!leftDomains[d]) {
      domainsOnlyB[d] = rightDomains[d];
    }
  }

  const diff = {
    exportedAt: new Date().toISOString(),
    siteA: {
      url: leftData.url || "",
      source: leftFilename || "current tab",
      exportedAt: leftData.exportedAt,
      totalTechniques: leftKeys.size,
      totalCalls: leftData.totalCalls || 0,
      riskLevel: leftData.riskLevel,
    },
    siteB: {
      url: rightData.url || "",
      source: rightFilename || "",
      exportedAt: rightData.exportedAt,
      totalTechniques: rightKeys.size,
      totalCalls: rightData.totalCalls || 0,
      riskLevel: rightData.riskLevel,
    },
    summary: {
      uniqueToA: onlyA.length,
      uniqueToB: onlyB.length,
      sharedTechniques: shared.length,
      domainsOnlyA: Object.keys(domainsOnlyA).length,
      domainsOnlyB: Object.keys(domainsOnlyB).length,
      domainsShared: Object.keys(domainsShared).length,
    },
    techniques: {
      uniqueToA: onlyA,
      uniqueToB: onlyB,
      shared,
    },
    domains: {
      onlyA: domainsOnlyA,
      onlyB: domainsOnlyB,
      shared: domainsShared,
    },
  };

  // Build a filename from both sites
  function siteSlug(url) {
    if (!url) return "unknown";
    try {
      return new URL(url).hostname.replace(/^www\./, "").replace(/[^a-z0-9.-]/gi, "_");
    } catch {
      return "unknown";
    }
  }
  const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const filename = `fp-diff-${siteSlug(leftData.url)}-vs-${siteSlug(rightData.url)}-${ts}.json`;

  // Trigger download
  const blob = new Blob([JSON.stringify(diff, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ── 3-way export ──────────────────────────────────────────────────────
// Membership-based diff: each technique is tagged with which sites it
// appeared on (A / B / C / AB / AC / BC / ABC). Methods within shared
// techniques get the same membership treatment.
function exportDifferences3Way() {
  const cats = {
    A: leftData.categories || {},
    B: rightData.categories || {},
    C: centerData.categories || {},
  };
  const allCats = new Set([...Object.keys(cats.A), ...Object.keys(cats.B), ...Object.keys(cats.C)]);
  const buckets = {
    A: [], B: [], C: [],
    AB: [], AC: [], BC: [],
    ABC: [],
  };
  for (const cat of allCats) {
    let m = "";
    if (cats.A[cat]) m += "A";
    if (cats.B[cat]) m += "B";
    if (cats.C[cat]) m += "C";
    const entry = {
      category: cat,
      callsA: cats.A[cat]?.totalCalls || 0,
      callsB: cats.B[cat]?.totalCalls || 0,
      callsC: cats.C[cat]?.totalCalls || 0,
    };
    if (m.length >= 2) {
      // Method-level membership for shared techniques
      const methodSets = {
        A: new Set((cats.A[cat]?.uniqueMethods || []).map(x => x.method)),
        B: new Set((cats.B[cat]?.uniqueMethods || []).map(x => x.method)),
        C: new Set((cats.C[cat]?.uniqueMethods || []).map(x => x.method)),
      };
      const methodMembership = {};
      for (const sub of [...methodSets.A, ...methodSets.B, ...methodSets.C]) {
        let mm = "";
        if (methodSets.A.has(sub)) mm += "A";
        if (methodSets.B.has(sub)) mm += "B";
        if (methodSets.C.has(sub)) mm += "C";
        if (!methodMembership[mm]) methodMembership[mm] = [];
        methodMembership[mm].push(sub);
      }
      entry.methodsByMembership = methodMembership;
    } else {
      // Unique to one side — list its methods
      const side = m;
      entry.uniqueMethods = cats[side][cat]?.uniqueMethods || [];
    }
    buckets[m].push(entry);
  }

  function siteSlug(url) {
    if (!url) return "unknown";
    try {
      return new URL(url).hostname.replace(/^www\./, "").replace(/[^a-z0-9.-]/gi, "_");
    } catch {
      return "unknown";
    }
  }

  const diff = {
    exportedAt: new Date().toISOString(),
    siteA: { url: leftData.url || "", source: leftFilename || "current tab", totalTechniques: Object.keys(cats.A).length, totalCalls: leftData.totalCalls || 0 },
    siteB: { url: rightData.url || "", source: rightFilename || "", totalTechniques: Object.keys(cats.B).length, totalCalls: rightData.totalCalls || 0 },
    siteC: { url: centerData.url || "", source: centerFilename || "", totalTechniques: Object.keys(cats.C).length, totalCalls: centerData.totalCalls || 0 },
    summary: {
      onlyA: buckets.A.length, onlyB: buckets.B.length, onlyC: buckets.C.length,
      AB: buckets.AB.length, AC: buckets.AC.length, BC: buckets.BC.length,
      ABC: buckets.ABC.length,
    },
    techniques: buckets,
  };

  const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const filename = `fp-diff3-${siteSlug(leftData.url)}-vs-${siteSlug(rightData.url)}-vs-${siteSlug(centerData.url)}-${ts}.json`;
  const blob = new Blob([JSON.stringify(diff, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ── File loading — button + drag/drop ─────────────────────────────────
$sides.left.load.addEventListener("click", () => $sides.left.file.click());
$sides.right.load.addEventListener("click", () => $sides.right.file.click());
$sides.center.load.addEventListener("click", () => $sides.center.file.click());

$sides.left.file.addEventListener("change", (e) => {
  if (e.target.files[0]) loadFromFile(e.target.files[0], "left");
});
$sides.right.file.addEventListener("change", (e) => {
  if (e.target.files[0]) loadFromFile(e.target.files[0], "right");
});
$sides.center.file.addEventListener("change", (e) => {
  if (e.target.files[0]) loadFromFile(e.target.files[0], "center");
});

// Wire up a dropzone — drag/drop + click to open file dialog
function wireDropzone(dropzoneEl, side) {
  if (!dropzoneEl) return;
  ["dragenter", "dragover"].forEach(ev => {
    dropzoneEl.addEventListener(ev, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzoneEl.classList.add("dragover");
    });
  });
  ["dragleave", "drop"].forEach(ev => {
    dropzoneEl.addEventListener(ev, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzoneEl.classList.remove("dragover");
    });
  });
  dropzoneEl.addEventListener("drop", (e) => {
    const file = e.dataTransfer.files[0];
    if (file) loadFromFile(file, side);
  });
  // Click anywhere on the dropzone to open the file picker
  dropzoneEl.addEventListener("click", () => {
    $sides[side].file.click();
  });
}

wireDropzone(document.getElementById("right-drop"), "right");
wireDropzone(document.getElementById("center-drop"), "center");

// Whole-window drag and drop — pick the side under the mouse. In
// 2-way mode the window is split in half (left | right); in 3-way
// mode it's split in thirds (left | center | right).
document.addEventListener("dragover", (e) => e.preventDefault());
document.addEventListener("drop", (e) => {
  e.preventDefault();
  const file = e.dataTransfer.files[0];
  if (!file) return;
  const w = window.innerWidth;
  let side;
  if (threeWayMode) {
    side = e.clientX < w / 3 ? "left" : e.clientX < 2 * w / 3 ? "center" : "right";
  } else {
    side = e.clientX < w / 2 ? "left" : "right";
  }
  loadFromFile(file, side);
});

// ── 3-way mode toggle ────────────────────────────────────────────────
const $toggleC = document.getElementById("toggle-c");
$toggleC.addEventListener("click", () => {
  threeWayMode = !threeWayMode;
  document.body.classList.toggle("three-way", threeWayMode);
  $toggleC.textContent = threeWayMode ? "− Remove Site C" : "+ Add Site C";
  $toggleC.title = threeWayMode
    ? "Drop back to 2-site comparison"
    : "Add or remove a third site for comparison";
  // If turning off, drop loaded center data so re-toggling starts fresh.
  if (!threeWayMode) {
    centerData = null;
    centerFilename = "";
    centerView = "all";
    // Reset the center dropzone so it shows the empty state if re-enabled.
    document.getElementById("center-body").innerHTML = `
      <div class="dropzone" id="center-drop">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
          <polyline points="17 8 12 3 7 8"/>
          <line x1="12" y1="3" x2="12" y2="15"/>
        </svg>
        <p><strong>Drop or click to load an exported summary JSON</strong></p>
        <p class="hint">Or click "Load file" in the header</p>
      </div>`;
    wireDropzone(document.getElementById("center-drop"), "center");
  }
  // Re-render with the new mode (or fall back to 2-way render if center
  // hasn't been loaded yet).
  if (leftData && rightData) maybeRenderDiff();
});

// ── Load current tab summary into Site A on open ──────────────────────
chrome.storage.session.get(["compareLeftData"], (stored) => {
  if (stored.compareLeftData) {
    leftData = stored.compareLeftData;
    leftFilename = "current tab";
    renderSide("left", leftData, "current tab");
    maybeRenderDiff();
    // Clear it so it doesn't get reused stale
    chrome.storage.session.remove("compareLeftData");
  } else {
    // Show empty state with upload prompt
    document.getElementById("left-body").innerHTML = `
      <div class="dropzone" id="left-drop">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
          <polyline points="17 8 12 3 7 8"/>
          <line x1="12" y1="3" x2="12" y2="15"/>
        </svg>
        <p><strong>Drop or click to load an exported summary JSON</strong></p>
        <p class="hint">Or click "Load file" in the header</p>
      </div>`;
    wireDropzone(document.getElementById("left-drop"), "left");
  }
});
