// compare.js — Compare two fingerprint summaries side-by-side

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
};

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = String(str);
  return div.innerHTML;
}

// ── State ─────────────────────────────────────────────────────────────
let leftData = null;
let rightData = null;
let leftFilename = ""; // filename of loaded file (or "current tab")
let rightFilename = "";

// ── Loaders ───────────────────────────────────────────────────────────
function loadFromFile(file, side) {
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const json = JSON.parse(e.target.result);
      // Support both summary-only and full report format
      const data = json.summary ? json.summary : json;
      if (!data.categories) {
        alert("This file doesn't look like a Fingerprint Detector export.");
        return;
      }
      if (side === "left") {
        leftData = data;
        leftFilename = file.name;
        renderSide("left", data, file.name);
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
  const urlEl = document.getElementById(side + "-url");
  const bodyEl = document.getElementById(side + "-body");

  // Show URL + filename in brackets (if loaded from a file)
  const url = data.url || "(unknown URL)";
  const fname = filename || (side === "left" ? leftFilename : rightFilename);
  urlEl.textContent = fname ? url + " [" + fname + "]" : url;
  urlEl.title = fname ? url + "\nFile: " + fname : url;

  // Also show exportedAt timestamp if present
  const exportedAt = data.exportedAt ? " — exported " + new Date(data.exportedAt).toLocaleString() : "";

  const cats = Object.keys(data.categories || {});
  const risk = data.riskLevel || "unknown";

  const html = `<div class="summary-stats">
    <span class="badge ${riskClass(risk)}">${escapeHtml(risk)}</span>
    <span class="badge none">${cats.length} techniques</span>
    <span class="badge none">${data.totalCalls || 0} total calls</span>
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

function maybeRenderDiff() {
  if (!leftData || !rightData) {
    // Render single-side categories only
    if (leftData) renderCategoriesStandalone("left", leftData);
    if (rightData) renderCategoriesStandalone("right", rightData);
    return;
  }

  // Both sides loaded — render diff
  const leftCats = new Set(Object.keys(leftData.categories || {}));
  const rightCats = new Set(Object.keys(rightData.categories || {}));

  const allCats = new Set([...leftCats, ...rightCats]);
  const onlyLeft = [...leftCats].filter(c => !rightCats.has(c));
  const onlyRight = [...rightCats].filter(c => !leftCats.has(c));
  const shared = [...leftCats].filter(c => rightCats.has(c));

  // Diff summary bar
  const diffSummary = document.getElementById("diff-summary");
  diffSummary.style.display = "flex";
  diffSummary.innerHTML = `
    <div class="stat">
      <div class="stat-label">Shared Techniques</div>
      <div class="stat-value">${shared.length}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Unique to A</div>
      <div class="stat-value high">${onlyLeft.length}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Unique to B</div>
      <div class="stat-value low">${onlyRight.length}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Total (A / B)</div>
      <div class="stat-value">${leftCats.size} / ${rightCats.size}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Calls (A / B)</div>
      <div class="stat-value">${leftData.totalCalls || 0} / ${rightData.totalCalls || 0}</div>
    </div>
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

  // Wire up toggles and export button
  const diffsOnlyCb = document.getElementById("diffs-only");
  diffsOnlyCb.addEventListener("change", () => {
    document.querySelector(".container").classList.toggle("diffs-only", diffsOnlyCb.checked);
  });
  const showMethodsCb = document.getElementById("show-methods");
  showMethodsCb.addEventListener("change", () => {
    document.querySelector(".container").classList.toggle("show-methods", showMethodsCb.checked);
  });
  document.getElementById("export-diffs").addEventListener("click", exportDifferences);

  // Render category lists with diff labels
  renderCategoriesDiff("left", leftData, allCats, onlyLeft, onlyRight, "left");
  renderCategoriesDiff("right", rightData, allCats, onlyLeft, onlyRight, "right");

  // Domain comparison
  renderDomainDiff();
}

function renderCategoriesStandalone(side, data) {
  const container = document.getElementById(side + "-categories");
  if (!container) return;
  const cats = Object.keys(data.categories || {}).sort();
  let html = "";
  for (const cat of cats) {
    const meta = CATEGORY_META[cat] || { icon: "?", color: "#78909c", risk: "low" };
    const catData = data.categories[cat];
    const calls = catData.totalCalls || 0;

    let methodsHtml = "";
    if (catData.uniqueMethods && catData.uniqueMethods.length > 0) {
      methodsHtml = `<div class="methods-list">`;
      for (const m of catData.uniqueMethods) {
        const detail = m.detail ? escapeHtml(m.detail.length > 60 ? m.detail.slice(0, 57) + "..." : m.detail) : "";
        methodsHtml += `<div class="method-row method-both" title="${escapeHtml(m.method)}${m.detail ? ' — ' + escapeHtml(m.detail) : ''}">
          <span class="method-name">${escapeHtml(m.method)}</span>
          ${detail ? `<span class="method-detail">${detail}</span>` : ""}
        </div>`;
      }
      methodsHtml += `</div>`;
    }

    html += `<div class="category-row both">
      <div class="category-main">
        <span class="name">
          <span class="icon" style="background:${meta.color}22;color:${meta.color}">${meta.icon}</span>
          ${escapeHtml(cat)}
        </span>
        <span class="count">${calls} calls</span>
      </div>
      ${methodsHtml}
    </div>`;
  }
  container.innerHTML = html || `<div class="placeholder">No detections</div>`;
}

// Build a Set of method signatures from a category's uniqueMethods array
function methodSet(catData) {
  const s = new Set();
  if (!catData || !catData.uniqueMethods) return s;
  for (const m of catData.uniqueMethods) {
    s.add(m.method);
  }
  return s;
}

function renderCategoriesDiff(side, data, allCats, onlyLeft, onlyRight, sideLabel) {
  const container = document.getElementById(side + "-categories");
  if (!container) return;

  const onlyLeftSet = new Set(onlyLeft);
  const onlyRightSet = new Set(onlyRight);

  const thisSideCats = Object.keys(data.categories || {});
  const sorted = thisSideCats.sort((a, b) => {
    const aUnique = (sideLabel === "left" ? onlyLeftSet : onlyRightSet).has(a);
    const bUnique = (sideLabel === "left" ? onlyLeftSet : onlyRightSet).has(b);
    if (aUnique && !bUnique) return -1;
    if (!aUnique && bUnique) return 1;
    return a.localeCompare(b);
  });

  // Get other side's data for method-level diff on shared categories
  const otherData = sideLabel === "left" ? rightData : leftData;

  let html = "";
  for (const cat of sorted) {
    const inThisSide = data.categories[cat];
    const meta = CATEGORY_META[cat] || { icon: "?", color: "#78909c", risk: "low" };
    const calls = inThisSide.totalCalls || 0;
    const isUniqueLeft = onlyLeftSet.has(cat);
    const isUniqueRight = onlyRightSet.has(cat);

    let diffClass = "both";
    let label = "";
    if (sideLabel === "left" && isUniqueLeft) {
      diffClass = "only-left";
      label = `<span class="diff-label unique-left">only A</span>`;
    } else if (sideLabel === "right" && isUniqueRight) {
      diffClass = "only-right";
      label = `<span class="diff-label unique-right">only B</span>`;
    } else {
      label = `<span class="diff-label shared">shared</span>`;
    }

    // Build method sub-list with diff labels
    const thisMethods = inThisSide.uniqueMethods || [];
    const otherCatData = otherData && otherData.categories ? otherData.categories[cat] : null;
    const otherMethodNames = methodSet(otherCatData);

    let methodsHtml = "";
    if (thisMethods.length > 0) {
      methodsHtml = `<div class="methods-list">`;
      // Sort: unique to this side first, then shared
      const sortedMethods = thisMethods.slice().sort((a, b) => {
        const aInOther = otherMethodNames.has(a.method);
        const bInOther = otherMethodNames.has(b.method);
        if (!aInOther && bInOther) return -1;
        if (aInOther && !bInOther) return 1;
        return a.method.localeCompare(b.method);
      });
      for (const m of sortedMethods) {
        const inOther = otherMethodNames.has(m.method);
        // If category is unique, all methods inherit the category's uniqueness
        // If category is shared, methods can be individually unique or shared
        let methodClass;
        if (isUniqueLeft || isUniqueRight) {
          methodClass = diffClass;
        } else {
          methodClass = inOther ? "method-both" : (sideLabel === "left" ? "method-only-left" : "method-only-right");
        }
        const detail = m.detail ? escapeHtml(m.detail.length > 60 ? m.detail.slice(0, 57) + "..." : m.detail) : "";
        methodsHtml += `<div class="method-row ${methodClass}" title="${escapeHtml(m.method)}${m.detail ? ' — ' + escapeHtml(m.detail) : ''}">
          <span class="method-name">${escapeHtml(m.method)}</span>
          ${detail ? `<span class="method-detail">${detail}</span>` : ""}
        </div>`;
      }
      methodsHtml += `</div>`;
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

function renderDomainDiff() {
  const section = document.getElementById("domains-section");
  const tbody = section.querySelector("tbody");
  const leftDomains = leftData.domains || {};
  const rightDomains = rightData.domains || {};
  const allDomains = new Set([...Object.keys(leftDomains), ...Object.keys(rightDomains)]);

  if (allDomains.size === 0) {
    section.style.display = "none";
    return;
  }
  section.style.display = "block";

  const sorted = [...allDomains].sort((a, b) => {
    const aTotal = (leftDomains[a]?.calls || 0) + (rightDomains[a]?.calls || 0);
    const bTotal = (leftDomains[b]?.calls || 0) + (rightDomains[b]?.calls || 0);
    return bTotal - aTotal;
  });

  let html = "";
  for (const domain of sorted) {
    const left = leftDomains[domain];
    const right = rightDomains[domain];
    const isThirdPartyA = left?.isThirdParty;
    const isThirdPartyB = right?.isThirdParty;
    const isThird = isThirdPartyA || isThirdPartyB;

    let rowClass = "both";
    let present = "shared";
    if (left && !right) { rowClass = "only-left"; present = "A only"; }
    else if (!left && right) { rowClass = "only-right"; present = "B only"; }

    html += `<tr class="${rowClass}">
      <td class="domain-name">${escapeHtml(domain)}${isThird ? '<span class="third-party">3rd-party</span>' : ''}</td>
      <td>${left ? left.calls + " calls / " + (left.categories?.length || 0) + " cats" : "—"}</td>
      <td>${right ? right.calls + " calls / " + (right.categories?.length || 0) + " cats" : "—"}</td>
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

// ── File loading — button + drag/drop ─────────────────────────────────
document.getElementById("left-load").addEventListener("click", () => {
  document.getElementById("left-file").click();
});
document.getElementById("right-load").addEventListener("click", () => {
  document.getElementById("right-file").click();
});

document.getElementById("left-file").addEventListener("change", (e) => {
  if (e.target.files[0]) loadFromFile(e.target.files[0], "left");
});
document.getElementById("right-file").addEventListener("change", (e) => {
  if (e.target.files[0]) loadFromFile(e.target.files[0], "right");
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
    document.getElementById(side + "-file").click();
  });
}

wireDropzone(document.getElementById("right-drop"), "right");

// Whole-window drag and drop — allows dropping on either side
document.addEventListener("dragover", (e) => e.preventDefault());
document.addEventListener("drop", (e) => {
  e.preventDefault();
  // Determine which side was dropped on based on mouse X
  const file = e.dataTransfer.files[0];
  if (!file) return;
  const side = e.clientX < window.innerWidth / 2 ? "left" : "right";
  loadFromFile(file, side);
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
