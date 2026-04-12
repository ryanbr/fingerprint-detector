// Content script (ISOLATED world) — bridges custom events from inject.js to the background service worker
// Runs in all frames including iframes, attaches the frame URL to each event.
// Syncs mute state (global + per-domain) from chrome.storage into the MAIN world inject script.

const frameUrl = location.href;
const isIframe = window !== window.top;

// Get the domain for this page/frame
let pageDomain = "";
try { pageDomain = new URL(location.href).hostname; } catch { /* invalid URL */ }

// ── Forward detection events to background ────────────────────────────
window.addEventListener("__fpDetector", (e) => {
  try {
    const parsed = JSON.parse(e.detail);
    const events = Array.isArray(parsed) ? parsed : [parsed];
    for (const data of events) {
      data.frameUrl = frameUrl;
      data.isIframe = isIframe;
    }
    chrome.runtime.sendMessage({ type: "fp-detection-batch", data: events });
  } catch { /* ignore malformed events */ }
});

// ── Sync mute state into inject.js (MAIN world) ──────────────────────
function pushMutesToPage(mutes) {
  window.dispatchEvent(
    new CustomEvent("__fpDetector_mutes", {
      detail: JSON.stringify(mutes),
    })
  );
}

// Merge global + domain-specific mutes into flat lists for inject.js
function buildEffectiveMutes(stored) {
  const global = stored.mutedGlobal || { methods: [], categories: [] };
  const byDomain = stored.mutedByDomain || {};
  const domain = byDomain[pageDomain] || { methods: [], categories: [] };

  return {
    mutedMethods: [...new Set([...global.methods, ...domain.methods])],
    mutedCategories: [...new Set([...global.categories, ...domain.categories])],
  };
}

// Load initial mute state
chrome.storage.local.get(["mutedGlobal", "mutedByDomain"], (stored) => {
  pushMutesToPage(buildEffectiveMutes(stored));
});

// Listen for mute changes
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.mutedGlobal || changes.mutedByDomain) {
    chrome.storage.local.get(["mutedGlobal", "mutedByDomain"], (stored) => {
      pushMutesToPage(buildEffectiveMutes(stored));
    });
  }
});

// ── Extension ID list relay (for export) ────────────────────────────
// Background/popup requests the full list → bridge asks inject.js → relays back
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "get-ext-ids") {
    const handler = (e) => {
      window.removeEventListener("__fpDetector_extIds", handler);
      try {
        sendResponse(JSON.parse(e.detail));
      } catch {
        sendResponse(null);
      }
    };
    window.addEventListener("__fpDetector_extIds", handler);
    window.dispatchEvent(new CustomEvent("__fpDetector_getExtIds"));
    // Timeout — if no probes happened, respond with null
    setTimeout(() => {
      window.removeEventListener("__fpDetector_extIds", handler);
      sendResponse(null);
    }, 200);
    return true; // async sendResponse
  }
});
