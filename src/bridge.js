// Content script (ISOLATED world) — bridges custom events from inject.js to the background service worker
// Runs in all frames including iframes, attaches the frame URL to each event.
// Syncs mute state from chrome.storage into the MAIN world inject script.

const frameUrl = location.href;
const isIframe = window !== window.top;

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
  } catch (_) {}
});

// ── Sync mute state into inject.js (MAIN world) ──────────────────────
function pushMutesToPage(mutes) {
  window.dispatchEvent(
    new CustomEvent("__fpDetector_mutes", {
      detail: JSON.stringify(mutes),
    })
  );
}

// Load initial mute state
chrome.storage.local.get(["mutedMethods", "mutedCategories"], (stored) => {
  pushMutesToPage({
    mutedMethods: stored.mutedMethods || [],
    mutedCategories: stored.mutedCategories || [],
  });
});

// Listen for mute changes (fired when user toggles mutes in popup)
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.mutedMethods || changes.mutedCategories) {
    pushMutesToPage({
      mutedMethods: changes.mutedMethods?.newValue || [],
      mutedCategories: changes.mutedCategories?.newValue || [],
    });
  }
});
