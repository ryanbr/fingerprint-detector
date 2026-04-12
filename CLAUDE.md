# CLAUDE.md

## Project overview

Fingerprint Detector is a Chrome/Firefox extension that detects browser fingerprinting techniques in real-time. It hooks 60+ browser APIs from `inject.js` (MAIN world), relays events through `bridge.js` (ISOLATED world) to a `background.js` service worker, and displays results in a `popup.js` UI.

## Architecture

```
inject.js (MAIN world, per tab/frame)
    ↓ CustomEvent batches (every 250ms)
bridge.js (ISOLATED world, per tab/frame)
    ↓ chrome.runtime.sendMessage
background.js (service worker, singleton)
    ↓ port.postMessage (persistent connection)
popup.js (popup UI)
```

## Key files

- `manifest.json` — Chrome MV3 manifest, version is the single source of truth
- `src/inject.js` — All API hooks, runs in the page context. Largest file (~1600 lines)
- `src/bridge.js` — Bridges page events to extension, syncs mute state
- `src/background.js` — Stores per-tab detections in memory + `chrome.storage.session`
- `src/popup.js` — Summary + debug log UI, mute system, export, multi-tab
- `src/popup.html` — Popup layout and styles
- `.github/workflows/release.yml` — Builds CRX/ZIP/XPI on manual dispatch

## Development guidelines

### Adding a new fingerprinting hook

1. Add the hook in `inject.js` using the appropriate helper:
   - `hookMethod(proto, prop, category, method)` — rate-limited (first 3 calls + every 100th)
   - `hookMethodHot(proto, prop, category, method)` — fire-once then pure passthrough (use for high-frequency APIs)
   - `hookGetter(proto, prop, category, method)` — for getter properties
   - `record(category, method, detail)` — for custom hooks that need args/return value inspection
   - `recordHot(category, method, detail)` — fire-once version of record
2. Add the category metadata in `popup.js` `CATEGORY_META` object with icon, color, risk level, and description
3. Guard with `typeof` checks — use `typeof window.X !== "undefined"` (not bare `typeof X` which throws in strict mode)

### Performance rules

- **Never** hook APIs that fire thousands of times per second with `hookMethod` — use `hookMethodHot`
- **Never** use `...args` spread in hook wrappers — use explicit params or `arguments`
- **Never** call `JSON.stringify` in hot paths
- **Never** use `new Error().stack` directly — use `captureStack()` which uses V8's `Error.captureStackTrace`
- **Never** use regex in per-call checks — use `indexOf` or `charCodeAt` for string matching
- Use `charCodeAt` fast-exits before expensive checks (e.g., check first char before `indexOf("chrome-extension://")`)
- Pre-compile any regex used in hooks (declare outside the wrapper function)
- Rate-limiting and mute checks are inlined into hook wrappers — keep them in sync if logic changes

### Storage

- `chrome.storage.local` — persistent across browser restarts: mutes (global + per-domain)
- `chrome.storage.session` — survives service worker restarts but clears on browser close: tabData, UI state (pause, filter, watched tabs, active panel)
- `tabData` in background.js is the primary store, persisted to session storage with 500ms debounce

### Mute system

Two layers: global mutes and per-domain mutes, merged at runtime.
- Stored in `chrome.storage.local` as `mutedGlobal` and `mutedByDomain`
- Bridge.js merges global + current domain mutes and pushes to inject.js via CustomEvent
- Inject.js checks mute Sets before any recording (inlined in hook wrappers for zero overhead when muted)

### Firefox compatibility

- Firefox build is auto-patched from Chrome manifest via `jq` in the release workflow
- Only two differences: `background.scripts` instead of `service_worker`, and `browser_specific_settings` with gecko ID
- Firefox 128+ supports `"world": "MAIN"` natively — no loader workaround needed
- Use `typeof window.X` not `typeof X` for global checks (strict mode ReferenceError)
- `Error.captureStackTrace` is V8-only — the `captureStack()` function has a `new Error().stack` fallback
- `Intl.NumberFormat.format` and `Intl.Collator.compare` are getter-based accessors — use `hookGetter` not `hookMethod`

### Release process

Run the "Build and Release CRX" workflow from the Actions tab:
- Pick bump type: patch / minor / major
- Workflow auto-bumps `manifest.json`, commits, tags, builds CRX+ZIP+XPI, creates GitHub release with changelog
- Version flows: manifest.json → popup footer (read at runtime via `chrome.runtime.getManifest().version`)

## Caps and limits

| Layer | Cap | Scope |
|---|---|---|
| inject.js rate limiter | First 3 full detail, then every 100th | Per method per tab |
| inject.js `recordHot` | 1 event ever | Per method per tab |
| inject.js batch flush | 50 events max | Per tab |
| Extension probe log | First + every 50th summary | Per tab |
| Background detections | 5,000 | Per tab |
| Background categories | 500 | Per category per tab |
| Popup log entries | 10,000 | Per tab |
| Popup DOM nodes | 500 visible | Across all tabs |
| Session storage save | 500ms debounce | Global |

## Common pitfalls

- `FontFaceSet` must be referenced as `window.FontFaceSet` — bare reference throws ReferenceError in strict mode
- `Intl.NumberFormat.prototype.format` is a getter, not a method — `hookMethodHot` breaks it, use `hookGetter`
- `Node.prototype.appendChild` should NOT be hooked globally — use MutationObserver instead (fires on every DOM append)
- `document.createElement` hooks must use `charCodeAt` fast-exit and `recordHot` — called millions of times
- Service worker can die after 30s idle — all data must be in `chrome.storage.session`, not just in-memory
