# CLAUDE.md

## Project overview

Fingerprint Detector is a Chrome/Firefox extension that detects browser fingerprinting techniques in real-time. It hooks 60+ browser APIs via modular hook files, bundles them with esbuild into a single `dist/inject.js` (MAIN world), relays events through `bridge.js` (ISOLATED world) to a `background.js` service worker, and displays results in a `popup.js` UI.

## Architecture

```
src/inject.js (entry point — core infrastructure)
    ↓ imports
src/hooks/*.js (19 hook modules)
    ↓ esbuild --bundle
dist/inject.js (bundled, MAIN world, per tab/frame)
    ↓ CustomEvent batches (every 250ms)
src/bridge.js (ISOLATED world, per tab/frame)
    ↓ chrome.runtime.sendMessage
src/background.js (service worker, singleton)
    ↓ port.postMessage (persistent connection)
src/popup.js (popup UI)
```

## Key files

- `manifest.json` — Chrome MV3 manifest, version is the single source of truth. Points to `dist/inject.js` (bundled)
- `src/inject.js` — Entry point (~195 lines): core infrastructure (batching, mute state, rate limiting, record/recordHot, hook helpers). Imports all hook modules
- `src/hooks/*.js` — 19 modular hook files, each exporting a `register()` function
- `src/bridge.js` — Bridges page events to extension, syncs mute state (global + per-domain)
- `src/background.js` — Stores per-tab detections in memory + `chrome.storage.session`
- `src/popup.js` — Summary + debug log UI, mute system, export, multi-tab
- `src/popup.html` — Popup layout and styles
- `dist/inject.js` — Auto-generated bundle (gitignored). Built by `npm run build`
- `package.json` — esbuild dev dependency and build/watch scripts
- `.github/workflows/release.yml` — Builds bundle + CRX/ZIP/XPI on manual dispatch

## Hook modules

| File | Categories covered |
|---|---|
| `hooks/canvas.js` | Canvas, OffscreenCanvas, getContext, measureText |
| `hooks/webgl.js` | WebGL, WebGL2, debug_renderer_info, shader pipeline |
| `hooks/audio.js` | AudioContext, OfflineAudioContext, baseLatency |
| `hooks/navigator.js` | Navigator/UA props, Workers, SharedArrayBuffer, Atomics |
| `hooks/vendor.js` | Brave, vendor globals, Opera, Vivaldi, Edge, CSS prefixes |
| `hooks/client-hints.js` | Sec-CH-UA, GPC, Accept-CH meta tags |
| `hooks/screen.js` | Screen props, devicePixelRatio, availTop/availLeft |
| `hooks/fonts.js` | offsetWidth/Height probing, FontFaceSet, queryLocalFonts, createElement iframe |
| `hooks/webrtc.js` | RTCPeerConnection, ICE candidates, STUN, codec capabilities |
| `hooks/network.js` | NetworkInformation, WebSocket (port scanning, burst detection) |
| `hooks/media.js` | MediaDevices, SpeechSynthesis (full), matchMedia |
| `hooks/storage.js` | localStorage, sessionStorage, indexedDB, openDatabase, storage.estimate |
| `hooks/timing.js` | performance.now, getEntries, PerformanceObserver |
| `hooks/privacy.js` | DNT, headless/webdriver, visualViewport, share/canShare |
| `hooks/hardware.js` | WebGPU, Bluetooth, USB, Serial, HID, Sensors, Keyboard |
| `hooks/adblock.js` | offsetParent burst, FingerprintJS bait elements, create-check-remove |
| `hooks/extension.js` | chrome-extension:// probing, getComputedStyle burst, runtime.sendMessage |
| `hooks/intl.js` | Timezone, Intl formatters, DisplayNames, Locale, toLocaleString |
| `hooks/misc.js` | Permissions, ClientRects, Plugins, Touch, Credentials, Math, Architecture, Apple Pay, Private Click |

## Build system

```bash
npm install          # install esbuild
npm run build        # src/inject.js + src/hooks/*.js → dist/inject.js (IIFE, ~3ms)
npm run watch        # auto-rebuild on file changes
```

- esbuild bundles all modules into a single IIFE in `dist/inject.js`
- `dist/` is gitignored — built locally for dev, built in CI for releases
- manifest.json points to `dist/inject.js`, not `src/inject.js`
- To test locally: run `npm run build`, then load unpacked in Chrome

## Development guidelines

### Adding a new fingerprinting hook

1. Find the appropriate hook module in `src/hooks/` (or create a new one)
2. Add the hook inside the `register()` function using the helpers from the params:
   - `hookMethod(proto, prop, category, method)` — rate-limited (first 3 calls + every 100th)
   - `hookMethodHot(proto, prop, category, method)` — fire-once then pure passthrough (use for high-frequency APIs)
   - `hookGetter(proto, prop, category, method)` — for getter properties
   - `record(category, method, detail)` — for custom hooks that need args/return value inspection
   - `recordHot(category, method, detail)` — fire-once version of record
3. Add the category metadata in `popup.js` `CATEGORY_META` object with icon, color, risk level, and description
4. Guard with `typeof` checks — use `typeof window.X !== "undefined"` (not bare `typeof X` which throws in strict mode)
5. Run `npm run build` and test

### Creating a new hook module

```js
// src/hooks/example.js
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot }) {
  // Your hooks here
  hookMethod(SomeAPI.prototype, "someMethod", "Category", "someMethod");
}
```

Then import and register it in `src/inject.js`:
```js
import { register as example } from './hooks/example.js';
// ... in the IIFE:
example(helpers);
```

### Performance rules

- **Never** hook APIs that fire thousands of times per second with `hookMethod` — use `hookMethodHot`
- **Never** use `...args` spread in hook wrappers — use explicit params or `arguments`
- **Never** call `JSON.stringify` in hot paths
- **Never** use `new Error().stack` directly — use `captureStack()` which uses V8's `Error.captureStackTrace`
- **Never** use regex in per-call checks — use `indexOf` or `charCodeAt` for string matching
- Use `charCodeAt` fast-exits before expensive checks (e.g., check first char before `indexOf("chrome-extension://")`)
- Pre-compile any regex used in hooks (declare outside the wrapper function)
- Rate-limiting and mute checks are inlined into hook wrappers in `src/inject.js` — keep them in sync if logic changes

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
- Only two differences: `background.scripts` instead of `service_worker`, and `browser_specific_settings` with gecko ID (min 128.0)
- Firefox 128+ supports `"world": "MAIN"` natively — no loader workaround needed
- Use `typeof window.X` not `typeof X` for global checks (strict mode ReferenceError)
- `Error.captureStackTrace` is V8-only — the `captureStack()` function has a `new Error().stack` fallback
- `Intl.NumberFormat.format` and `Intl.Collator.compare` are getter-based accessors — use `hookGetter` not `hookMethod`

### Release process

Run the "Build and Release CRX" workflow from the Actions tab:
1. Pick bump type: **patch** / **minor** (default) / **major** — or set an exact version override
2. Workflow auto-bumps `manifest.json`, commits "Release vX.Y.Z", pushes
3. Generates changelog from git log since last tag
4. Creates annotated git tag
5. Runs `npm ci && npm run build` to bundle inject.js
6. Packages CRX (Chrome) + ZIP (Chrome/sideload) + XPI (Firefox)
7. Creates GitHub release with changelog and all 3 assets
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
- `dist/inject.js` is gitignored — always run `npm run build` before testing locally
- The release workflow runs the build automatically — don't commit `dist/` to the repo
