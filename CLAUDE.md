# CLAUDE.md

## Project overview

Fingerprint Detector is a Chrome/Firefox extension that detects browser fingerprinting techniques in real-time. It hooks 300+ browser APIs via 22 modular hook files, bundles them with esbuild into a single minified `dist/inject.js` (MAIN world), relays events through `bridge.js` (ISOLATED world) to a `background.js` service worker, and displays results in a `popup.js` UI with a tracking-library banner. A separate `compare.html` page lets users diff two exported fingerprint reports side-by-side. A `tests.html` test harness exercises every hook for manual verification.

In addition to primitive fingerprinting hooks, a data-driven tracker registry identifies 70+ named third-party libraries (analytics, ad-tech, CMPs, anti-bot, session replay, APM/RUM, marketing automation etc.) and surfaces them in a dedicated popup banner that's collapsible with persisted state.

## Architecture

```
src/inject.js (entry point — core infrastructure)
    ↓ imports
src/hooks/*.js (22 hook modules)
    ↓ esbuild --bundle --minify
dist/inject.js (bundled + minified, MAIN world, per tab/frame)
    ↓ CustomEvent batches (every 250ms foreground / 2000ms hidden)
src/bridge.js (ISOLATED world, per tab/frame)
    ↓ chrome.runtime.sendMessage
src/background.js (service worker, singleton)
    ↓ port.postMessage (persistent connection)
src/popup.js (popup UI)  ──┐
                           ↓ opens in new tab
                 src/compare.html / compare.js (side-by-side diff)

tests.html (project root) — standalone test harness, manually opened
```

## Key files

- `manifest.json` — Chrome MV3 manifest. Includes `browser_specific_settings.gecko` with `data_collection_permissions: { required: ["none"] }` for Firefox/AMO. Chrome ignores unrecognized top-level keys, so one manifest works for both browsers.
- `src/inject.js` — Entry point (~490 lines): core infrastructure (batching, mute state, rate limiting, record/recordHot, hook helpers, anti-tamper spoofing: `fnWrapperMap` + `copyFnIdentity` + descriptor spoof). Imports all 22 hook modules.
- `src/hooks/*.js` — 22 modular hook files, each exporting a `register(helpers)` function.
- `src/bridge.js` — Bridges page events to extension, syncs mute state (global + per-domain).
- `src/background.js` — Stores per-tab detections in memory + `chrome.storage.session` (survives service worker restart). Per-tab dirty tracking with 1s debounced gzip-compressed writes.
- `src/popup.js` / `src/popup.html` — Summary + debug log UI, mute system, export, tracking-library banner (stacked multi-line for 2+ detections, collapsible with persisted state for 2+), expanded-category preservation across Summary re-renders, Compare button.
- `src/compare.js` / `src/compare.html` — Standalone compare page: side-by-side diff of two exported summaries, method-level diff, light/dark mode, domain comparison, diff export.
- `tests.html` — Standalone manual test harness at repo root, 39 sections covering every detection. Open locally or via GitHub Pages / raw.githack.com to exercise every hook.
- `dist/inject.js` — Auto-generated bundle (gitignored). Built by `npm run build` (minified) or `npm run watch` (unminified, for dev).
- `scripts/prepare-ext.js` — Assembles build-tmp/ for web-ext lint (Firefox-patched manifest).
- `package.json` — esbuild + eslint + web-ext dev deps, build/watch/lint scripts.
- `eslint.config.js` — ESLint flat config with browser/extension globals and security rules.
- `fingerprint_table.md` — Reference table of every detection hook with risk level and description.
- `SECURITY.md` — Privacy promise, permissions explained, data flow diagram, threat model.
- `.github/workflows/lint.yml` — Runs ESLint + build verification + web-ext lint on every push and PR.
- `.github/workflows/release.yml` — Builds bundle + CRX/ZIP/XPI on manual dispatch with version bump dropdown.

## Hook modules

| File | Categories covered |
|---|---|
| `hooks/canvas.js` | Canvas, OffscreenCanvas, getContext attrs, measureText, fillText, drawImage, isPointInPath, captureStream |
| `hooks/webgl.js` | WebGL, WebGL2, debug_renderer_info, shader pipeline, buffer/renderbuffer/framebuffer queries, draw calls, getContextAttributes |
| `hooks/audio.js` | AudioContext constructors + getters, AudioBuffer reads, AnalyserNode data, AudioNode.connect, OfflineAudioContext |
| `hooks/navigator.js` | Navigator/UA props, getBattery (access), getGamepads, Workers, SharedArrayBuffer, Atomics, ServiceWorker (access), Cache API |
| `hooks/vendor.js` | Brave, vendor globals, Opera, Vivaldi, Edge, CSS prefixes, automation artifacts |
| `hooks/client-hints.js` | Sec-CH-UA, GPC, Accept-CH meta tags, userAgentData.toJSON |
| `hooks/screen.js` | Screen props, devicePixelRatio, availTop/availLeft, ScreenOrientation (type/angle/lock/unlock) |
| `hooks/fonts.js` | offsetWidth/Height font probing (SPAN/DIV/P/A), FontFaceSet (access), queryLocalFonts, system font keywords, 5s hard-deadline unwrap |
| `hooks/webrtc.js` | RTCPeerConnection full pipeline (access for createOffer/Answer/setLocal/Remote), ICE candidates with IP extraction, STUN config, codec capabilities |
| `hooks/network.js` | NetworkInformation, WebSocket (port scanning, burst detection) |
| `hooks/media.js` | MediaDevices (access), SpeechSynthesis (full including utterance setters), matchMedia, canPlayType, MediaRecorder.isTypeSupported, WebCodec, getAutoplayPolicy |
| `hooks/storage.js` | localStorage, sessionStorage, indexedDB (+ databases/stores/reads), openDatabase, storage.estimate/persist/persisted (access), cookies, BroadcastChannel, Storage Access API |
| `hooks/timing.js` | performance.now, getEntries/ByType/ByName, PerformanceObserver, mark/measure, memory, timeOrigin, PerformanceResourceTiming property getters |
| `hooks/privacy.js` | DNT, headless/webdriver, visualViewport, share/canShare (access), Function.toString anti-spoofing + spoof-back, Object.prototype.toString probe detection with 5s deadline unwrap, Error.stack getter (Firefox/Safari) + Error.captureStackTrace (V8), automation globals, userActivation, currentScript, fullscreenElement/Enabled, isSecureContext |
| `hooks/hardware.js` | WebGPU, Bluetooth/USB/Serial/HID (all access-based), Sensors, Keyboard |
| `hooks/adblock.js` | offsetParent burst, 90+ FingerprintJS bait elements, create-check-remove cycle via MutationObserver (not appendChild wrap) |
| `hooks/extension.js` | chrome-extension:// probing via Image.src / Link.href / setAttribute, getComputedStyle burst, runtime.sendMessage. fetch/XHR hooks removed. Self-unwrapping after idle. |
| `hooks/intl.js` | Timezone (Date.getTimezoneOffset), Intl formatters full suite, DisplayNames, Locale getters, supportedValuesOf, Date/Number/Array toLocaleString |
| `hooks/misc.js` | Credentials (access), ClientRects, Plugins, Touch, Math, Architecture (Float32Array NaN bit), Apple Pay, Private Click (attributionSourceId), document.referrer/name/hasFocus, SubtleCrypto.digest, WebAssembly constructors + compile/instantiate |
| `hooks/behavior.js` | MouseEvent/KeyboardEvent/PointerEvent/Touch property-read hooks (cursor coords, keystrokes, pressure, tilt, touch hardware) |
| `hooks/permissions.js` | Notification API, ServiceWorkerRegistration (showNotification/getNotifications/pushManager), Clipboard, Geolocation, WakeLock, IdleDetector, Navigator badging, MediaDevices (getUserMedia/getDisplayMedia), File System Access, PublicKeyCredential, PaymentRequest, DeviceOrientation/DeviceMotion.requestPermission, requestMIDIAccess |
| `hooks/tracking-libraries.js` | 70+ named tracking / ad-tech / CMP / anti-bot / session-replay / APM / marketing-automation libraries — registry-driven (see "Tracking-library detection" section). Core categories: anti-bot (Akamai BM, Cloudflare BM, DataDome, PerimeterX, Kasada, Imperva, Blockthrough, Admiral, ThreatMetrix), fingerprinting (FingerprintJS), analytics (Google Tag, Adobe Analytics, Matomo, Comscore, Chartbeat, Parse.ly, Webtrekk/Mapp, WP.com Stats, Quantcast), APM/RUM (New Relic, Dynatrace, Elastic APM, Sentry, mPulse, RUM Vision, SpeedCurve LUX, Adobe Helix RUM), session replay (Hotjar, Clarity, LogRocket, Noibu), tag managers (GTM, Tealium, Adobe DTM/Launch), CMPs (OneTrust, Usercentrics, iubenda, Osano, Transcend, Quantcast Choice, Google Funding Choices, TrueVault, Ziff Davis), ad networks (Meta Pixel, Bing UET, LinkedIn Insight, Criteo, Nativo, Media.net, Publift Fuse, Google Publisher Tag, IAS), e-commerce (Klaviyo, Yotpo, Bazaarvoice, Insider, Awin, Geniuslink, Adobe Commerce, Global-e), marketing automation (HubSpot, Salesforce MC, Listrak, Kameleoon, FigPii, BrightEdge, Pushly, Swan), misc (Qualtrics SiteIntercept, Branch, TrustedSite, accessiBe) |

See `fingerprint_table.md` for the full reference of every hook and what it detects.

## Tracking-library detection

`hooks/tracking-libraries.js` uses a data-driven registry (LIBRARIES array) to detect **70+ named tracking / ad-tech / CMP / analytics / session-replay / APM / marketing-automation libraries** through a shared scan pipeline. One PerformanceObserver + one MutationObserver + one set of scheduled scans (DOMContentLoaded / +2s / window.load) processes all libraries in each pass — new entries add almost no runtime cost.

Each library entry describes:
- Explicit `globals` names + `globalPrefixes` for pattern matching
- `keyPatterns` (regex) for cookie / localStorage / sessionStorage keys
- `scriptSrcPatterns` for DOM `<script src>` and PerformanceObserver resource URL matching
- `domAttributes` for `<script data-*>` integration tags
- Optional `anomaly` for library-specific quirks (e.g. Matomo's `Date.prototype.getTimeAlias`)
- Optional `classifyOrigin: true` for 1p-vs-3p-vs-custom-subdomain URL classification

Each detection fires a distinct category in the Debug Log (`FingerprintJSDetect`, `MatomoDetect`, `OneTrustDetect`, `AdobeAnalyticsDetect`, etc. — one per entry). The popup shows a prominent banner above the tabs:

- **1 library detected**: compact one-line layout with icon + name + signal count
- **2+ libraries**: stacked multi-line layout, one row per detected library with icon + name + signal count. A `Hide` / `Show` button in the banner header collapses the list; the collapsed state is persisted in `chrome.storage.local.trackerBannerCollapsed`
- **6+ libraries**: the stacked list caps at ~125px height and becomes mouse-wheel scrollable with a hidden scrollbar

The Summary JSON export includes a top-level `trackingLibraries` array rolling up per-library signal counts and distinct signals. Adding a new tracker is a ~15–30 line registry entry — no new timers, observers, or iterations needed.

### Registry authoring conventions

Lessons accumulated while growing the registry:

- **Prefer distinctive globals over generic prefixes.** Short prefixes like `swan` or `s` false-positive on unrelated code. Listing 5–8 specific multi-word globals is safer than a 3-char prefix catch-all.
- **Avoid IAB-standard globals in CMP entries.** `__tcfapi` / `__gpp` / `__uspapi` / `__cmpGdprAppliesGlobally` are set by *every* CMP (OneTrust, iubenda, Usercentrics, Osano, Quantcast Choice, etc.) — using them as detection signals would cross-match every entry. Use vendor-specific globals (`OneTrust`, `UC_UI`, `_iub`) and cookies instead.
- **Skip too-generic filenames.** Things like `/collect.js`, `/bundle.min.js`, `/index.js`, or 32-hex-char webpack hashes match unrelated webpack output on arbitrary sites. Host match + distinctive globals are enough.
- **Watch for cookie collisions between vendors.** `_vuid` is set by both Yahoo Rapid and Listrak — neither entry uses it as a signal any more (caught during review).
- **Heritage / acquisition artefacts are stable signals.** Legacy cookie / global / domain names persist for years after rebrands and are often the most reliable detection surface: `_etmc` (ExactTarget inside Salesforce MC), `rxVisitor`/`rxvt` (Ruxit inside Dynatrace), `ywxi.net` (McAfee SECURE inside TrustedSite), `GlobalE_Analytics_Borderfree` (Borderfree inside Global-e), `pSUPERFLY` (Chartbeat's 15+ year old codename), `2o7.net` (Omniture inside Adobe Analytics), `bnc.lt` (pre-rebrand Branch).

### Known perf note

`scanStorage` currently loops `cookies × libraries × keyPatterns` — roughly O(n × 70 × avg 3) regex tests per scan. Acceptable today (50–200ms on heavy pages) but a future optimisation would invert this into a precomputed Map lookup at registration time. Not urgent.

## Anti-tamper spoofing

The extension avoids being detected by anti-bot scripts through four layered defenses, all in `src/inject.js` + `src/hooks/privacy.js`:

1. **`fnWrapperMap`** (WeakMap) — records every wrapper → native function pair at hook install time. Used by the `Function.prototype.toString` override so calling `.toString()` on our wrappers returns the original native source with the `[native code]` marker. WeakMap so GC'd with the wrapper.

2. **`copyFnIdentity(wrapper, orig)`** — copies `.name` and `.length` from the native to the wrapper via `Object.defineProperty`. Without this, sites can detect us via `fn.name === "wrapper"` or `fn.length === 0` checks. Applied to every wrapper installed by `hookMethod` / `hookMethodHot` / `hookGetter`.

3. **`Object.prototype.toString` wrapper** — detects proxy-tamper probes like `Object.prototype.toString.call(window)` while spoofing back native output. Fast-exits for non-fingerprint targets, self-unwraps on first detected probe, hard 5s deadline unwrap regardless so hot paths (JSON.stringify, template literals) don't pay ongoing cost.

4. **Descriptor spoofing** — `Object.getOwnPropertyDescriptor` / `getOwnPropertyDescriptors` / `Reflect.getOwnPropertyDescriptor` are overridden to synthesize fake data descriptors for access-based hooks (`hookMethodViaAccess`). Without this, sites probing descriptors would see `.get` set and `.value` undefined — a clear tampering signal. The overrides use the same `fnWrapperMap` + `copyFnIdentity` treatment so they're themselves invisible.

## Build system

```bash
npm install           # install esbuild + eslint + web-ext
npm run build         # src/inject.js + src/hooks/*.js → dist/inject.js (minified IIFE)
npm run watch         # auto-rebuild on file changes (unminified for easier dev)
npm run lint          # ESLint on src/
npm run lint:ext      # build + assemble build-tmp/ + web-ext lint (Firefox compat check)
npm run lint:all      # runs both ESLint and web-ext lint
```

- esbuild bundles all modules into a single IIFE in `dist/inject.js`
- Production build is minified (`--minify --legal-comments=none`) — ~87kb (grew from ~65kb as the tracker registry expanded from 9 → 70+ entries); watch mode is unminified (~160kb) for easier dev
- `dist/` and `build-tmp/` are gitignored — built locally for dev, built in CI for releases
- manifest.json points to `dist/inject.js`, not `src/inject.js`
- To test locally: run `npm run build`, then load unpacked in Chrome

## Linting

Two linters run on every push and PR:

**ESLint** (`npm run lint`):
- Browser + extension globals declared in `eslint.config.js`
- Hook modules have `args: none` rule to suppress unused-param warnings (each hook only uses a subset of the helper fns)
- Security rules enforced: `no-eval`, `no-implied-eval`, `no-new-func`
- Style rules: `no-var`, `prefer-const`, `eqeqeq`

**web-ext lint** (`npm run lint:ext`):
- Mozilla's extension linter catches manifest/API issues ESLint can't
- Runs on a prepared `build-tmp/` directory with Firefox-patched manifest
- Catches manifest errors, unsupported fields, CSP violations, deprecated APIs
- 9 innerHTML warnings are false positives (all values sanitized via `escapeHtml`)

## Test harness

`tests.html` at the repo root is a standalone manual test page. Each section simulates a category of fingerprinting APIs so you can verify the extension catches them:

- 39 sections (non-interactive + interactive)
- Non-interactive section "Run All" executes every auto-test in sequence
- Interactive sections show permission prompts (geolocation, clipboard, camera, file picker, etc.)
- Each section shows a ✓ Done / ✗ Error badge and lists the APIs it exercised
- Tracker-library simulations (fingerprintjsDetect, matomoDetect, akamaiBotManagerDetect, otherTrackerLibs) set globals + cookies + DOM scripts to trip each detector
- Section count must always match test-function count 1:1

Open locally via `file://` or serve via `python3 -m http.server`. With the extension loaded, check the Debug Log panel to see which hooks fired.

## Development guidelines

### Adding a new fingerprinting hook

1. Find the appropriate hook module in `src/hooks/` (or create a new one)
2. Add the hook inside the `register()` function using the helpers from the params:
   - `hookMethod(proto, prop, category, method)` — rate-limited (first 3 calls + every 100th)
   - `hookMethodHot(proto, prop, category, method)` — fire-once then self-unwraps (use for high-frequency APIs)
   - `hookMethodViaAccess(proto, prop, category, method)` — access-based: returns native, keeps our frame out of call stack (use for promise-returning methods that may throw)
   - `hookGetter(proto, prop, category, method)` — for getter properties
   - `record(category, method, detail)` — for custom hooks that need args/return value inspection
   - `recordHot(category, method, detail)` — fire-once version of record
3. Add the category metadata in `popup.js` `CATEGORY_META` object with icon, color, risk level, and description
4. Also add the category to `compare.js` `CATEGORY_META` (same icon/color/risk, no description needed)
5. Guard with `typeof` checks — use `typeof window.X !== "undefined"` (not bare `typeof X` which throws in strict mode)
6. Run `npm run build` and test (open tests.html to verify if applicable)
7. Update `fingerprint_table.md` with the new hook

### Adding a new tracking library detector

1. Append an entry to the `LIBRARIES` array in `hooks/tracking-libraries.js`:
   ```js
   {
     name: "DisplayName",
     category: "NewTrackerDetect",
     globals: [...], globalPrefixes: [...],
     keyPatterns: [...], scriptSrcPatterns: [...],
     domAttributes: [...], classifyOrigin: boolean,
   }
   ```
2. Add `NewTrackerDetect` to `popup.js` CATEGORY_META with icon/color/risk/desc
3. Add `NewTrackerDetect` to `compare.js` CATEGORY_META
4. Add `NewTrackerDetect` to `TRACKING_LIBRARY_CATEGORIES` in popup.js (for the banner)
5. Add a simulation section in `tests.html` (or to the `otherTrackerLibs` catchall)

No new timers, observers, or iterations needed — the shared scan pipeline picks it up automatically.

### Creating a new hook module

```js
// src/hooks/example.js
export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot }) {
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

- **Never** hook APIs that fire thousands of times per second with `hookMethod` — use `hookMethodHot` (self-unwrapping) or `hookMethodViaAccess` (no call-stack overhead)
- **Never** use `...args` spread in hook wrappers — use explicit params or `arguments`
- **Never** call `JSON.stringify` in hot paths
- **Never** use `new Error().stack` directly — use `captureStack()` which uses V8's `Error.captureStackTrace` (saved at init before hooks run, to avoid self-triggering the Error.captureStackTrace hook)
- **Never** use regex in per-call checks — use `indexOf` or `charCodeAt` for string matching
- Use `charCodeAt` fast-exits before expensive checks (e.g., check first char before `indexOf("chrome-extension://")`)
- Pre-compile any regex used in hooks (declare outside the wrapper function)
- Rate-limiting and mute checks are inlined into hook wrappers in `src/inject.js` — keep them in sync if logic changes
- Use **self-unwrapping hooks** for techniques that only probe at startup — restore the native getter/setter after detection is complete (see `extension.js` and `fonts.js` for patterns; `hookMethodHot` does this automatically)
- **Hidden tabs** flush event batches every 2s instead of 250ms — `inject.js` listens for `visibilitychange` to adjust `flushInterval`

### Storage

- `chrome.storage.local` — persistent across browser restarts: mutes (global + per-domain), compare theme preference, tracker-banner collapsed state (`trackerBannerCollapsed`)
- `chrome.storage.session` — survives service worker restarts but clears on browser close: tabData (per-tab keys, gzip-compressed), UI state (pause, filter, active panel), compareLeftData (current tab summary passed to compare page)
- `tabData` in background.js is the primary store, persisted with per-tab dirty tracking + 1s debounce + gzip compression
- SW wake restore path MERGES (not overwrites) in-flight detections that arrived during the async restore window

### Mute system

Two layers: global mutes and per-domain mutes, merged at runtime.
- Stored in `chrome.storage.local` as `mutedGlobal` and `mutedByDomain`
- Bridge.js merges global + current domain mutes and pushes to inject.js via CustomEvent
- Inject.js checks mute Sets before any recording (inlined in hook wrappers for zero overhead when muted)
- Click mute icon = mute on current domain only (persistent)
- Right-click mute icon = mute globally (persistent)
- Mute stops recording but doesn't unhook — the wrapper remains installed (preserves ability to unmute later)

### Popup behavior

- Single-tab only — the popup always shows the currently-active browser tab's data. No multi-tab switching (MV3 popups close on tab switch anyway).
- Debug Log DOM capped at 500 nodes; buffer holds up to 3000 entries
- Precomputed `_hay` (filter haystack) + `_muteKey` per log entry so refilter-on-keystroke is O(N) property reads instead of O(N) string rebuilds
- Fast-path in `addLogBatch` skips buildLogNode for events that would be immediately trimmed (giant initial batch on popup open)
- Tracking-library banner stacks when 2+ libraries detected (see Tracking-library detection section). Collapsible via the `Hide`/`Show` button in the header when in stacked mode; state persists via `chrome.storage.local.trackerBannerCollapsed`.
- `renderSummary` is NOT called on every event batch — only on popup open and after mute-button clicks. Per-batch port messages only update the Debug Log + set the banner `.active` flag, never the Summary panel. Before rebuilding `content.innerHTML`, the set of currently-expanded category names (keyed off `data-cat`) is snapshotted and reapplied afterwards so muting doesn't collapse other open categories.

### Compare view

- `popup.js` → Compare button saves current summary to `chrome.storage.session.compareLeftData` then opens `compare.html` in a new tab
- `compare.html` reads it on load as Site A, then the user drops/loads a JSON file for Site B
- Supports method-level diff inside shared categories (not just category-level)
- Three toggles: **Show only differences**, **Show methods**, **Light/Dark mode**
- **Lazy rendering**: method sub-rows are only built when "Show methods" is first toggled on
- **Cached DOM refs** + **cached method sets** — no repeated DOM queries or set rebuilding
- Export differences creates a JSON with unique-to-A, unique-to-B, shared categories + method-level diffs within shared categories

### Firefox compatibility

- Single manifest.json serves both Chrome and Firefox. `browser_specific_settings.gecko` (id + strict_min_version 128.0 + data_collection_permissions { required: ["none"] }) is in the root manifest. Chrome silently ignores unknown keys.
- Release workflow additionally patches the manifest via `jq` to convert `background.service_worker` → `background.scripts` for the XPI build (Firefox MV3 supports both, but older tooling prefers scripts).
- `data_collection_permissions: { required: ["none"] }` is required by AMO for all new extensions.
- Firefox 128+ supports `"world": "MAIN"` natively — no loader workaround needed
- Use `typeof window.X` not `typeof X` for global checks (strict mode ReferenceError)
- `Error.captureStackTrace` is V8-only — `captureStack()` has a `new Error().stack` fallback and saves a private native reference at init so our own Error.captureStackTrace hook doesn't trigger on our own calls
- `Intl.NumberFormat.format` and `Intl.Collator.compare` are getter-based accessors — use `hookGetter` not `hookMethod`
- `navigator.serviceWorker` access throws SecurityError in sandboxed iframes — hook `ServiceWorkerContainer.prototype` directly instead of touching `navigator.serviceWorker`

### Release process

Run the "Build and Release CRX" workflow from the Actions tab:
1. Pick bump type: **patch** / **minor** (default) / **major** — or set an exact version override
2. Workflow auto-bumps `manifest.json`, commits "Release vX.Y.Z", pushes
3. Generates changelog from git log since last tag
4. Creates annotated git tag
5. Runs `npm ci && npm run lint && npm run build` to lint and produce minified bundle
6. Packages CRX (Chrome) + ZIP (Chrome/sideload) + XPI (Firefox with patched manifest)
7. Creates GitHub release with changelog and all 3 assets
- Version flows: manifest.json → popup footer (read at runtime via `chrome.runtime.getManifest().version`)
- Uses `actions/checkout@v5` and `actions/setup-node@v5` (Node 22)

## Caps and limits

| Layer | Cap | Scope |
|---|---|---|
| inject.js rate limiter | First 3 full detail, then every 100th | Per method per tab |
| inject.js `recordHot` | 1 event ever | Per method per tab |
| inject.js batch flush (visible tab) | 50 events max, 250ms interval | Per tab |
| inject.js batch flush (hidden tab) | 50 events max, 2000ms interval | Per tab |
| Extension probe log | First + every 50th summary | Per tab |
| Extension ID Set | 5,000 IDs | Per tab |
| WebSocket local port Set | 1,000 ports | Per tab |
| Font probe counter unwrap | 1,000 probes OR 5s → restore native getters | Per tab |
| Extension probe idle unwrap | 2 seconds of no probes → restore setters | Per tab |
| Object.prototype.toString unwrap | First probe OR 5s → restore native | Per tab |
| fetch/XHR extension hook hard deadline | 3s (actually removed entirely — kept here for history) | N/A |
| Background detections | 2,000 | Per tab |
| Background categories | 300 | Per category per tab |
| Background tabs stored | 50 | Global (oldest evicted) |
| Popup log entries | 3,000 | Per tab |
| Popup DOM nodes | 500 visible | Per tab |
| Session storage save | 1000ms debounce, per-tab keys, gzip-compressed | Global |

## Security posture

- **No external network requests** — all data stays in `chrome.storage.local` / `chrome.storage.session`
- **No eval / Function constructor** — enforced by ESLint
- **Explicit CSP in manifest** — `script-src 'self'; object-src 'self'`
- **All `innerHTML` values escaped** via `escapeHtml()` which uses `textContent`
- **No telemetry, analytics, or remote code**
- **Anti-tamper spoofing** — `Function.prototype.toString` / `Object.prototype.toString` / `name` / `length` / descriptors all spoof back native-looking output, so sites checking for extension presence see an untampered browser
- See `SECURITY.md` for the full privacy promise and threat model

## Common pitfalls

- `FontFaceSet` must be referenced as `window.FontFaceSet` — bare reference throws ReferenceError in strict mode
- `Intl.NumberFormat.prototype.format` is a getter, not a method — `hookMethodHot` breaks it, use `hookGetter`
- `Node.prototype.appendChild` should NOT be hooked globally — use MutationObserver instead (fires on every DOM append). `adblock.js` already does this.
- `document.createElement` should NOT be hooked globally — same reason. `fonts.js` used to; removed for stack-attribution reasons.
- `Function.prototype.toString` / `Object.prototype.toString` require care when hooking — must register in `fnWrapperMap` with `copyFnIdentity` treatment to stay invisible to tamper checks
- `fetch` / `XMLHttpRequest.open` global wraps cause stack-attribution errors (site fetch rejections get blamed on dist/inject.js). `extension.js` removed its fetch/XHR hooks for this reason.
- Service worker can die after 30s idle — all data must be in `chrome.storage.session`, not just in-memory. SW wake MERGES restored data with in-flight detections (not overwrite).
- `dist/inject.js` is gitignored — always run `npm run build` before testing locally
- The release workflow runs the build automatically — don't commit `dist/` to the repo
- `navigator.serviceWorker` access throws in sandboxed iframes — hook `ServiceWorkerContainer.prototype` directly instead
- `chrome.tabs.sendMessage` to tabs without content scripts (chrome://, extension pages) triggers `runtime.lastError` — always consume it in callbacks
- Setters can't return values — `no-setter-return` ESLint rule catches this (use `setter(val); return;` pattern)
- Adding a new category requires updating: `popup.js` CATEGORY_META + `compare.js` CATEGORY_META + `fingerprint_table.md`
- Adding a new tracking library requires updating: `hooks/tracking-libraries.js` LIBRARIES array + `popup.js` CATEGORY_META + TRACKING_LIBRARY_CATEGORIES + `compare.js` CATEGORY_META + `tests.html`. Also check the icon isn't already used elsewhere (collisions have caught us multiple times — e.g. 🛡️ was in use by GPC / Akamai BM / Transcend, 🌐 by Network / Media.net, ⭐ by Bazaarvoice, ☁️ by Cloudflare).
- `hookMethodHot` self-unwraps after first fire — if you combine it with a manual wrap of the same method, the identity check in the wrapper prevents clobbering your wrap
- Wrappers must preserve `this` via `.apply(this, arguments)` or Web IDL methods throw "Illegal invocation" when called on valid instances
- `hookMethodViaAccess` is preferred for promise-returning methods so our frame stays out of rejection stacks (e.g. permission denials, network errors)
