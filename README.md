# Fingerprint Detector

A Chrome and Firefox extension that detects and displays browser fingerprinting techniques used by websites in real-time.

<img width="964" height="510" alt="bbUntitled2" src="https://github.com/user-attachments/assets/dab173bb-ce9b-4ebc-b19d-a5697d9cf23e" />

## What it does

Websites use fingerprinting to identify and track users without cookies. This extension hooks into 60+ browser APIs commonly used for fingerprinting and reports exactly which techniques a site is using, which scripts are responsible, and whether they originate from iframes or third-party code.

## Features

- **Summary view** — categorized detections with risk levels (high/medium/low), call counts, and source URLs
- **Live debug log** — real-time stream of every fingerprinting API access with millisecond timestamps
- **Source tracking** — shows the exact script URL and line number that triggered each detection
- **Iframe detection** — identifies fingerprinting from embedded iframes with the frame URL tagged
- **Sec-CH-UA detail** — shows which specific Client Hints are being requested and which browser identity they expose
- **Per-domain mutes** — mute noisy methods per site or globally; persists across browser restarts
- **Pause/resume** — freeze the debug log while keeping events queued; auto-disables when you scroll up
- **Multi-tab** — watch multiple tabs simultaneously with per-tab isolation
- **Export** — summary (JSON), debug log (JSON/CSV), or full report with domain breakdown and extension probe list
- **Per-tab isolation** — each tab's data is independent with 10K event cap per tab
- **Persistent state** — detection data survives service worker restarts; UI state persists across popup reopens
- **Minimal overhead** — batched events, rate limiting, fire-once hooks, V8-optimized stack capture

## Fingerprinting techniques detected

### High risk
| Technique | What it detects |
|---|---|
| Canvas | `toDataURL`, `getImageData`, `measureText`, `OffscreenCanvas` — GPU/driver/OS fingerprint |
| WebGL | Renderer, vendor, extensions, shader precision, shader compilation errors, draw+readPixels, `WEBGL_debug_renderer_info` |
| WebGL2 | `getInternalformatParameter`, instanced drawing, indexed parameters |
| Audio | `AudioContext` / `OfflineAudioContext` processing differences, `baseLatency` |
| Fonts | `offsetWidth`/`offsetHeight` probing, `queryLocalFonts()`, `document.fonts.check/load/forEach` |
| WebRTC | Full IP leak pipeline: STUN server config, `createDataChannel`, `createOffer`, `setLocalDescription`, ICE candidate IP extraction, `RTCRtpSender/Receiver.getCapabilities()` codec enumeration |
| Client Hints | `Sec-CH-UA-*` via `getHighEntropyValues()` with hint-to-header mapping, `Accept-CH` meta tag detection, brand identity exposure (Brave/Edge/Opera/Vivaldi) |
| MediaDevices | `enumerateDevices` — camera/microphone hardware |
| Math | `Math.tan(-1e300)` etc. — float-point output varies by OS/arch |
| Architecture | `Float32Array` NaN bit pattern — x86 vs ARM detection |
| WebGPU | `gpu.requestAdapter()`, `GPUAdapter.limits/features` — GPU hardware details |
| Hardware | Bluetooth, USB, Serial, HID device enumeration |
| Sensors | Accelerometer, Gyroscope, Magnetometer, AmbientLightSensor |
| Keyboard | `keyboard.getLayoutMap()` — language/locale detection |
| Ad Block Detection | offsetParent burst detection, 90+ known FingerprintJS bait element IDs/classes, create-check-remove cycle detection |
| Extension Detection | `chrome-extension://` URL probing via fetch/XHR/img/link/setAttribute, `chrome.runtime.sendMessage` to extension IDs, `getComputedStyle` burst detection for injected CSS |
| Headless Detection | `navigator.webdriver`, `visualViewport` dimensions, `navigator.share/canShare` absence |

### Medium risk
| Technique | What it detects |
|---|---|
| Navigator | `userAgent`, `hardwareConcurrency`, `deviceMemory`, `maxTouchPoints`, `platform`, `pdfViewerEnabled` |
| Client Rects | `getBoundingClientRect`, `getClientRects` — varies by font rendering |
| Permissions | `Permissions.query`, `Notification.permission` |
| Speech Synthesis | `getVoices()` — installed voice enumeration |
| Plugins | `navigator.plugins`, `navigator.mimeTypes` |
| GPC | `navigator.globalPrivacyControl` — privacy preference signal |
| DNT | `navigator.doNotTrack` — 1-bit privacy fingerprint |
| Media Queries | `matchMedia` — prefers-color-scheme, reduced-motion, color-gamut, forced-colors, dynamic-range, contrast, monochrome |
| WebSocket | Localhost/local IP port scanning detection, connection burst detection, VPN bypass probing |
| Timing | `performance.now()`, `getEntries`, `PerformanceObserver` — high-resolution timers |
| Vendor Detection | Browser-specific globals (`window.chrome`, `window.opr`, `window.opera`, `window.vivaldi`, `navigator.brave`), CSS vendor prefix probing |
| Intl | `Intl.NumberFormat/Collator/DisplayNames/Locale`, `supportedValuesOf`, `Date.toLocaleString`, `Number.toLocaleString` |
| Credentials | `credentials.get()` / `credentials.create()` — WebAuthn probing |
| Apple Pay | `ApplePaySession.canMakePayments()` |
| Private Click | Safari `<a>.attributionSourceId` — Privacy Preserving Ad Measurement |

### Low risk
| Technique | What it detects |
|---|---|
| Screen | `width`, `height`, `colorDepth`, `devicePixelRatio`, `availTop`/`availLeft` (taskbar size) |
| Timezone | `getTimezoneOffset`, `Intl.DateTimeFormat.resolvedOptions` |
| Storage | `cookieEnabled`, `localStorage`, `sessionStorage`, `indexedDB`, `openDatabase`, `navigator.storage.estimate()` (disk size leak) |
| Touch | `ontouchstart`, `document.createEvent('TouchEvent')` |
| Network | `connection.effectiveType`, `downlink`, `rtt`, `saveData` |

### Browser-specific detection
| Browser | What's detected |
|---|---|
| Brave | `navigator.brave.isBrave()`, `Sec-CH-UA` brands containing "Brave" |
| Edge | `__edgeTrackingPreventionStatistics`, `__edgeContentSpoofingProtection`, `MSStream`, `msCredentials`, `Sec-CH-UA` brands |
| Opera | `window.opr`, `window.opera`, `opr.addons`, `opr.sidebarAction`, `Sec-CH-UA` brands |
| Vivaldi | `window.vivaldi`, `vivaldi.jdhooks`, `Sec-CH-UA` brands |
| Safari | `window.safari`, `ApplePaySession`, `<a>.attributionSourceId` |
| Yandex | `window.yandex`, `window.__yb`, `window.__ybro` |
| Samsung | `window.samsungAr` |
| Firefox | `window.__firefox__` |

## Install

### Chrome
1. Download the latest `.crx` or `.zip` from [Releases](https://github.com/ryanbr/fingerprint-detector/releases)
2. Open `chrome://extensions`
3. Enable **Developer mode** (top right)
4. Drag the `.crx` file onto the page, or click **Load unpacked** and select the unzipped folder

### Firefox
1. Download the latest `.xpi` from [Releases](https://github.com/ryanbr/fingerprint-detector/releases)
2. Open the `.xpi` file in Firefox, or go to `about:addons` and install from file
3. Requires Firefox 128+

## Usage

- The badge on the extension icon shows how many fingerprinting categories were detected (green = low, orange = medium, red = high)
- Click the icon to open the popup
- **Summary tab** — grouped by category, sorted by risk
  - Hover any entry for a mute button
  - Click = mute on this domain only, right-click = mute on all sites
- **Debug Log tab** — live event stream
  - Click any row to expand its call stack
  - **Mute** — click the mute icon to mute that method on this site, right-click to mute globally
  - **Filter** — search by category, method, source URL, or frame URL
  - **Pause** — freeze the log; scrolling up auto-pauses, scrolling to bottom auto-resumes
  - **Export** — download summary or log as JSON/CSV with domain breakdown
  - **Multi-tab** — click tab chips to watch fingerprinting across multiple tabs

## Export format

Exports include a domain breakdown showing which domains are fingerprinting:

```json
{
  "domains": {
    "ads.tracker.com": {
      "calls": 47,
      "categories": ["Canvas", "WebGL"],
      "isThirdParty": true
    }
  },
  "extensionProbes": {
    "totalProbes": 823,
    "uniqueExtensionIds": ["cjpalhdlnbpafiamejdnhcphjbkeiagm", "..."]
  }
}
```

## How it works

1. **inject.js** runs in the page's MAIN world at `document_start`, wrapping fingerprinting-related APIs with detection hooks
2. **bridge.js** runs in the ISOLATED world, forwarding batched events from the page to the extension and syncing mute state
3. **background.js** stores per-tab detection data (persisted to `chrome.storage.session`), streams events to the popup via persistent ports
4. **popup.js** renders the summary and debug log views with per-domain mute persistence

### Performance

- **Fire-once hooks** (`hookMethodHot`) for high-frequency APIs — `performance.now`, `Math.*`, `getBoundingClientRect`, `localStorage` record once then become pure passthrough
- **Rate limiting** — first 3 calls per method get full stack traces, then every 100th
- **Batched dispatch** — events queued and flushed every 250ms (max 50 per batch)
- **V8 optimizations** — `Error.captureStackTrace` instead of `new Error()`, `indexOf` instead of regex for URL extraction, `charCodeAt` fast-exits on hot-path string checks
- **Inlined mute checks** — wrapper functions check mute Sets directly, avoiding function call overhead when muted
- **Extension probe rate limiting** — first probe logged with full detail, then periodic summaries every 50 probes
- **DOM cap** — max 500 visible log entries, 10K stored per tab, 5K per tab in background

## License

GPL-3.0
