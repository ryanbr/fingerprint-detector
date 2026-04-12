# Fingerprint Detector

A Chrome extension that detects and displays browser fingerprinting techniques used by websites in real-time.

## What it does

Websites use fingerprinting to identify and track users without cookies. This extension hooks into 43+ browser APIs commonly used for fingerprinting and reports exactly which techniques a site is using, which scripts are responsible, and whether they originate from iframes or third-party code.

## Features

- **Summary view** — categorized detections with risk levels (high/medium/low), call counts, and source URLs
- **Live debug log** — real-time stream of every fingerprinting API access with millisecond timestamps
- **Source tracking** — shows the exact script URL and line number that triggered each detection
- **Iframe detection** — identifies fingerprinting from embedded iframes with the frame URL tagged
- **Sec-CH-UA detail** — shows which specific Client Hints are being requested and which browser identity they expose
- **Mute system** — mute noisy methods or entire categories; persists across browser restarts
- **Pause/resume** — freeze the debug log while keeping events queued
- **Multi-tab** — watch multiple tabs simultaneously with per-tab isolation
- **Export** — summary (JSON), debug log (JSON/CSV), or full report
- **Per-tab isolation** — each tab's data is independent with 10K event cap per tab
- **Minimal overhead** — batched events, rate limiting, fire-once hooks for high-frequency APIs

## Fingerprinting techniques detected

### High risk
| Technique | What it detects |
|---|---|
| Canvas | `toDataURL`, `getImageData` — GPU/driver/OS fingerprint |
| WebGL | Renderer, vendor, extensions, shader precision |
| Audio | `AudioContext` / `OfflineAudioContext` processing differences |
| Fonts | `offsetWidth`/`offsetHeight` probing on spans, `queryLocalFonts()` |
| WebRTC | `RTCPeerConnection` creation — local/public IP leak |
| Client Hints | `Sec-CH-UA-*` via `getHighEntropyValues()` — arch, bitness, model, platform version |
| MediaDevices | `enumerateDevices` — camera/microphone hardware |
| Math | `Math.tan(-1e300)` etc. — float-point output varies by OS/arch |
| Architecture | `Float32Array` NaN bit pattern — x86 vs ARM detection |
| WebGPU | `gpu.requestAdapter()` — GPU hardware details |
| Hardware | Bluetooth, USB, Serial, HID device enumeration |
| Sensors | Accelerometer, Gyroscope, Magnetometer, AmbientLightSensor |
| Keyboard | `keyboard.getLayoutMap()` — language/locale detection |

### Medium risk
| Technique | What it detects |
|---|---|
| Navigator | `userAgent`, `hardwareConcurrency`, `deviceMemory`, `maxTouchPoints`, `platform` |
| Client Rects | `getBoundingClientRect` — varies by font rendering |
| Permissions | `Permissions.query`, `Notification.permission` |
| Speech Synthesis | `getVoices()` — installed voice enumeration |
| Plugins | `navigator.plugins`, `navigator.mimeTypes` |
| GPC | `navigator.globalPrivacyControl` — privacy preference signal |
| DNT | `navigator.doNotTrack` — 1-bit privacy fingerprint |
| Media Queries | `matchMedia` — prefers-color-scheme, reduced-motion, color-gamut, forced-colors |
| WebSocket | `new WebSocket()` — can reveal real IP behind VPN/proxy |
| Timing | `performance.now()`, `PerformanceObserver` — high-resolution timers |
| Vendor Detection | Browser-specific globals (`window.chrome`, `window.opr`, `window.vivaldi`, `navigator.brave`) |
| Ad Block Detection | `offsetParent` probing on ad-like elements |
| Intl | `Intl.NumberFormat`, `Intl.Collator` locale detection |
| Credentials | `credentials.get()` / `credentials.create()` — WebAuthn probing |
| CSS Prefixes | `CSS.supports()` with `-webkit-`, `-moz-`, `-ms-` |

### Low risk
| Technique | What it detects |
|---|---|
| Screen | `width`, `height`, `colorDepth`, `devicePixelRatio`, `availTop`/`availLeft` |
| Timezone | `getTimezoneOffset`, `Intl.DateTimeFormat.resolvedOptions` |
| Storage | `cookieEnabled`, `localStorage`, `sessionStorage`, `indexedDB`, `openDatabase` |
| Touch | `ontouchstart`, `document.createEvent('TouchEvent')` |
| Network | `connection.effectiveType`, `downlink`, `rtt`, `saveData` |

### Browser-specific detection
| Browser | What's detected |
|---|---|
| Brave | `navigator.brave.isBrave()`, `Sec-CH-UA` brands containing "Brave" |
| Edge | `__edgeTrackingPreventionStatistics`, `MSStream`, `Sec-CH-UA` brands |
| Opera | `window.opr`, `opr.addons`, `Sec-CH-UA` brands containing "Opera" |
| Vivaldi | `window.vivaldi`, `Sec-CH-UA` brands containing "Vivaldi" |
| Safari | `window.safari`, `ApplePaySession`, `<a>.attributionSourceId` |

## Install

1. Clone or download this repo
2. Open `chrome://extensions`
3. Enable **Developer mode** (top right)
4. Click **Load unpacked**
5. Select the `fingerprint-detector` folder

## Usage

- The badge on the extension icon shows how many fingerprinting categories were detected (green = low, orange = medium, red = high)
- Click the icon to open the popup
- **Summary tab** — grouped by category, sorted by risk. Hover any entry for a mute button
- **Debug Log tab** — live event stream. Click any row to expand its call stack
  - **Mute** — click the mute icon on a row to mute that method, right-click to mute the entire category
  - **Filter** — type in the filter bar to search by category, method, source URL, or frame URL
  - **Pause** — freeze the log while events queue up, resume to flush
  - **Export** — download summary or log as JSON/CSV
  - **Multi-tab** — click tab chips to watch fingerprinting across multiple tabs

## How it works

1. **inject.js** runs in the page's MAIN world at `document_start`, wrapping fingerprinting-related APIs with detection hooks
2. **bridge.js** runs in the ISOLATED world, forwarding batched events from the page to the extension
3. **background.js** stores per-tab detection data and streams events to the popup via persistent ports
4. **popup.js** renders the summary and debug log views

High-frequency APIs (`performance.now`, `Math.*`, `getBoundingClientRect`, `localStorage`) use fire-once hooks that record the first call then become pure passthrough — zero overhead after detection.

## License

GPL-3.0
