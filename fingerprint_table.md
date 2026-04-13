# Fingerprinting Checks Reference Table

This document lists every fingerprinting technique the extension detects. Each row shows the category, API hooked, the specific value or behavior it reveals, and its fingerprinting risk level.

Categories are color-coded in the extension UI:
- 🔴 **High** — strong identifying signal, often highly unique per device/browser
- 🟠 **Medium** — contributes to a fingerprint but less entropy alone
- 🟢 **Low** — useful only in combination with other signals

## Canvas

| Hook | Risk | What it reveals |
|---|---|---|
| `CanvasRenderingContext2D.toDataURL()` | 🔴 High | Base64 PNG/JPEG of canvas — pixel-level output varies by GPU, driver, OS, anti-aliasing settings |
| `CanvasRenderingContext2D.toBlob()` | 🔴 High | Same as toDataURL but as a Blob object |
| `CanvasRenderingContext2D.getImageData()` | 🔴 High | Raw pixel data (RGBA array) — same fingerprinting signal as toDataURL |
| `CanvasRenderingContext2D.measureText()` | 🔴 High | TextMetrics object (width, ascent, descent) — varies by OS font rendering |
| `CanvasRenderingContext2D.fillText()` | 🔴 High | Text rendering — the setup step before extraction |
| `CanvasRenderingContext2D.strokeText()` | 🔴 High | Outlined text rendering |
| `CanvasRenderingContext2D.isPointInPath()` | 🔴 High | Hit-test results vary by rendering engine |
| `CanvasRenderingContext2D.isPointInStroke()` | 🔴 High | Same for stroke paths |
| `CanvasRenderingContext2D.drawImage()` | 🔴 High | Copying canvas content between canvases for extraction |
| `HTMLCanvasElement.toDataURL()` / `toBlob()` | 🔴 High | Alternative API paths to the same extraction |
| `HTMLCanvasElement.getContext('2d')` | 🔴 High | 2D canvas context creation |
| `new OffscreenCanvas(w, h)` | 🔴 High | Worker-based canvas — bypasses main-thread hooks |
| `OffscreenCanvas.getContext()` | 🔴 High | Context creation on offscreen canvas |
| `OffscreenCanvas.convertToBlob()` | 🔴 High | Extracting pixel data from offscreen canvas |
| `OffscreenCanvas.transferToImageBitmap()` | 🔴 High | Same via ImageBitmap |
| `createImageBitmap(canvas)` | 🔴 High | Alternative extraction path without toDataURL |

## WebGL / WebGL2

| Hook | Risk | What it reveals |
|---|---|---|
| `WebGLRenderingContext.getParameter()` | 🔴 High | GPU limits (`MAX_TEXTURE_SIZE`, `MAX_VIEWPORT_DIMS`, etc.) — vary by GPU |
| `WebGLRenderingContext.getSupportedExtensions()` | 🔴 High | Full extension list — unique per GPU/driver combo |
| `WebGLRenderingContext.getExtension()` | 🔴 High | Specific extension support checks |
| `WebGLRenderingContext.getShaderPrecisionFormat()` | 🔴 High | Float/int precision per shader type — varies by hardware |
| `WebGLRenderingContext.readPixels()` | 🔴 High | Raw pixel data from GPU-rendered output (canvas fingerprint via GPU) |
| `createShader / shaderSource / compileShader` | 🔴 High | Shader compilation pipeline |
| `getShaderInfoLog / getProgramInfoLog` | 🔴 High | Error messages vary by GPU driver |
| `createProgram / linkProgram` | 🔴 High | Shader program creation |
| `drawArrays / drawElements` | 🔴 High | GPU renders geometry differently per hardware |
| `getBufferParameter / getRenderbufferParameter` | 🔴 High | Buffer limits vary by GPU |
| `getFramebufferAttachmentParameter` | 🔴 High | Framebuffer support varies |
| `getExtension("WEBGL_debug_renderer_info")` | 🔴 High | Explicitly flagged — exposes GPU vendor/renderer string (`ANGLE (NVIDIA GeForce RTX 3080...)`) |
| WebGL2: `getInternalformatParameter` | 🔴 High | Format support per GPU |
| WebGL2: `getIndexedParameter` | 🔴 High | Indexed buffer binding limits |
| WebGL2: `drawArraysInstanced / drawElementsInstanced / drawRangeElements` | 🔴 High | Instanced rendering support |

## Audio

| Hook | Risk | What it reveals |
|---|---|---|
| `new AudioContext({ sampleRate })` | 🔴 High | Audio context creation + sample rate config |
| `new OfflineAudioContext(ch, len, rate)` | 🔴 High | The primary audio fingerprinting context — logs channels, buffer length, sample rate |
| `AudioContext.createOscillator()` | 🔴 High | Test signal generator |
| `AudioContext.createDynamicsCompressor()` | 🔴 High | Compressor output varies by implementation (the classic audio fingerprint) |
| `AudioContext.createAnalyser()` | 🔴 High | Frequency/time-domain extraction |
| `AudioContext.createGain()` / `createBiquadFilter()` | 🔴 High | Additional processing nodes in the chain |
| `AudioContext.createBuffer()` / `createBufferSource()` | 🔴 High | Custom audio data injection |
| `AudioContext.createScriptProcessor()` | 🔴 High | Script-based audio processing |
| `AudioNode.connect()` | 🔴 High | Wiring the audio processing chain |
| `OfflineAudioContext.startRendering()` | 🔴 High | Triggers the offline render that produces the fingerprint |
| `AudioBuffer.getChannelData()` | 🔴 High | Raw audio samples — the extraction step (like toDataURL for canvas) |
| `AudioBuffer.copyFromChannel()` | 🔴 High | Alternative buffer read |
| `AnalyserNode.getFloatFrequencyData()` | 🔴 High | Frequency spectrum data |
| `AnalyserNode.getByteFrequencyData()` | 🔴 High | Byte-format frequency data |
| `AnalyserNode.getFloatTimeDomainData()` | 🔴 High | Waveform data |
| `AnalyserNode.getByteTimeDomainData()` | 🔴 High | Byte-format waveform |
| `audioContext.sampleRate` | 🔴 High | Audio hardware sample rate (44100/48000/etc.) |
| `audioContext.baseLatency` / `outputLatency` | 🔴 High | Latency varies by audio driver |
| `audioContext.destination` / `state` | 🔴 High | Output device info and context state |

## Navigator / User-Agent

| Hook | Risk | What it reveals |
|---|---|---|
| `navigator.userAgent` | 🟠 Medium | Full UA string |
| `navigator.appVersion` | 🟠 Medium | Browser version string |
| `navigator.appName` / `appCodeName` / `product` | 🟠 Medium | Legacy browser identification |
| `navigator.platform` | 🟠 Medium | OS platform (`Win32`, `Linux x86_64`) |
| `navigator.oscpu` | 🟠 Medium | Firefox-specific OS/CPU string |
| `navigator.cpuClass` | 🟠 Medium | IE-specific CPU class |
| `navigator.buildID` | 🟠 Medium | Firefox-specific build timestamp |
| `navigator.language` / `languages` | 🟠 Medium | UI language + preference list |
| `navigator.hardwareConcurrency` | 🔴 High | Reported CPU core count |
| `navigator.deviceMemory` | 🔴 High | Approximate RAM in GB |
| `navigator.maxTouchPoints` | 🟠 Medium | Touch support level |
| `navigator.vendor` / `productSub` / `vendorSub` | 🟠 Medium | Browser vendor info |
| `navigator.connection` | 🟢 Low | NetworkInformation object access |
| `navigator.getBattery()` | 🟠 Medium | Battery level, charging state |
| `navigator.getGamepads()` | 🟠 Medium | Gamepad hardware enumeration |
| `navigator.javaEnabled()` | 🟠 Medium | Legacy Java plugin probe |
| `navigator.taintEnabled()` | 🟠 Medium | Ancient API presence check |
| `navigator.pdfViewerEnabled` | 🟠 Medium | PDF viewer availability |
| `navigator.plugins` | 🟠 Medium | Plugin enumeration |
| `navigator.mimeTypes` | 🟠 Medium | MIME type enumeration |
| `new Worker(url)` | 🔴 High | Worker creation + pool burst detection (hardware concurrency probing) |
| `new SharedWorker(url)` | 🔴 High | Cross-tab worker |
| `new SharedArrayBuffer(len)` | 🔴 High | Used for timing-based core counting |
| `Atomics.wait / notify / waitAsync` | 🔴 High | Cross-worker synchronization in core count benchmarks |
| `serviceWorker.register()` | 🟠 Medium | SW registration |
| `serviceWorker.getRegistrations()` | 🟠 Medium | Enumerates installed SWs — browsing history signal |
| `serviceWorker.getRegistration()` | 🟠 Medium | Check specific scope |
| `serviceWorker.ready` / `controller` | 🟠 Medium | SW activation state |

## Client Hints (Sec-CH-UA)

| Hook | Risk | What it reveals |
|---|---|---|
| `navigator.userAgentData` | 🔴 High | UA data object access |
| `userAgentData.brands` | 🔴 High | Browser brand list — detects Brave, Edge, Opera, Vivaldi |
| `userAgentData.mobile` | 🔴 High | Mobile/desktop flag |
| `userAgentData.platform` | 🔴 High | Simplified OS platform |
| `userAgentData.getHighEntropyValues()` | 🔴 High | Architecture, bitness, model, platformVersion, uaFullVersion — logged with mapping to Sec-CH-UA-* header names |
| `userAgentData.toJSON()` | 🔴 High | Full UA data dump |
| `<meta http-equiv="Accept-CH">` | 🔴 High | Accept-CH meta tag — server-hint request via HTML |

## Privacy / GPC / DNT / Headless

| Hook | Risk | What it reveals |
|---|---|---|
| `navigator.globalPrivacyControl` | 🟠 Medium | GPC signal — 1-bit privacy preference |
| `navigator.doNotTrack` | 🟠 Medium | DNT signal |
| `navigator.webdriver` | 🔴 High | Automation flag — `true` in Puppeteer/Playwright/Selenium |
| `visualViewport.width/height/scale/offsetTop/offsetLeft` | 🔴 High | Mismatches with screen dimensions reveal headless browsers |
| `navigator.share()` / `canShare()` | 🔴 High | Absence indicates headless Chrome |
| `window.outerWidth / outerHeight` | 🔴 High | 0 = headless browser |
| `window.screenX / screenY` | 🔴 High | 0,0 = automation window |
| `window.innerWidth / innerHeight` | 🔴 High | Viewport size probing |
| `document.hidden` / `visibilityState` | 🔴 High | Tab backgrounding detection |
| `Function.prototype.toString` on native APIs | 🔴 High | Anti-spoofing check — detects anti-fingerprinting extensions |
| Automation globals (`cdc_adoQpoasnfa76pfcZLmcfl`, `__webdriver_*`, `_phantom`, `__nightmare`, etc.) | 🔴 High | ChromeDriver, Selenium, Puppeteer, PhantomJS, Watir detection |
| `$cdc_*` document properties | 🔴 High | ChromeDriver DOM signature |

## Screen

| Hook | Risk | What it reveals |
|---|---|---|
| `screen.width / height` | 🟢 Low | Monitor resolution |
| `screen.colorDepth / pixelDepth` | 🟢 Low | Color bit depth |
| `screen.availWidth / availHeight` | 🟢 Low | Usable screen area |
| `screen.availTop / availLeft` | 🟢 Low | Taskbar/dock position — reveals OS UI layout |
| `window.devicePixelRatio` | 🟢 Low | DPR — reveals zoom level and HiDPI displays |

## Fonts

| Hook | Risk | What it reveals |
|---|---|---|
| `HTMLElement.offsetWidth` on SPAN/DIV/P/A | 🔴 High | Text dimension probing — reveals which fonts are installed |
| `HTMLElement.offsetHeight` on SPAN/DIV/P/A | 🔴 High | Same via height |
| `Element.scrollWidth / scrollHeight` on SPAN/DIV/P/A | 🔴 High | Alternative dimension probe |
| System font keyword probing (`system-ui`, `serif`, `sans-serif`, `caption`, `menu`...) | 🔴 High | Reveals default font preferences and OS UI fonts |
| `window.queryLocalFonts()` | 🔴 High | Direct Font Access API — full installed font list |
| `document.fonts.check()` | 🔴 High | Direct font availability test |
| `document.fonts.load()` | 🔴 High | Font loading probe |
| `document.fonts.forEach()` | 🔴 High | Enumerate loaded fonts |
| `document.fonts.add()` | 🔴 High | Adding fonts to document |
| `document.fonts.ready` | 🔴 High | Awaited before font probing sequences |
| `new FontFace()` | 🔴 High | Dynamic font loading test |
| `createElement('iframe')` | 🔴 High | Font metrics measurement iframe creation |

## WebRTC

| Hook | Risk | What it reveals |
|---|---|---|
| `new RTCPeerConnection({ iceServers })` | 🔴 High | STUN/TURN server URLs logged — reveals config |
| `createDataChannel()` | 🔴 High | Part of IP leak pipeline |
| `createOffer()` / `createAnswer()` | 🔴 High | Part of IP leak pipeline |
| `setLocalDescription()` / `setRemoteDescription()` | 🔴 High | Part of IP leak pipeline |
| `onicecandidate` handler | 🔴 High | ICE candidates intercepted — leaked IPs logged directly |
| `addEventListener("icecandidate")` | 🔴 High | Alternative ICE candidate path |
| `RTCRtpSender.getCapabilities()` | 🔴 High | Audio/video codec enumeration |
| `RTCRtpReceiver.getCapabilities()` | 🔴 High | Same for receiver side |

## WebSocket

| Hook | Risk | What it reveals |
|---|---|---|
| `new WebSocket(url)` | 🟠 Medium | WebSocket connection creation — first non-local connection logged |
| Localhost / local IP probe (`ws://127.0.0.1`, `ws://192.168.*`, `ws://[::1]`) | 🟠 Medium | Local port scanning — detects software running on the user's machine |
| 5+ unique local ports probed | 🟠 Medium | Port scan alert with full port list |
| 5+ connections in 2 seconds | 🟠 Medium | Connection burst — scanning pattern |

## Storage

| Hook | Risk | What it reveals |
|---|---|---|
| `localStorage.getItem / setItem / removeItem / clear` | 🟢 Low | Local storage read/write/cleanup |
| `localStorage.key() / length` | 🟢 Low | Stored key enumeration |
| `document.cookie` | 🟢 Low | Cookie read for tracking |
| `navigator.cookieEnabled` | 🟢 Low | Cookie support check |
| `window.sessionStorage` | 🟢 Low | Session storage access |
| `indexedDB.open()` | 🟢 Low | Opening a database |
| `indexedDB.databases()` | 🟢 Low | Enumerates all DB names — reveals browsing history, installed PWAs |
| `indexedDB.deleteDatabase()` | 🟢 Low | DB cleanup after probing |
| `IDBDatabase.createObjectStore / transaction / close` | 🟢 Low | DB operations |
| `IDBDatabase.objectStoreNames` | 🟢 Low | Store enumeration |
| `IDBObjectStore.get / getAll / count / getAllKeys` | 🟢 Low | Data reads |
| `navigator.storage.estimate()` | 🟢 Low | Returns `{ usage, quota }` — quota reveals approximate disk size |
| `navigator.storage.persist()` / `persisted()` | 🟢 Low | Persistence state |
| `window.openDatabase` (Web SQL) | 🟢 Low | Legacy Web SQL access |
| `new BroadcastChannel(name)` | 🟢 Low | Cross-tab communication |
| `caches.keys()` | 🟢 Low | Cache enumeration — reveals visited sites |
| `caches.open() / has() / match()` | 🟢 Low | Cache probing |

## Timezone / Intl

| Hook | Risk | What it reveals |
|---|---|---|
| `Date.getTimezoneOffset()` | 🟢 Low | Timezone offset in minutes |
| `Intl.DateTimeFormat.resolvedOptions()` | 🟢 Low | IANA timezone + locale |
| `Intl.NumberFormat.resolvedOptions()` | 🟠 Medium | Locale + numbering system |
| `Intl.Collator.resolvedOptions()` | 🟠 Medium | Sort order locale |
| `Intl.ListFormat / PluralRules / RelativeTimeFormat / Segmenter .resolvedOptions()` | 🟠 Medium | Additional locale data |
| `Intl.DisplayNames.of()` | 🟠 Medium | Localized language/region names |
| `Intl.NumberFormat.format` (getter) | 🟠 Medium | Formatter access |
| `Intl.Collator.compare` (getter) | 🟠 Medium | Collator access |
| `Intl.Locale.language/region/script/calendar/numberingSystem/hourCycle/baseName` | 🟠 Medium | Direct locale component access |
| `Intl.supportedValuesOf()` | 🟠 Medium | Enumerates supported calendars, numbering systems, timezones |
| `Date.toLocaleString / toLocaleDateString / toLocaleTimeString` | 🟠 Medium | Date format varies by locale (MM/DD/YYYY vs DD.MM.YYYY) |
| `Number.toLocaleString` | 🟠 Medium | Decimal/group separator varies (1,234.56 vs 1.234,56) |
| `Array.toLocaleString` | 🟠 Medium | Array formatting with locale |

## Media Devices / Speech Synthesis

| Hook | Risk | What it reveals |
|---|---|---|
| `MediaDevices.enumerateDevices()` | 🔴 High | Cameras, microphones, speakers enumeration |
| `speechSynthesis.getVoices()` | 🟠 Medium | Installed TTS voice list — varies by OS/language packs |
| `speechSynthesis.speak()` | 🟠 Medium | Silent speech timing attacks |
| `speechSynthesis.cancel()` | 🟠 Medium | Speech cancellation |
| `speechSynthesis.onvoiceschanged` | 🟠 Medium | Voice list change listener |
| `speechSynthesis.pending / speaking / paused` | 🟠 Medium | State checks |
| `new SpeechSynthesisUtterance()` | 🟠 Medium | Utterance creation |
| `utterance.voice =` / `lang =` | 🟠 Medium | Which voice/language is being tested |

## Media Queries (matchMedia)

| Hook | Risk | What it reveals |
|---|---|---|
| `matchMedia(query)` | 🟠 Medium | All CSS media queries — logs the exact query string |

Common fingerprinting queries caught:
- `(prefers-color-scheme: dark/light)`
- `(prefers-reduced-motion: reduce)`
- `(prefers-reduced-transparency: reduce)`
- `(prefers-contrast: high/more/low)`
- `(forced-colors: active)`
- `(color-gamut: srgb/p3/rec2020)`
- `(dynamic-range: high)`
- `(inverted-colors: inverted)`
- `(max-monochrome: N)`

## Keyboard

| Hook | Risk | What it reveals |
|---|---|---|
| `keyboard.getLayoutMap()` | 🔴 High | Keyboard layout — reveals language/locale |

## Hardware APIs

| Hook | Risk | What it reveals |
|---|---|---|
| `Bluetooth.requestDevice() / getDevices()` | 🔴 High | Bluetooth device enumeration |
| `USB.getDevices() / requestDevice()` | 🔴 High | USB device enumeration |
| `Serial.getPorts() / requestPort()` | 🔴 High | Serial port enumeration |
| `HID.getDevices() / requestDevice()` | 🔴 High | HID device enumeration |

## Sensors

| Hook | Risk | What it reveals |
|---|---|---|
| `new Accelerometer()` | 🔴 High | Motion sensor access |
| `new Gyroscope()` | 🔴 High | Rotation sensor access |
| `new Magnetometer()` | 🔴 High | Magnetic field sensor |
| `new AbsoluteOrientationSensor()` / `RelativeOrientationSensor()` | 🔴 High | Device orientation |
| `new LinearAccelerationSensor()` / `GravitySensor()` | 🔴 High | Motion sub-sensors |
| `new AmbientLightSensor()` | 🔴 High | Light level sensor |

## WebGPU

| Hook | Risk | What it reveals |
|---|---|---|
| `gpu.requestAdapter()` | 🔴 High | GPU adapter request |
| `gpuAdapter.requestDevice()` | 🔴 High | GPU device creation |
| `gpuAdapter.requestAdapterInfo()` | 🔴 High | Adapter info — exposes GPU hardware details |

## Math / Architecture

| Hook | Risk | What it reveals |
|---|---|---|
| `Math.acos / acosh / asin / asinh / atan / atanh` | 🔴 High | Float-point output varies by OS/arch |
| `Math.cos / cosh / exp / expm1 / log1p` | 🔴 High | Same |
| `Math.sin / sinh / tan / tanh` | 🔴 High | Same |
| `new Float32Array(1)` | 🔴 High | NaN bit pattern probe — x86 vs ARM architecture detection |

## Timing

| Hook | Risk | What it reveals |
|---|---|---|
| `performance.now()` | 🟠 Medium | High-resolution timer — used for timing attacks and hardware benchmarking |
| `performance.getEntries() / getEntriesByType() / getEntriesByName()` | 🟠 Medium | Resource/navigation/paint timing data |
| `performance.mark() / measure()` | 🟠 Medium | Hardware benchmarking |
| `performance.timeOrigin` | 🟠 Medium | High-precision page start timestamp |
| `performance.timing` | 🟠 Medium | Navigation Timing L1 — detailed page load timing |
| `performance.navigation` | 🟠 Medium | Navigation type and redirect count |
| `performance.memory` (Chrome) | 🟠 Medium | `jsHeapSizeLimit` reveals device RAM |
| `new PerformanceObserver()` | 🟠 Medium | Async performance data collection |

## Touch

| Hook | Risk | What it reveals |
|---|---|---|
| `window.ontouchstart` (get/set) | 🟢 Low | Touch support probing |
| `document.createEvent('TouchEvent')` | 🟢 Low | Touch event creation probe |

## Network Information

| Hook | Risk | What it reveals |
|---|---|---|
| `connection.effectiveType` | 🟢 Low | Network type (4g/wifi/etc.) |
| `connection.downlink` | 🟢 Low | Bandwidth estimate |
| `connection.rtt` | 🟢 Low | Round-trip time |
| `connection.saveData` | 🟢 Low | Data saver preference |

## Vendor Detection (Browser-Specific Globals)

| Hook | Risk | What it reveals |
|---|---|---|
| `window.chrome` | 🟠 Medium | Chrome/Chromium detection |
| `window.safari` / `webkit` | 🟠 Medium | Safari detection |
| `window.__crWeb` / `__gCrWeb` | 🟠 Medium | Chrome iOS WebView |
| `window.__firefox__` | 🟠 Medium | Firefox detection |
| `window.__edgeTrackingPreventionStatistics` | 🟠 Medium | Edge detection |
| `window.__edgeContentSpoofingProtection` | 🟠 Medium | Edge detection |
| `window.MSStream` / `msCredentials` / `MSInputMethodContext` | 🟠 Medium | Edge/IE legacy globals |
| `window.opr` / `opera` / `opr.addons` / `opr.sidebarAction` | 🟠 Medium | Opera detection |
| `window.vivaldi` / `vivaldi.jdhooks` | 🟠 Medium | Vivaldi detection |
| `window.yandex` / `__yb` / `__ybro` | 🟠 Medium | Yandex Browser |
| `window.samsungAr` | 🟠 Medium | Samsung Internet |
| `window.ucweb` / `UCShellJava` | 🟠 Medium | UC Browser |
| `window.puffinDevice` | 🟠 Medium | Puffin Browser |
| `navigator.brave.isBrave()` | 🟠 Medium | Brave browser detection |
| `CSS.supports()` with vendor prefixes (`-webkit-`, `-moz-`, `-ms-`, `-o-`) | 🟠 Medium | Browser engine detection |

## Ad Block Detection

| Hook | Risk | What it reveals |
|---|---|---|
| `offsetParent` burst detection (15+ reads in 200ms) | 🔴 High | FingerprintJS-style filter list detection pattern |
| Known FingerprintJS bait element IDs (90+) | 🔴 High | IDs like `ad_300X250`, `Ad-Content`, `bannerfloat22`, etc. |
| Known FingerprintJS bait classes | 🔴 High | Classes like `sponsored-text-link`, `trafficjunky-ad`, `BetterJsPopOverlay` |
| Create-check-remove cycle (20+ elements in 500ms) | 🔴 High | Classic ad blocker fingerprinting pattern |

## Extension Detection

| Hook | Risk | What it reveals |
|---|---|---|
| `fetch("chrome-extension://...")` | 🔴 High | Web-accessible resource probing |
| `XMLHttpRequest.open("GET", "chrome-extension://...")` | 🔴 High | XHR-based resource probing |
| `Image.src = "chrome-extension://..."` | 🔴 High | Image probe |
| `Link.href = "chrome-extension://..."` | 🔴 High | Link probe |
| `Element.setAttribute("src"/"href", "chrome-extension://...")` | 🔴 High | Covers script, iframe, img, link |
| `chrome.runtime.sendMessage(extId, ...)` | 🔴 High | Direct messaging to known extension IDs |
| `getComputedStyle` burst on body-level elements | 🔴 High | Extension CSS tripwire detection |

## Permissions / Credentials / Apple Pay / Private Click

| Hook | Risk | What it reveals |
|---|---|---|
| `Permissions.query()` | 🟠 Medium | Permission state probing |
| `Notification.permission` | 🟠 Medium | Notification permission state |
| `CredentialsContainer.get()` | 🟠 Medium | WebAuthn / credential probing |
| `CredentialsContainer.create()` | 🟠 Medium | WebAuthn credential creation |
| `ApplePaySession.canMakePayments()` | 🟠 Medium | Apple Pay availability |
| `<a>.attributionSourceId` / `attributionsourceid` | 🟠 Medium | Safari Private Click Measurement |

## Client Rects

| Hook | Risk | What it reveals |
|---|---|---|
| `Element.getClientRects()` | 🟠 Medium | Element bounding rects vary by font rendering |
| `Element.getBoundingClientRect()` | 🟠 Medium | Same |

---

## Summary

| Category | Risk | # of Hooks |
|---|---|---|
| Canvas | 🔴 High | 16 |
| WebGL / WebGL2 | 🔴 High | 15 |
| Audio | 🔴 High | 19 |
| Navigator | 🟠 Medium | 30+ |
| Client Hints (Sec-CH-UA) | 🔴 High | 7 |
| Privacy / Headless | 🔴 High | 13 |
| Screen | 🟢 Low | 6 |
| Fonts | 🔴 High | 12 |
| WebRTC | 🔴 High | 8 |
| WebSocket | 🟠 Medium | 4 |
| Storage / IndexedDB / Cache | 🟢 Low | 18 |
| Timezone / Intl | 🟠 Medium | 13 |
| Media Devices / Speech | 🟠 Medium | 9 |
| Media Queries | 🟠 Medium | 1 |
| Keyboard | 🔴 High | 1 |
| Hardware APIs | 🔴 High | 8 |
| Sensors | 🔴 High | 8 |
| WebGPU | 🔴 High | 3 |
| Math / Architecture | 🔴 High | 16 |
| Timing | 🟠 Medium | 9 |
| Touch / Network | 🟢 Low | 6 |
| Vendor Detection | 🟠 Medium | 17 |
| Ad Block Detection | 🔴 High | 4 |
| Extension Detection | 🔴 High | 7 |
| Permissions / Credentials | 🟠 Medium | 6 |
| Client Rects | 🟠 Medium | 2 |

**Total: 260+ individual fingerprinting hooks** across 36 categories.
