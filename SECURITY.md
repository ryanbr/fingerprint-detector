# Security & Privacy

## Privacy promise

Fingerprint Detector is **strictly local**. It never sends any data outside your browser.

**What we DO:**
- Hook fingerprinting-related browser APIs to detect when sites probe them
- Store detection data in `chrome.storage.local` and `chrome.storage.session` (both are local to your browser profile)
- Display detection results in the extension popup and the compare view
- Allow you to manually export detection data as a JSON/CSV file that you download to your own computer

**What we DO NOT do:**
- ❌ No telemetry
- ❌ No analytics
- ❌ No crash reporting
- ❌ No external network requests
- ❌ No remote code loading
- ❌ No user accounts, login, or identity
- ❌ No syncing across devices
- ❌ No third-party services
- ❌ No cookies or auth tokens read

## Permissions explained

| Permission | Why we need it |
|---|---|
| `activeTab` | Query the current tab URL to display in the popup and name exports |
| `webNavigation` | Clear per-tab detection data when a page navigates to a new URL |
| `storage` | Save mutes (`chrome.storage.local`), UI state and detection data (`chrome.storage.session`) |
| `tabs` | Enumerate tabs with detection data for the multi-tab debug log |
| `<all_urls>` content scripts | Inject detection hooks into every frame to catch fingerprinting anywhere |

## Security controls

| Control | Implementation |
|---|---|
| **Content Security Policy** | MV3 default CSP (`script-src 'self'; object-src 'self'`) enforced, explicitly declared in manifest |
| **No eval / Function constructor** | ESLint rules `no-eval`, `no-implied-eval`, `no-new-func` fail the build |
| **HTML escaping** | All dynamic values written to `innerHTML` are escaped via `escapeHtml()` (uses `textContent`) |
| **No remote code** | No `<script src="https://...">`, no CDN, no external modules |
| **Bundled code** | `dist/inject.js` is built with esbuild; source tree is auditable |
| **CI linting** | ESLint + web-ext lint run on every push and before every release |
| **Code signing** | CRX is signed with a key generated per-release in the build workflow |
| **Minimum Firefox** | 128.0 — ensures modern security features are available |

## Data flow

```
Website (untrusted)
  ↓
inject.js (MAIN world, untrusted context)
  ↓ CustomEvent (local to page)
bridge.js (ISOLATED world, content script)
  ↓ chrome.runtime.sendMessage (local IPC)
background.js (service worker)
  ↓ port.postMessage (local IPC)
popup.js / compare.js (extension pages)
  ↓
chrome.storage.local / session (local to browser)
```

No data crosses the browser boundary at any point.

## Threats we defend against

| Threat | Mitigation |
|---|---|
| Malicious page injecting scripts into extension UI | Strict CSP blocks inline scripts; `escapeHtml` on all innerHTML |
| Malicious JSON file in Compare view | JSON.parse throws on invalid input; schema-checked before render; all values escaped when displayed |
| Service worker data loss | Persisted to `chrome.storage.session` so data survives worker restarts |
| Extension sandboxing bypass | All fingerprinting hooks run in the page's context and cannot escape the browser sandbox |

## What you should know

- **The extension can see everything you visit** — that's inherent to detecting fingerprinting everywhere. If you don't trust this code, audit the source at https://github.com/ryanbr/fingerprint-detector or build it yourself from source.
- **Detection can be noisy** — normal websites use some of these APIs legitimately. The extension distinguishes real fingerprinting via rate limiting and burst detection but isn't perfect.
- **Your mutes and export files are yours** — they live only in your browser and wherever you choose to save the exports. We never see them.

## Reporting security issues

If you find a security issue, please file an issue at:
https://github.com/ryanbr/fingerprint-detector/issues

For sensitive disclosures, mark the issue as private or reach the author via the repo.

## License

GPL-3.0 — the code is open source and auditable.
