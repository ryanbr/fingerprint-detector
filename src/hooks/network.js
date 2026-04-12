// hooks/network.js — Connection Info, WebSocket (with port scanning detection)
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 14. Connection Info ───────────────────────────────────────────────
  if (typeof NetworkInformation !== "undefined") {
    for (const prop of ["effectiveType", "downlink", "rtt", "saveData"]) {
      hookGetter(NetworkInformation.prototype, prop, "Network", `connection.${prop}`);
    }
  }

  // ── 16. WebSocket Fingerprinting ──────────────────────────────────────
  // WebSocket connections can:
  // - Reveal real IP behind VPN/proxy (bypass HTTP proxy)
  // - Probe localhost ports to detect installed software
  // - Scan local network services
  // - Measure round-trip latency for network fingerprinting
  if (typeof WebSocket !== "undefined") {
    const OrigWS = WebSocket;

    // Local address patterns for port scanning detection
    const LOCAL_RE = /^wss?:\/\/(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)(:\d+)?/i;

    // Track connection bursts (rapid opens = port scanning)
    let wsCount = 0;
    let wsBurstStart = 0;
    let wsLocalCount = 0;
    const wsLocalPorts = new Set();
    const MAX_WS_PORTS = 1000; // cap memory
    const WS_BURST_WINDOW = 2000; // ms
    const WS_BURST_THRESHOLD = 5;
    let wsBurstReported = false;
    let wsLocalReported = false;

    function extractPort(url) {
      try {
        const u = new URL(url);
        return u.port || (u.protocol === "wss:" ? "443" : "80");
      } catch (_) {
        return "";
      }
    }

    window.WebSocket = function (url, protocols) {
      const urlStr = typeof url === "string" ? url : String(url);
      const now = Date.now();

      // Reset burst window
      if (now - wsBurstStart > WS_BURST_WINDOW) {
        wsCount = 0;
        wsBurstStart = now;
      }
      wsCount++;

      // Detect localhost/local network probing (port scanning)
      const isLocal = LOCAL_RE.test(urlStr);
      if (isLocal) {
        wsLocalCount++;
        if (wsLocalPorts.size < MAX_WS_PORTS) {
          wsLocalPorts.add(extractPort(urlStr));
        }

        if (wsLocalCount === 1) {
          // First local probe — log with full detail
          record("WebSocket", "localhost probe", urlStr);
        }
        if (wsLocalCount % 10 === 0 && !wsLocalReported) {
          record("WebSocket", "localhost port scan",
            wsLocalCount + " local connections across " + wsLocalPorts.size + " ports");
        }
        if (wsLocalPorts.size >= 5 && !wsLocalReported) {
          wsLocalReported = true;
          record("WebSocket", "localhost port scan detected",
            wsLocalPorts.size + " unique ports probed: " +
            [...wsLocalPorts].slice(0, 20).join(", ") +
            (wsLocalPorts.size > 20 ? "..." : ""));
        }
      } else {
        // Non-local WebSocket — log first one
        if (wsCount === 1) {
          record("WebSocket", "new WebSocket", urlStr);
        }
      }

      // Detect rapid connection burst (any target)
      if (wsCount >= WS_BURST_THRESHOLD && !wsBurstReported) {
        wsBurstReported = true;
        record("WebSocket", "connection burst",
          wsCount + " connections in " + WS_BURST_WINDOW + "ms");
      }

      return protocols !== undefined ? new OrigWS(url, protocols) : new OrigWS(url);
    };
    window.WebSocket.prototype = OrigWS.prototype;
    for (const key of ["CONNECTING", "OPEN", "CLOSING", "CLOSED"]) {
      window.WebSocket[key] = OrigWS[key];
    }

    // Expose local port scan data for export
    window.addEventListener("__fpDetector_getWsPorts", () => {
      if (wsLocalPorts.size > 0) {
        window.dispatchEvent(new CustomEvent("__fpDetector_wsPorts", {
          detail: JSON.stringify({
            totalLocal: wsLocalCount,
            totalAll: wsCount,
            ports: [...wsLocalPorts],
          }),
        }));
      }
    });
  }
}
