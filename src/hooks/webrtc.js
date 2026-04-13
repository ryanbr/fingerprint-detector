// hooks/webrtc.js — WebRTC fingerprinting (IP leak, ICE candidates, codec enumeration)
export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 7. WebRTC Fingerprinting ────────────────────────────────────────────
  // WebRTC is used for:
  // - Local/public IP discovery via ICE candidates
  // - STUN server probing to extract IPs behind VPN
  // - Media codec enumeration via getCapabilities()
  if (typeof RTCPeerConnection !== "undefined") {
    const OrigRTC = RTCPeerConnection;

    window.RTCPeerConnection = function (config, constraints) {
      // Log STUN/TURN servers — these are used to extract public IPs
      let stunServers = "";
      if (config && config.iceServers) {
        const urls = [];
        for (const server of config.iceServers) {
          const u = server.urls || server.url;
          if (Array.isArray(u)) { for (let j = 0; j < u.length; j++) urls.push(u[j]); }
          else if (u) urls.push(u);
        }
        stunServers = urls.join(", ");
      }
      record("WebRTC", "new RTCPeerConnection", stunServers || "(no ICE servers)");

      const pc = constraints ? new OrigRTC(config, constraints) : new OrigRTC(config);

      // Hook onicecandidate — this is where IP addresses leak
      const origDesc = Object.getOwnPropertyDescriptor(OrigRTC.prototype, "onicecandidate");
      let iceCandidateHooked = false;

      if (origDesc && origDesc.set) {
        const origSet = origDesc.set;
        Object.defineProperty(pc, "onicecandidate", {
          get() { return origDesc.get ? origDesc.get.call(this) : undefined; },
          set(handler) {
            if (!iceCandidateHooked && typeof handler === "function") {
              iceCandidateHooked = true;
              const wrappedHandler = function (event) {
                if (event && event.candidate && event.candidate.candidate) {
                  const c = event.candidate.candidate;
                  // Extract IP from ICE candidate string
                  const ipMatch = c.match(/(\d+\.\d+\.\d+\.\d+|[0-9a-f:]{3,})/i);
                  if (ipMatch) {
                    record("WebRTC", "ICE candidate (IP leak)", ipMatch[0] + " — " + c.slice(0, 80));
                  }
                }
                return handler.call(this, event);
              };
              origSet.call(this, wrappedHandler);
              return;
            }
            origSet.call(this, handler);
          },
          configurable: true,
        });
      }

      return pc;
    };
    window.RTCPeerConnection.prototype = OrigRTC.prototype;

    // Hook the IP leak pipeline methods on the prototype.
    // createDataChannel is sync — plain hookMethod is fine. The other
    // four return promises and commonly lose `this` via destructuring,
    // so use access-based to keep our frame out of rejection stacks.
    hookMethod(OrigRTC.prototype, "createDataChannel", "WebRTC", "createDataChannel");
    hookMethodViaAccess(OrigRTC.prototype, "createOffer", "WebRTC", "createOffer");
    hookMethodViaAccess(OrigRTC.prototype, "createAnswer", "WebRTC", "createAnswer");
    hookMethodViaAccess(OrigRTC.prototype, "setLocalDescription", "WebRTC", "setLocalDescription");
    hookMethodViaAccess(OrigRTC.prototype, "setRemoteDescription", "WebRTC", "setRemoteDescription");

    // Hook addEventListener for "icecandidate" — alternative to onicecandidate
    const origAddEL = OrigRTC.prototype.addEventListener;
    OrigRTC.prototype.addEventListener = function (type, listener, opts) {
      if (type === "icecandidate" && typeof listener === "function") {
        record("WebRTC", "addEventListener('icecandidate')", "");
        const origListener = listener;
        listener = function (event) {
          if (event && event.candidate && event.candidate.candidate) {
            const c = event.candidate.candidate;
            const ipMatch = c.match(/(\d+\.\d+\.\d+\.\d+|[0-9a-f:]{3,})/i);
            if (ipMatch) {
              record("WebRTC", "ICE candidate (IP leak)", ipMatch[0] + " — " + c.slice(0, 80));
            }
          }
          return origListener.call(this, event);
        };
      }
      return origAddEL.call(this, type, listener, opts);
    };

    // Media codec fingerprinting via getCapabilities (static method)
    if (typeof RTCRtpSender !== "undefined" && RTCRtpSender.getCapabilities) {
      const origSenderCaps = RTCRtpSender.getCapabilities;
      RTCRtpSender.getCapabilities = function (kind) {
        record("WebRTC", "RTCRtpSender.getCapabilities", kind || "");
        return origSenderCaps.call(this, kind);
      };
    }
    if (typeof RTCRtpReceiver !== "undefined" && RTCRtpReceiver.getCapabilities) {
      const origReceiverCaps = RTCRtpReceiver.getCapabilities;
      RTCRtpReceiver.getCapabilities = function (kind) {
        record("WebRTC", "RTCRtpReceiver.getCapabilities", kind || "");
        return origReceiverCaps.call(this, kind);
      };
    }
  }
}
