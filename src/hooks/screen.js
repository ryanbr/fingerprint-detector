// hooks/screen.js — Screen properties, devicePixelRatio, availTop/availLeft
export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 5. Screen Properties ──────────────────────────────────────────────
  const screenProps = ["width", "height", "colorDepth", "pixelDepth", "availWidth", "availHeight"];
  for (const prop of screenProps) {
    hookGetter(Screen.prototype, prop, "Screen", `screen.${prop}`);
  }

  // ── 19. Device Pixel Ratio ────────────────────────────────────────────
  {
    const dprDesc = Object.getOwnPropertyDescriptor(window, "devicePixelRatio") ||
                    Object.getOwnPropertyDescriptor(Window.prototype, "devicePixelRatio");
    if (dprDesc && dprDesc.get) {
      const origGet = dprDesc.get;
      Object.defineProperty(window, "devicePixelRatio", {
        ...dprDesc,
        get() {
          record("Screen", "window.devicePixelRatio", "devicePixelRatio");
          return origGet.call(this);
        },
      });
    }
  }

  // ── 37. Screen Frame (taskbar/dock size) ──────────────────────────────
  for (const prop of ["availTop", "availLeft"]) {
    hookGetter(Screen.prototype, prop, "Screen", `screen.${prop}`);
  }

  // ── Screen Orientation API ────────────────────────────────────────────
  // type: "portrait-primary" / "landscape-primary" / etc.
  // angle: 0 / 90 / 180 / 270
  // Strong mobile fingerprint — desktops generally report
  // landscape-primary + 0, mobile varies by device hold state.
  if (typeof ScreenOrientation !== "undefined") {
    hookGetter(ScreenOrientation.prototype, "type", "Screen", "screen.orientation.type");
    hookGetter(ScreenOrientation.prototype, "angle", "Screen", "screen.orientation.angle");
    if (typeof ScreenOrientation.prototype.lock === "function") {
      hookMethodViaAccess(ScreenOrientation.prototype, "lock", "Permissions", "screen.orientation.lock");
    }
    if (typeof ScreenOrientation.prototype.unlock === "function") {
      hookMethodHot(ScreenOrientation.prototype, "unlock", "Permissions", "screen.orientation.unlock");
    }
  }
}
