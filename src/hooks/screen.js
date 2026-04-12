// hooks/screen.js — Screen properties, devicePixelRatio, availTop/availLeft
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
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
}
