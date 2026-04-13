// hooks/behavior.js — Behavioral fingerprinting (mouse, keyboard, touch, pointer)
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // Behavioral fingerprinting captures user interaction patterns:
  // - Mouse movement velocity/trajectory (biometric signature)
  // - Keystroke dynamics (typing rhythm, hold time)
  // - Touch gestures (pressure, finger size)
  // - Scroll patterns
  // - Pointer events with pressure/tilt
  //
  // These are detected at the event-listener level (addEventListener)
  // since the events themselves fire constantly and we can't hook those.

  const BEHAVIORAL_EVENTS = {
    // Mouse tracking
    "mousemove":     { category: "Behavior", label: "mousemove tracking", risk: "high" },
    "mousedown":     { category: "Behavior", label: "mousedown tracking", risk: "medium" },
    "mouseup":       { category: "Behavior", label: "mouseup tracking", risk: "medium" },
    "click":         { category: "Behavior", label: "click tracking", risk: "medium" },
    "dblclick":      { category: "Behavior", label: "dblclick tracking", risk: "medium" },
    "contextmenu":   { category: "Behavior", label: "contextmenu listener", risk: "low" },
    "wheel":         { category: "Behavior", label: "wheel (scroll) tracking", risk: "medium" },

    // Keyboard tracking (keystroke dynamics)
    "keydown":       { category: "Behavior", label: "keydown tracking", risk: "high" },
    "keyup":         { category: "Behavior", label: "keyup tracking", risk: "high" },
    "keypress":      { category: "Behavior", label: "keypress tracking (deprecated)", risk: "high" },
    "input":         { category: "Behavior", label: "input event tracking", risk: "medium" },
    "beforeinput":   { category: "Behavior", label: "beforeinput tracking", risk: "medium" },
    "compositionstart": { category: "Behavior", label: "IME composition tracking", risk: "medium" },
    "compositionupdate": { category: "Behavior", label: "IME composition tracking", risk: "medium" },

    // Pointer events (unified mouse/touch/pen)
    "pointermove":   { category: "Behavior", label: "pointermove tracking", risk: "high" },
    "pointerdown":   { category: "Behavior", label: "pointerdown tracking", risk: "medium" },
    "pointerup":     { category: "Behavior", label: "pointerup tracking", risk: "medium" },

    // Touch events (mobile)
    "touchmove":     { category: "Behavior", label: "touchmove tracking", risk: "high" },
    "touchstart":    { category: "Behavior", label: "touchstart tracking", risk: "medium" },
    "touchend":      { category: "Behavior", label: "touchend tracking", risk: "medium" },

    // Scroll tracking
    "scroll":        { category: "Behavior", label: "scroll tracking", risk: "medium" },

    // Focus patterns
    "focus":         { category: "Behavior", label: "focus tracking", risk: "low" },
    "blur":          { category: "Behavior", label: "blur tracking", risk: "low" },
    "visibilitychange": { category: "Behavior", label: "visibility change tracking", risk: "low" },

    // Drag tracking
    "drag":          { category: "Behavior", label: "drag tracking", risk: "medium" },
    "dragstart":     { category: "Behavior", label: "dragstart tracking", risk: "medium" },

    // Device orientation (motion-based biometric)
    "devicemotion":  { category: "Behavior", label: "devicemotion tracking", risk: "high" },
    "deviceorientation": { category: "Behavior", label: "deviceorientation tracking", risk: "high" },
  };

  // Hook EventTarget.addEventListener to detect behavioral tracking.
  // We use a fire-once-per-event-type pattern so each unique event type
  // is only logged once across the page lifetime — no flood from multiple
  // scripts attaching the same listener.
  const seenEvents = Object.create(null);
  const origAddEventListener = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, listener, options) {
    if (typeof type === "string" && BEHAVIORAL_EVENTS[type] && !seenEvents[type]) {
      seenEvents[type] = true;
      const meta = BEHAVIORAL_EVENTS[type];
      // Identify the target type (window/document/element)
      let targetType = "unknown";
      if (this === window) targetType = "window";
      else if (this === document) targetType = "document";
      else if (this && this.tagName) targetType = this.tagName.toLowerCase();
      else if (this && this.constructor && this.constructor.name) targetType = this.constructor.name;
      recordHot("Behavior", meta.label, targetType + "." + type);
    }
    return origAddEventListener.apply(this, arguments);
  };

  // Mouse event properties that reveal exact cursor coordinates.
  // Hooking these on the MouseEvent prototype catches sites reading them
  // inside event handlers.
  if (typeof MouseEvent !== "undefined") {
    const MOUSE_PROPS = [
      "clientX", "clientY", "screenX", "screenY",
      "pageX", "pageY", "offsetX", "offsetY",
      "movementX", "movementY",
    ];
    // Fire-once per property — don't spam on every mouse event read
    const readProps = Object.create(null);
    for (const prop of MOUSE_PROPS) {
      const desc = Object.getOwnPropertyDescriptor(MouseEvent.prototype, prop);
      if (!desc || !desc.get) continue;
      const origGet = desc.get;
      Object.defineProperty(MouseEvent.prototype, prop, {
        ...desc,
        get() {
          if (!readProps[prop]) {
            readProps[prop] = true;
            recordHot("Behavior", "MouseEvent." + prop, "cursor coordinate read");
          }
          return origGet.call(this);
        },
      });
    }
  }

  // KeyboardEvent properties that reveal keystroke details.
  if (typeof KeyboardEvent !== "undefined") {
    const KEY_PROPS = ["key", "code", "keyCode", "which", "charCode"];
    const readKeyProps = Object.create(null);
    for (const prop of KEY_PROPS) {
      const desc = Object.getOwnPropertyDescriptor(KeyboardEvent.prototype, prop);
      if (!desc || !desc.get) continue;
      const origGet = desc.get;
      Object.defineProperty(KeyboardEvent.prototype, prop, {
        ...desc,
        get() {
          if (!readKeyProps[prop]) {
            readKeyProps[prop] = true;
            recordHot("Behavior", "KeyboardEvent." + prop, "keystroke read");
          }
          return origGet.call(this);
        },
      });
    }
  }

  // Pointer event properties — pressure and tilt reveal stylus/pen hardware
  if (typeof PointerEvent !== "undefined") {
    const POINTER_PROPS = ["pressure", "tangentialPressure", "tiltX", "tiltY", "twist", "pointerType", "isPrimary"];
    const readPointerProps = Object.create(null);
    for (const prop of POINTER_PROPS) {
      const desc = Object.getOwnPropertyDescriptor(PointerEvent.prototype, prop);
      if (!desc || !desc.get) continue;
      const origGet = desc.get;
      Object.defineProperty(PointerEvent.prototype, prop, {
        ...desc,
        get() {
          if (!readPointerProps[prop]) {
            readPointerProps[prop] = true;
            recordHot("Behavior", "PointerEvent." + prop, "pointer property read");
          }
          return origGet.call(this);
        },
      });
    }
  }

  // Touch event properties — finger size and force reveal device characteristics
  if (typeof Touch !== "undefined") {
    const TOUCH_PROPS = ["radiusX", "radiusY", "rotationAngle", "force"];
    const readTouchProps = Object.create(null);
    for (const prop of TOUCH_PROPS) {
      const desc = Object.getOwnPropertyDescriptor(Touch.prototype, prop);
      if (!desc || !desc.get) continue;
      const origGet = desc.get;
      Object.defineProperty(Touch.prototype, prop, {
        ...desc,
        get() {
          if (!readTouchProps[prop]) {
            readTouchProps[prop] = true;
            recordHot("Behavior", "Touch." + prop, "touch hardware read");
          }
          return origGet.call(this);
        },
      });
    }
  }
}
