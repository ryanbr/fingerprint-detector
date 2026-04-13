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

  // NOTE: We deliberately do NOT hook EventTarget.addEventListener to
  // detect behavioral event attachment. That approach had two problems:
  //
  // 1. Putting our wrapper in the call stack of every addEventListener
  //    call meant any native throw (e.g. Permissions Policy violations
  //    on unload listeners) was attributed to dist/inject.js in
  //    Chrome's Errors panel — the extension got blamed for page bugs.
  //
  // 2. It was a noisy signal anyway. Every React/Vue/framework page
  //    attaches mousemove/click/keydown listeners legitimately. Listener
  //    attachment is not fingerprinting on its own.
  //
  // The property-read hooks below (MouseEvent.clientX, KeyboardEvent.key,
  // Touch.force, etc.) are strictly stronger signal — they only fire
  // when a handler actually *reads* cursor/keystroke/touch data, which
  // is what behavioral fingerprinting actually does.

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
