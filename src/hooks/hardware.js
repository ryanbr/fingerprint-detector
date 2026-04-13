// hooks/hardware.js — WebGPU, Bluetooth/USB/Serial/HID, Sensors, Keyboard Layout
export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 23. WebGPU ────────────────────────────────────────────────────────
  if (typeof GPU !== "undefined") {
    // Access-based hook: page code often destructures or caches
    // requestAdapter, which throws "Illegal invocation" from the native
    // call site. Using a getter keeps our frame out of that stack trace.
    hookMethodViaAccess(GPU.prototype, "requestAdapter", "WebGPU", "gpu.requestAdapter");
  }
  if (typeof GPUAdapter !== "undefined") {
    hookMethod(GPUAdapter.prototype, "requestDevice", "WebGPU", "gpuAdapter.requestDevice");
    hookMethod(GPUAdapter.prototype, "requestAdapterInfo", "WebGPU", "gpuAdapter.requestAdapterInfo");
  }

  // ── 24. Bluetooth / USB / Serial / HID (hardware enumeration) ────────
  // All of these return promises and are commonly called via destructured
  // references — use access-based hooks so our wrapper isn't in the
  // rejection stack on "Illegal invocation".
  if (typeof Bluetooth !== "undefined" && Bluetooth.prototype.requestDevice) {
    hookMethodViaAccess(Bluetooth.prototype, "requestDevice", "Hardware", "bluetooth.requestDevice");
    hookMethodViaAccess(Bluetooth.prototype, "getDevices", "Hardware", "bluetooth.getDevices");
  }
  if (typeof USB !== "undefined") {
    hookMethodViaAccess(USB.prototype, "getDevices", "Hardware", "usb.getDevices");
    hookMethodViaAccess(USB.prototype, "requestDevice", "Hardware", "usb.requestDevice");
  }
  if (typeof Serial !== "undefined") {
    hookMethodViaAccess(Serial.prototype, "getPorts", "Hardware", "serial.getPorts");
    hookMethodViaAccess(Serial.prototype, "requestPort", "Hardware", "serial.requestPort");
  }
  if (typeof HID !== "undefined") {
    hookMethodViaAccess(HID.prototype, "getDevices", "Hardware", "hid.getDevices");
    hookMethodViaAccess(HID.prototype, "requestDevice", "Hardware", "hid.requestDevice");
  }

  // ── 25. Sensor APIs ──────────────────────────────────────────────────
  for (const SensorCls of ["Accelerometer", "Gyroscope", "Magnetometer",
    "AbsoluteOrientationSensor", "RelativeOrientationSensor",
    "LinearAccelerationSensor", "GravitySensor", "AmbientLightSensor"]) {
    if (typeof window[SensorCls] !== "undefined") {
      const Orig = window[SensorCls];
      const sensorLabel = "new " + SensorCls;
      window[SensorCls] = function (options) {
        recordHot("Sensors", sensorLabel, SensorCls);
        return options ? new Orig(options) : new Orig();
      };
      window[SensorCls].prototype = Orig.prototype;
    }
  }

  // ── 21. Keyboard Layout API ───────────────────────────────────────────
  if (typeof Keyboard !== "undefined" && Keyboard.prototype.getLayoutMap) {
    hookMethod(Keyboard.prototype, "getLayoutMap", "Keyboard", "keyboard.getLayoutMap");
  }
}
