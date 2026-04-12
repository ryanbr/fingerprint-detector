// hooks/hardware.js — WebGPU, Bluetooth/USB/Serial/HID, Sensors, Keyboard Layout
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 23. WebGPU ────────────────────────────────────────────────────────
  if (typeof GPU !== "undefined") {
    hookMethod(GPU.prototype, "requestAdapter", "WebGPU", "gpu.requestAdapter");
  }
  if (typeof GPUAdapter !== "undefined") {
    hookMethod(GPUAdapter.prototype, "requestDevice", "WebGPU", "gpuAdapter.requestDevice");
    hookMethod(GPUAdapter.prototype, "requestAdapterInfo", "WebGPU", "gpuAdapter.requestAdapterInfo");
  }

  // ── 24. Bluetooth / USB / Serial / HID (hardware enumeration) ────────
  if (typeof Bluetooth !== "undefined" && Bluetooth.prototype.requestDevice) {
    hookMethod(Bluetooth.prototype, "requestDevice", "Hardware", "bluetooth.requestDevice");
    hookMethod(Bluetooth.prototype, "getDevices", "Hardware", "bluetooth.getDevices");
  }
  if (typeof USB !== "undefined") {
    hookMethod(USB.prototype, "getDevices", "Hardware", "usb.getDevices");
    hookMethod(USB.prototype, "requestDevice", "Hardware", "usb.requestDevice");
  }
  if (typeof Serial !== "undefined") {
    hookMethod(Serial.prototype, "getPorts", "Hardware", "serial.getPorts");
    hookMethod(Serial.prototype, "requestPort", "Hardware", "serial.requestPort");
  }
  if (typeof HID !== "undefined") {
    hookMethod(HID.prototype, "getDevices", "Hardware", "hid.getDevices");
    hookMethod(HID.prototype, "requestDevice", "Hardware", "hid.requestDevice");
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
