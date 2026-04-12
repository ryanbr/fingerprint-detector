// hooks/storage.js — Storage, Storage Quota, openDatabase, sessionStorage
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 11. Storage Fingerprinting ────────────────────────────────────────
  hookGetter(Navigator.prototype, "cookieEnabled", "Storage", "navigator.cookieEnabled");
  if (typeof Storage !== "undefined") {
    // Hot path — called constantly by many sites
    hookMethodHot(Storage.prototype, "setItem", "Storage", "localStorage.setItem");
    hookMethodHot(Storage.prototype, "getItem", "Storage", "localStorage.getItem");
  }
  if (typeof window.indexedDB !== "undefined") {
    hookMethod(IDBFactory.prototype, "open", "Storage", "indexedDB.open");
  }

  // ── 29d. Storage Quota (disk size leak) ────────────────────────────────
  // navigator.storage.estimate() returns {usage, quota} — the quota reveals
  // approximate disk size which is a high-entropy fingerprint signal.
  if (typeof StorageManager !== "undefined") {
    hookMethod(StorageManager.prototype, "estimate", "Storage", "navigator.storage.estimate");
    hookMethod(StorageManager.prototype, "persist", "Storage", "navigator.storage.persist");
    hookMethod(StorageManager.prototype, "persisted", "Storage", "navigator.storage.persisted");
  }

  // ── 38. openDatabase (Web SQL) ────────────────────────────────────────
  if (typeof window.openDatabase === "function") {
    const origOpenDB = window.openDatabase;
    window.openDatabase = function (name, ver, desc, size) {
      recordHot("Storage", "openDatabase", "");
      return origOpenDB.call(this, name, ver, desc, size);
    };
  }
  // Also check for its existence (boolean probe)
  {
    const desc = Object.getOwnPropertyDescriptor(window, "openDatabase");
    if (desc && desc.get) {
      const origGet = desc.get;
      Object.defineProperty(window, "openDatabase", {
        ...desc,
        get() {
          record("Storage", "window.openDatabase", "existence check");
          return origGet.call(this);
        },
      });
    }
  }

  // ── 39. sessionStorage probe ──────────────────────────────────────────
  {
    const desc = Object.getOwnPropertyDescriptor(window, "sessionStorage");
    if (desc && desc.get) {
      const origGet = desc.get;
      Object.defineProperty(window, "sessionStorage", {
        ...desc,
        get() {
          record("Storage", "window.sessionStorage", "access");
          return origGet.call(this);
        },
      });
    }
  }
}
