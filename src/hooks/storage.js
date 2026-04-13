// hooks/storage.js — Storage, IndexedDB, Storage Quota, openDatabase, sessionStorage, Cache API
export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 11. Storage Fingerprinting ────────────────────────────────────────
  hookGetter(Navigator.prototype, "cookieEnabled", "Storage", "navigator.cookieEnabled");
  if (typeof Storage !== "undefined") {
    hookMethodHot(Storage.prototype, "setItem", "Storage", "localStorage.setItem");
    hookMethodHot(Storage.prototype, "getItem", "Storage", "localStorage.getItem");
    hookMethodHot(Storage.prototype, "removeItem", "Storage", "localStorage.removeItem");
    hookMethodHot(Storage.prototype, "clear", "Storage", "localStorage.clear");
    hookMethodHot(Storage.prototype, "key", "Storage", "localStorage.key");
    hookGetter(Storage.prototype, "length", "Storage", "localStorage.length");
  }

  // document.cookie — reading/writing cookies for tracking
  {
    const cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
    if (cookieDesc) {
      if (cookieDesc.get) {
        const origGet = cookieDesc.get;
        Object.defineProperty(Document.prototype, "cookie", {
          ...cookieDesc,
          get() {
            recordHot("Storage", "document.cookie", "get");
            return origGet.call(this);
          },
          set: cookieDesc.set,
        });
      }
    }
  }

  // BroadcastChannel — cross-tab communication, can be used to coordinate
  // fingerprinting across tabs or detect multiple open tabs
  if (typeof BroadcastChannel !== "undefined") {
    const OrigBC = BroadcastChannel;
    window.BroadcastChannel = function (name) {
      recordHot("Storage", "new BroadcastChannel", name || "");
      return new OrigBC(name);
    };
    window.BroadcastChannel.prototype = OrigBC.prototype;
  }

  // ── IndexedDB fingerprinting ──────────────────────────────────────────
  // indexedDB.databases() enumerates all DB names — reveals browsing history
  // and installed PWAs. The open/transaction/read pipeline is used to probe
  // stored data and test storage capabilities.
  if (typeof window.indexedDB !== "undefined") {
    // Database lifecycle
    hookMethod(IDBFactory.prototype, "open", "Storage", "indexedDB.open");
    hookMethod(IDBFactory.prototype, "deleteDatabase", "Storage", "indexedDB.deleteDatabase");

    // databases() — enumerates all DB names (high-value fingerprint)
    if (IDBFactory.prototype.databases) {
      hookMethod(IDBFactory.prototype, "databases", "Storage", "indexedDB.databases");
    }

    // Database operations
    if (typeof IDBDatabase !== "undefined") {
      hookMethodHot(IDBDatabase.prototype, "createObjectStore", "Storage", "IDBDatabase.createObjectStore");
      hookMethodHot(IDBDatabase.prototype, "transaction", "Storage", "IDBDatabase.transaction");
      hookMethodHot(IDBDatabase.prototype, "close", "Storage", "IDBDatabase.close");
      hookGetter(IDBDatabase.prototype, "objectStoreNames", "Storage", "IDBDatabase.objectStoreNames");
    }

    // Object store data reads — probing stored content
    if (typeof IDBObjectStore !== "undefined") {
      hookMethodHot(IDBObjectStore.prototype, "get", "Storage", "IDBObjectStore.get");
      hookMethodHot(IDBObjectStore.prototype, "getAll", "Storage", "IDBObjectStore.getAll");
      hookMethodHot(IDBObjectStore.prototype, "count", "Storage", "IDBObjectStore.count");
      hookMethodHot(IDBObjectStore.prototype, "getAllKeys", "Storage", "IDBObjectStore.getAllKeys");
    }
  }

  // ── 29d. Storage Quota (disk size leak) ────────────────────────────────
  if (typeof StorageManager !== "undefined") {
    // Access-based: all three return promises and are commonly
    // destructured; keeps the extension out of "Illegal invocation"
    // stacks attributed to dist/inject.js.
    hookMethodViaAccess(StorageManager.prototype, "estimate", "Storage", "navigator.storage.estimate");
    hookMethodViaAccess(StorageManager.prototype, "persist", "Storage", "navigator.storage.persist");
    hookMethodViaAccess(StorageManager.prototype, "persisted", "Storage", "navigator.storage.persisted");
  }

  // ── 38. openDatabase (Web SQL) ────────────────────────────────────────
  if (typeof window.openDatabase === "function") {
    const origOpenDB = window.openDatabase;
    window.openDatabase = function (name, ver, desc, size) {
      recordHot("Storage", "openDatabase", "");
      return origOpenDB.call(this, name, ver, desc, size);
    };
  }
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
