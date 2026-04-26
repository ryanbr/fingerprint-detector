// Assembles a temporary extension directory for web-ext lint.
// web-ext is a Firefox tool, so we patch the manifest to match our
// Firefox build (gecko ID, background.scripts instead of service_worker).

import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const OUT = path.join(ROOT, "build-tmp");

function rmrf(p) {
  if (fs.existsSync(p)) fs.rmSync(p, { recursive: true, force: true });
}

function copy(src, dst) {
  fs.mkdirSync(path.dirname(dst), { recursive: true });
  fs.copyFileSync(src, dst);
}

function copyDir(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name);
    const d = path.join(dst, entry.name);
    if (entry.isDirectory()) copyDir(s, d);
    else fs.copyFileSync(s, d);
  }
}

// Clean + recreate
rmrf(OUT);
fs.mkdirSync(OUT, { recursive: true });

// Patch manifest for Firefox (same transform as the release workflow)
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "manifest.json"), "utf8"));
manifest.browser_specific_settings = {
  gecko: {
    id: "fingerprint-detector@ryanbr",
    strict_min_version: "128.0",
    data_collection_permissions: { required: ["none"] },
  },
};
// Keep both service_worker (Chrome) and scripts (Firefox fallback) — recent
// web-ext / AMO rules require service_worker to be paired with scripts.
if (manifest.background && manifest.background.service_worker && !manifest.background.scripts) {
  manifest.background.scripts = [manifest.background.service_worker];
}
fs.writeFileSync(path.join(OUT, "manifest.json"), JSON.stringify(manifest, null, 2));
copy(path.join(ROOT, "LICENSE"), path.join(OUT, "LICENSE"));

// Icons
copyDir(path.join(ROOT, "icons"), path.join(OUT, "icons"));

// Bundled inject.js (must be built already)
const distInject = path.join(ROOT, "dist", "inject.js");
if (!fs.existsSync(distInject)) {
  console.error("dist/inject.js not found — run `npm run build` first");
  process.exit(1);
}
copy(distInject, path.join(OUT, "dist", "inject.js"));

// Non-bundled src files
const srcFiles = [
  "popup.html", "popup.js",
  "bridge.js", "background.js",
  "compare.html", "compare.js",
];
for (const f of srcFiles) {
  copy(path.join(ROOT, "src", f), path.join(OUT, "src", f));
}

console.log("Assembled extension at " + OUT);
