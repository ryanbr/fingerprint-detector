// Firefox content script loader — injects inject.js into the page context.
// Firefox doesn't support "world": "MAIN" in manifest content_scripts,
// so we inject a <script> tag pointing to the extension's inject.js file.
// This achieves the same result: inject.js runs in the page's JS context.

const api = typeof browser !== "undefined" ? browser : chrome;
const script = document.createElement("script");
script.src = api.runtime.getURL("src/inject.js");
script.onload = function () {
  script.remove();
};
(document.head || document.documentElement).appendChild(script);
