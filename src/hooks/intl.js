// hooks/intl.js — Timezone, Intl locale fingerprinting, locale-dependent formatting
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 10. Date/Timezone Fingerprinting ──────────────────────────────────
  hookMethod(Date.prototype, "getTimezoneOffset", "Timezone", "getTimezoneOffset");
  if (typeof Intl !== "undefined" && Intl.DateTimeFormat) {
    hookMethod(Intl.DateTimeFormat.prototype, "resolvedOptions", "Timezone", "Intl.DateTimeFormat.resolvedOptions");
  }

  // ── 41. Intl locale fingerprinting ────────────────────────────────────
  // Intl APIs reveal the user's language, region, calendar, numbering
  // system, and formatting preferences — high-entropy fingerprint data.
  if (typeof Intl !== "undefined") {
    // resolvedOptions() on all Intl formatters — reveals locale, calendar,
    // numbering system, timezone, and formatting preferences
    if (Intl.NumberFormat) {
      hookMethod(Intl.NumberFormat.prototype, "resolvedOptions", "Intl", "Intl.NumberFormat.resolvedOptions");
      // format is a getter returning a bound function — hook the getter
      hookGetter(Intl.NumberFormat.prototype, "format", "Intl", "Intl.NumberFormat.format");
    }
    if (Intl.Collator) {
      hookMethod(Intl.Collator.prototype, "resolvedOptions", "Intl", "Intl.Collator.resolvedOptions");
      // compare is a getter returning a bound function — hook the getter
      hookGetter(Intl.Collator.prototype, "compare", "Intl", "Intl.Collator.compare");
    }
    for (const cls of ["ListFormat", "PluralRules", "RelativeTimeFormat", "Segmenter"]) {
      if (Intl[cls] && Intl[cls].prototype.resolvedOptions) {
        hookMethod(Intl[cls].prototype, "resolvedOptions", "Intl", "Intl." + cls + ".resolvedOptions");
      }
    }

    // Intl.DisplayNames — reveals how the browser localizes
    // language/region/script/currency names (locale-specific output)
    if (Intl.DisplayNames) {
      hookMethod(Intl.DisplayNames.prototype, "of", "Intl", "Intl.DisplayNames.of");
      hookMethod(Intl.DisplayNames.prototype, "resolvedOptions", "Intl", "Intl.DisplayNames.resolvedOptions");
    }

    // Intl.Locale — direct locale inspection
    if (Intl.Locale) {
      for (const prop of ["language", "region", "script", "calendar",
        "numberingSystem", "hourCycle", "baseName"]) {
        hookGetter(Intl.Locale.prototype, prop, "Intl", "Intl.Locale." + prop);
      }
    }

    // Intl.supportedValuesOf — enumerates all supported calendars,
    // numbering systems, timezones, etc. for the locale
    if (typeof Intl.supportedValuesOf === "function") {
      const origSVO = Intl.supportedValuesOf;
      Intl.supportedValuesOf = function (key) {
        record("Intl", "Intl.supportedValuesOf", key || "");
        return origSVO.call(this, key);
      };
    }
  }

  // ── 41b. Locale-dependent formatting methods ──────────────────────────
  // toLocaleString/toLocaleDateString/toLocaleTimeString produce
  // locale-specific output that reveals language and region settings.
  {
    const localeMethods = [
      [Date.prototype, "toLocaleString", "Date.toLocaleString"],
      [Date.prototype, "toLocaleDateString", "Date.toLocaleDateString"],
      [Date.prototype, "toLocaleTimeString", "Date.toLocaleTimeString"],
      [Number.prototype, "toLocaleString", "Number.toLocaleString"],
    ];
    for (const [proto, method, label] of localeMethods) {
      hookMethodHot(proto, method, "Intl", label);
    }
    // Array.toLocaleString calls element toLocaleString — fire-once
    hookMethodHot(Array.prototype, "toLocaleString", "Intl", "Array.toLocaleString");
  }
}
