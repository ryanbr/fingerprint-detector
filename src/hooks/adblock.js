// hooks/adblock.js — DOM Blockers (ad blocker fingerprinting via bait elements)
export function register({ hookMethod, hookMethodHot, hookGetter, record, recordHot, captureStack, extractSource, queueEvent }) {
  // ── 33. DOM Blockers (ad blocker fingerprinting) ───────────────────────
  // Detects the FingerprintJS-style pattern: rapid creation of many hidden
  // bait elements followed by offsetParent checks to determine which ad
  // blocker filter lists are active.
  //
  // Detection strategy:
  // 1. Track offsetParent reads in a sliding time window
  // 2. If many reads happen in a short burst (>15 in 200ms), it's a probe
  // 3. Also match known FingerprintJS bait selectors by ID/class
  // 4. Track element creation + immediate removal (create-check-remove cycle)
  {
    // Known bait element IDs used by FingerprintJS across 41 filter lists
    const KNOWN_BAIT_IDS = new Set([
      "ad_300X250", "Ad-Content", "bannerfloat22", "campaign-banner",
      "ad_banner", "adbanner", "adbox", "adsbox", "ad-slot",
      "adblock-honeypot", "ad_blocker", "Iklan-Melayang",
      "Kolom-Iklan-728", "SidebarIklan-wrapper", "Box-Banner-ads",
      "mobileCatfish", "pavePub", "kauli_yad_1", "mgid_iframe1",
      "ad_inview_area", "barraPublicidade", "Publicidade",
      "publiEspecial", "queTooltip", "backkapat", "reklami",
      "onlajny-stickers", "reklamni-box", "advertentie",
      "vipAdmarktBannerBlock", "SSpotIMPopSlider", "werbungsky",
      "reklame-rechts-mitte", "ceneo-placeholder-ceneo-12",
      "cemp_doboz", "hirdetesek_box", "cookieconsentdiv",
      "qoo-counter", "top100counter", "pgeldiz", "livereAdWrapper",
      "navbar_notice_50", "divAgahi",
    ]);

    const KNOWN_BAIT_CLASSES = new Set([
      "sponsored-text-link", "trafficjunky-ad", "textad_headline",
      "yb-floorad", "widget_po_ads_widget", "BetterJsPopOverlay",
      "quangcao", "close-ads", "mainostila", "sponsorit", "ylamainos",
      "reklama-megaboard", "sklik", "adstekst", "reklamos_tarpas",
      "reklamos_nuorodos", "box_adv_annunci", "cnt-publi",
      "reclama", "geminiLB1Ad", "right-and-left-sponsers",
      "Zi_ad_a_H", "frontpageAdvM", "cfa_popup",
      "ezmob-footer", "cc-CookieWarning", "aw-cookie-banner",
      "sygnal24-gdpr-modal-wrap", "adblocker-root", "wp_adblock_detect",
      "header-blocked-ad", "hs-sosyal", "as-oil",
      "navigate-to-top", "newsletter_holder",
      "util-bar-module-firefly-visible", "BlockNag__Card",
      "article-sharer", "community__social-desc",
      "ctpl-fullbanner", "zergnet-recommend",
      "ads300s", "bumq", "img-kosana",
      "optimonk-iframe-container", "yandex-rtb-block",
      "lapni-pop-over", "sponsorlinkgruen",
      "ad-desktop-rectangle", "mobile_adhesion", "widgetadv", "ads_ban",
      "revenue_unit_item",
    ]);

    // Burst detection: count offsetParent reads in a time window
    const BURST_WINDOW = 200; // ms
    const BURST_THRESHOLD = 15; // reads within window = fingerprinting
    let burstCount = 0;
    let burstWindowStart = 0;
    let burstDetected = false;
    let burstReported = false;

    // Track element creation for create-check-remove pattern
    let recentCreations = 0;
    let recentRemovals = 0;
    let creationWindow = 0;
    const CREATION_BURST_THRESHOLD = 20;
    const CREATION_WINDOW_MS = 500;

    // Hook offsetParent
    const origOffsetParent = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "offsetParent");
    if (origOffsetParent && origOffsetParent.get) {
      const opGet = origOffsetParent.get;

      Object.defineProperty(HTMLElement.prototype, "offsetParent", {
        configurable: true, enumerable: true,
        get() {
          const val = opGet.call(this);
          const now = Date.now();

          // 1. Burst detection — many offsetParent reads in a short window
          if (!burstReported) {
            if (now - burstWindowStart > BURST_WINDOW) {
              burstCount = 0;
              burstWindowStart = now;
            }
            burstCount++;
            if (burstCount >= BURST_THRESHOLD && !burstDetected) {
              burstDetected = true;
              record("AdBlockDetect", "offsetParent burst",
                burstCount + " reads in " + BURST_WINDOW + "ms (filter list fingerprinting pattern)");
            }
          }

          // 2. Known bait ID match
          if (this.id && KNOWN_BAIT_IDS.has(this.id)) {
            record("AdBlockDetect", "known bait element",
              "id=\"" + this.id + "\" (FingerprintJS filter list probe)");
          }

          // 3. Known bait class match — avoid split() on every call
          if (this.className && typeof this.className === "string") {
            // Fast path: single-class elements (most bait elements)
            if (this.className.indexOf(" ") === -1) {
              if (KNOWN_BAIT_CLASSES.has(this.className)) {
                record("AdBlockDetect", "known bait element",
                  "class=\"" + this.className + "\" (FingerprintJS filter list probe)");
              }
            } else {
              const classes = this.className.split(" ");
              for (let i = 0; i < classes.length; i++) {
                if (KNOWN_BAIT_CLASSES.has(classes[i])) {
                  record("AdBlockDetect", "known bait element",
                    "class=\"" + classes[i] + "\" (FingerprintJS filter list probe)");
                  break;
                }
              }
            }
          }

          return val;
        },
      });
    }

    // Track create-check-remove cycles via MutationObserver instead of
    // wrapping Element.prototype.appendChild / Node.prototype.removeChild.
    // The wraps put us in the call stack of every DOM mutation on the
    // page, which caused Chrome console warnings from unrelated page
    // code (insecure iframe sandbox attributes on engadget.com, etc.)
    // to be attributed to dist/inject.js. MutationObserver callbacks
    // run asynchronously after the native mutation completes, so our
    // frame isn't on the stack when Chrome emits those warnings.
    if (typeof MutationObserver !== "undefined") {
      const observer = new MutationObserver((mutations) => {
        if (burstReported) return;
        const now = Date.now();
        if (now - creationWindow > CREATION_WINDOW_MS) {
          recentCreations = 0;
          recentRemovals = 0;
          creationWindow = now;
        }
        for (let i = 0; i < mutations.length; i++) {
          recentCreations += mutations[i].addedNodes.length;
          recentRemovals += mutations[i].removedNodes.length;
        }
        if (recentCreations >= CREATION_BURST_THRESHOLD &&
            recentRemovals >= CREATION_BURST_THRESHOLD &&
            !burstReported) {
          burstReported = true;
          record("AdBlockDetect", "create-check-remove cycle",
            recentCreations + " elements created and " + recentRemovals +
            " removed in " + CREATION_WINDOW_MS + "ms (ad blocker fingerprinting)");
          observer.disconnect();
        }
      });

      // body may not exist at document_start — defer observation until it does
      function startObserving() {
        if (document.body) {
          observer.observe(document.body, { childList: true, subtree: false });
        }
      }
      if (document.body) {
        startObserving();
      } else {
        document.addEventListener("DOMContentLoaded", startObserving, { once: true });
      }
    }
  }
}
