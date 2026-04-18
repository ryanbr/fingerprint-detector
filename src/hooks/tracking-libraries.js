// hooks/tracking-libraries.js — Unified tracking library detection.
//
// Single data-driven detector that replaces three previously separate
// modules (fingerprint-library.js, matomo.js, akamai-bot-manager.js).
//
// Each library is described as a LIBRARIES registry entry. A shared
// scan pipeline checks every registered library against all signal
// types in one pass.
//
// Benefits over the three-module approach:
// - 1 PerformanceObserver (was 3)
// - 1 MutationObserver (was 3)
// - 1 set of scheduled scans (was 3)
// - 1 `Object.keys(window)` iteration per scan (was 3)
// - 1 localStorage + sessionStorage + cookie iteration per scan (was 3)
// - Adding a new library = one entry in the registry (no new
//   observers, timers, or iterations)
//
// To add a new tracker detector: append an entry to LIBRARIES with
// the name, category, and whichever signal arrays apply. Pattern
// checkers below automatically pick it up.

export function register({ hookMethod, hookMethodHot, hookMethodViaAccess, hookGetter, record, recordHot, captureStack, extractSource, queueEvent, fnWrapperMap }) {
  // ── Library registry ─────────────────────────────────────────────────
  const LIBRARIES = [
    {
      name: "FingerprintJS",
      category: "FingerprintJSDetect",
      // Well-known explicit global names
      globals: [
        "FingerprintJS", "FingerprintJSPro",
        "fpjsAgent", "fpPromise",
        "__fpjs", "fpjs",
        "__fpjs_p_l_b", "__fpjs_d_c", "__fpjs_d_m",  // Pro loader internals
        "FPJS_AGENT", "FPJS",
      ],
      // Any window own-key matching one of these prefixes → match
      globalPrefixes: ["__fpjs", "_fpjs_"],
      // Cookie / storage key patterns
      keyPatterns: [
        /^__fpjs/i, /^_fpjs/i,
        /^_vid$/i, /^_sid$/i, /^_fp_vid$/i, /^fpjs_/i,
      ],
      // <script src> URL patterns (also used by PerformanceObserver)
      scriptSrcPatterns: [
        // FingerprintJS Pro loader: apiKey + loaderVersion combo
        /[?&]apiKey=[^&]+[\s\S]*[?&]loaderVersion=/i,
        /[?&]loaderVersion=[^&]+[\s\S]*[?&]apiKey=/i,
        // Known public CDN hosts (only fires when not behind a
        // custom subdomain; the query-string patterns above catch
        // the custom-subdomain case)
        /\bfpjscdn\.(?:net|sh|com|io)\b/i,
        /\bfpcdn\.io\b/i,
        /\bopenfpcdn\.io\b/i,
        /\bapi\.fpjs\.(?:io|sh)\b/i,
        /\bm\.instant\.one\b/i,
        /\/fingerprintjs[^/?]*\.(?:min\.)?js\b/i,
        /\/fp(?:\.v\d+)?\.min\.js\b/i,
      ],
      // <script data-*> attributes
      domAttributes: ["data-fpjs-public-key", "data-fpjs-api-key"],
      // Classify script origin 1p vs 3p (only FingerprintJS uses
      // custom-subdomain obfuscation routinely)
      classifyOrigin: true,
    },
    {
      name: "Matomo",
      category: "MatomoDetect",
      globals: ["Matomo", "Piwik", "_paq", "_mtm", "Piwik_Overlay"],
      globalPrefixes: ["_pk_"],
      keyPatterns: [
        /^_pk_id/i, /^_pk_ses/i, /^_pk_ref/i, /^_pk_cvar/i,
        /^_pk_hsr/i, /^_pk_testcookie/i, /^_pk_/i,
        /^mtm_consent/i, /^mtm_cookie/i, /^mtm_/i,
        /^piwik_/i,
      ],
      scriptSrcPatterns: [
        /\/matomo(?:\.v\d+)?\.(?:min\.)?js\b/i,
        /\/piwik(?:\.v\d+)?\.(?:min\.)?js\b/i,
        /\/mtm\.(?:min\.)?js\b/i,
        /\/container_[a-zA-Z0-9]+\.js\b/i,   // Tag Manager containers
      ],
      domAttributes: [],
      classifyOrigin: false,
      // Matomo-specific anomaly: Date.prototype.getTimeAlias
      anomaly: {
        key: "Date.prototype.getTimeAlias",
        label: "Date.prototype.getTimeAlias",
        detail: "Matomo-specific alias property",
        check: () => {
          try {
            return typeof Date.prototype.getTimeAlias === "function";
          } catch { return false; }
        },
      },
    },
    {
      name: "Akamai Bot Manager",
      category: "AkamaiBotManagerDetect",
      globals: ["bmak", "_abck", "bm_sz", "ak_bmsc"],
      globalPrefixes: ["bmak", "_bm_"],
      keyPatterns: [
        /^_abck$/, /^bm_sz$/, /^bm_s$/, /^bm_sv$/, /^bm_mi$/,
        /^bm_so$/, /^ak_bmsc$/, /^sbsd$/, /^sbsd_o$/,
      ],
      // ABM sensor hash is randomised per customer, but the path
      // shape /akam/<version>/<hex> is stable across all deployments
      // (v10-v13+ seen in the wild). Matching the path catches
      // first-party proxy deployments like <site>.com/akam/13/<hash>.
      scriptSrcPatterns: [
        /\/akam\/\d+\/[0-9a-f]{6,}\b/i,
      ],
      domAttributes: [],
      classifyOrigin: false,
    },
    {
      name: "Cloudflare Bot Management",
      category: "CloudflareBotManagementDetect",
      globals: ["turnstile"],   // Turnstile CAPTCHA widget
      globalPrefixes: ["_cf_chl_"],  // Cloudflare challenge runtime options
      keyPatterns: [
        /^__cf_bm$/, /^cf_clearance$/, /^_cfuvid$/, /^_cf_bm$/,
      ],
      scriptSrcPatterns: [
        /\bchallenges\.cloudflare\.com\b/i,
        /\/cdn-cgi\/challenge-platform\//i,
        /\/cdn-cgi\/bm\//i,
      ],
      domAttributes: [],
      classifyOrigin: false,
    },
    {
      name: "DataDome",
      category: "DataDomeDetect",
      // Note: the globals DD_RUM and DD_LOGS are DataDog (observability
      // product), NOT DataDome — deliberately excluded to prevent false
      // positives. DataDome client-side presence is primarily via the
      // cookie + script URL; it doesn't expose obvious globals.
      globals: ["datadome"],
      globalPrefixes: [],
      keyPatterns: [
        /^datadome$/i, /^dd_cookie_test/i, /^dd_s$/i,
      ],
      scriptSrcPatterns: [
        /\bjs\.datadome\.co\b/i,
        /\bapi\.datadome\.co\b/i,
        /\bcaptcha-delivery\.com\b/i,
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "PerimeterX / HUMAN",
      category: "PerimeterXDetect",
      globals: [
        "_pxAppId", "_pxAction", "_pxSID",
        "_pxParam1", "_pxjsClientSrc",
        "_pxttld", "_pxUuid",
      ],
      globalPrefixes: ["_px"],
      // Both underscore-prefixed and non-underscore cookie families.
      // The _px* family is universal; the non-underscore ones
      // (pxjsc/pxhc/pxcts/pxsid/pxac) are set by newer builds and
      // the _pxc cookie is the main tracking cookie observed on
      // apartmenttherapy.com and similar first-party proxy sites.
      keyPatterns: [
        /^_px/i,           // catches _px, _px2, _px3, _pxc, _pxhd, _pxvid, _pxff_*, _pxttld, _pxUuid, etc.
        /^pxjsc$/i, /^pxhc$/i, /^pxcts$/i, /^pxsid$/i, /^pxac$/i,
      ],
      scriptSrcPatterns: [
        // Direct / third-party CDN deployments
        /\bclient\.perimeterx\.net\b/i,
        /\bclient\.px-cdn\.net\b/i,
        /\bclient\.px-cloud\.net\b/i,
        /\bcollector-\w+\.px-cloud\.net\b/i,
        /\bpxl\.humansecurity\.com\b/i,
        /\bclient-response\.px-client\.net\b/i,
        // First-party proxy path pattern — the <appId>/init.js
        // structure is distinctive to PerimeterX. appId is 6-12
        // alphanumeric chars. Confirmed on apartmenttherapy.com
        // (/jAYekY18/init.js) and similar customer-domain setups.
        /\/[a-zA-Z0-9]{6,12}\/init\.js\b/,
        /\/[a-zA-Z0-9]{6,12}\/main\.min\.js\b/,
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Imperva / Incapsula",
      category: "ImpervaDetect",
      globals: [],  // Imperva operates mostly at edge, limited client globals
      globalPrefixes: ["__imperva_"],
      // Only high-confidence cookie names. ___utmvc was removed —
      // couldn't confirm it's Imperva-specific, may be other trackers.
      keyPatterns: [
        /^incap_ses/i, /^visid_incap/i, /^nlbi_/i,
      ],
      scriptSrcPatterns: [
        /\bcdn\.incapsula\.com\b/i,
        /\bincapsula\.com\/.+\.js\b/i,
        /\bimperva\.com\/.+\.js\b/i,
      ],
      domAttributes: [],
      classifyOrigin: false,
    },
    {
      name: "Hotjar",
      category: "HotjarDetect",
      // Session-replay + heatmap product. Records user interactions,
      // mouse movements, and scrolls. Rebranded ContentSquare
      // subsidiary since 2023.
      // Signatures confirmed from static.hotjar.com/c/hotjar-*.js loader.
      globals: [
        "hj",                      // main queue fn (hj('event', ...))
        "hjSiteSettings",          // config object with site_id
        "hjBootstrap",             // loader fn
        "hjBootstrapCalled",       // array of booted instances
        "hjLazyModules",           // module registry (SURVEY_V2, HEATMAP_RETAKER, etc.)
      ],
      globalPrefixes: ["_hj"],     // catches _hj*, _hjSettings, _hjUserAttributesHash, etc.
      keyPatterns: [
        /^_hjSession/i,            // _hjSession_*, _hjSessionUser_*
        /^_hjIncluded/i,           // _hjIncludedInSessionSample_*
        /^_hjAbsolute/i,           // _hjAbsoluteSessionInProgress
        /^_hjFirstSeen$/i,
        /^_hjMinimizedPolls/i,
        /^_hjShown/i,              // _hjShownFeedback*
        /^_hjTLDTest$/i,
        /^hj-uut$/i,               // sessionStorage UUID key
        /^_hj/i,                   // generic fallback for any _hj* key
      ],
      scriptSrcPatterns: [
        /\bstatic\.hotjar\.com\b/i,
        /\bscript\.hotjar\.com\b/i,
        /\bmetrics\.hotjar\.io\b/i,
        /\binsights\.hotjar\.com\b/i,
        /\bvoc\.hotjar\.com\b/i,
        /\bvc\.hotjar\.io\b/i,
        /\bhotjarians\.net\b/i,           // integration env
        /\/hotjar-[0-9a-f]+\.js\b/i,       // static.hotjar.com/c/hotjar-3736802.js
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Piano / Tinypass",
      category: "PianoDetect",
      // Piano (formerly Tinypass) is a paywall / subscription platform.
      // Used by news and magazine publishers. Their script does user
      // identification and page-view tracking for paywall enforcement.
      globals: [
        "tp",                 // primary Piano SDK global
        "pn",                 // internal namespace (confirmed on cdn-au.piano.io)
        "pdl",                // Piano Data Layer
        "tinypass",           // legacy name
        "__tpVersion",        // version string
        "pnFullTPVersion",
        "pnHasPolyfilled",
        "pnInitPerformance",
      ],
      globalPrefixes: ["__tp_", "pn_", "tp__"],
      keyPatterns: [
        // Consent / tracking cookies
        /^_pc_/i,
        /^_pcid$/i, /^_pctx$/i, /^_pcus$/i, /^_pprv$/i,
        // Telemetry cookies (short prefixes are distinctive)
        /^__tbc$/i, /^__tac$/i, /^__tae$/i,
        /^__pls$/i, /^__pnahc$/i, /^__pat$/i,
        // localStorage keys
        /^__tp/i,            // __tp*
        /^tp__/i,            // tp__*
        /^pianoId$/i,
        /^_ls_ttl$/i,
      ],
      scriptSrcPatterns: [
        /\bcdn(?:-\w+)?\.piano\.io\b/i,   // cdn.piano.io, cdn-au.piano.io, cdn-eu, cdn-na
        /\btinypass\.com\b/i,              // legacy domain
        /\bexperience\.piano\.io\b/i,
        /\/tinypass(?:\.min)?\.js\b/i,    // script filename
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Kasada",
      category: "KasadaDetect",
      // KPSDK global is the primary reliable signal. x-kpsdk-* are
      // primarily HTTP request headers (not localStorage/cookies) so
      // storage-based detection is inconsistent; keeping the patterns
      // for deployments that do cache the tokens, but the global +
      // script-URL checks are the reliable path.
      globals: ["KPSDK"],
      globalPrefixes: ["KPSDK_"],
      keyPatterns: [
        /^x-kpsdk-/i, /^KPSDK-/i,
      ],
      scriptSrcPatterns: [
        /\bips\.js\.kasada\.io\b/i,
        /\bkasada\.io\b/i,
      ],
      domAttributes: [],
      classifyOrigin: false,
    },
    {
      name: "Meta Pixel",
      category: "MetaPixelDetect",
      // Meta / Facebook Pixel — first-party ad attribution and
      // conversion tracking. Thin on fingerprinting (screen dims +
      // userAgentData.getHighEntropyValues only); main signal is the
      // _fbp / _fbc first-party cookies plus fbclid URL param.
      // Signatures confirmed from connect.facebook.net/en_US/fbevents.js.
      globals: [
        "fbq",                   // primary pixel fn
        "_fbq",                  // internal alias / queue
        "__fbeventsModules",     // plugin/module registry
      ],
      globalPrefixes: [],
      keyPatterns: [
        /^_fbp$/i,               // browser ID cookie
        /^_fbc$/i,               // click ID cookie (derived from fbclid)
        /^_fbleid$/i,            // last event id cookie
        /^fbclid$/i,              // URL param forwarded into _fbc
      ],
      scriptSrcPatterns: [
        /\bconnect\.facebook\.net\b/i,     // main pixel CDN
        /\/fbevents\.js\b/i,                 // pixel script filename
        /\bgw\.conversionsapigateway\.com\b/i, // Conversions API Gateway
        /\bfbsbx\.com\b/i,                   // fb sandbox CDN
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Bing UET",
      category: "BingUETDetect",
      // Microsoft Bing Ads UET (Universal Event Tracking) — conversion
      // tracking and audience analytics pixel. First-party cookies
      // (_uetsid / _uetvid / _uetmsclkid) plus a randomised
      // window.ueto_XXXXXXXXXX global. Signatures confirmed from
      // bat.bing.com/bat.js.
      globals: [
        "UET",                   // constructor
        "UET_init",              // init fn
        "UET_push",              // push fn
        "uetq",                  // event queue
      ],
      globalPrefixes: [
        "_uetq",                 // queue aliases
        "ueto_",                 // randomised per-tag global (ueto_ + 10 chars)
      ],
      keyPatterns: [
        /^_uetsid$/i,            // session id (24h)
        /^_uetvid$/i,            // visitor id (~390d)
        /^_uetmsclkid$/i,        // Microsoft Click ID (from msclkid URL param)
        /^_uetuid$/i,            // user id
        /^_uetdbg$/i,            // debug cookie
        /^_uetmsdns$/i,          // MS DNS indicator
        /^_uet[a-z]+_exp$/i,     // localStorage expiry fallback (_uetsid_exp etc.)
      ],
      scriptSrcPatterns: [
        /\bbat\.bing\.com\b/i,   // primary loader + beacon host
        /\bbat\.bing\.net\b/i,   // no-cookie consent host
        /\/bat\.js\b/i,            // script filename
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Parse.ly",
      category: "ParselyDetect",
      // Parse.ly (owned by Automattic) — content analytics platform
      // tracking pageviews, engagement time, scroll depth, video
      // consumption and conversions. First-party cookies plus
      // pStore-* localStorage mirrors. Signatures confirmed from
      // cdn.parsely.com/keys/*/p.js.
      globals: [
        "PARSELY",               // primary object
        "_parselyIsTest",        // test-mode flag
      ],
      globalPrefixes: [],
      keyPatterns: [
        /^_parsely_visitor$/i,      // visitor id (~395d)
        /^_parsely_session$/i,      // session (30min)
        /^_parsely_tpa_blocked$/i,  // third-party analytics blocked flag
        /^_parsely_slot_click$/i,   // slot click tracking
        /^parsely_uuid$/i,          // legacy visitor id
        /^pStore-_?parsely/i,       // localStorage mirrors (pStore-_parsely_visitor etc.)
      ],
      scriptSrcPatterns: [
        /\bcdn\.parsely\.com\b/i,   // primary loader CDN
        /\bp1\.parsely\.com\b/i,    // beacon host
        /\/keys\/[^/]+\/p\.js\b/i,  // script path pattern: /keys/<site>/p.js
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "New Relic Browser",
      category: "NewRelicBrowserDetect",
      // New Relic Browser Agent — APM/observability script that
      // wraps XHR, fetch, Promise, timers, MutationObserver and
      // history.pushState and ships session-scoped telemetry (errors,
      // performance metrics, user interactions) to bam.nr-data.net.
      // Not an ad tracker, but worth flagging for transparency: the
      // agent instruments the page extensively. Many sites self-host
      // the loader (hence the /newrelic.js path pattern).
      globals: [
        "NREUM",                 // primary agent namespace
        "newrelic",              // public API alias
      ],
      globalPrefixes: [],
      keyPatterns: [
        /^NREUM_SESSION_ID$/,    // 16-char hex session id in sessionStorage
      ],
      scriptSrcPatterns: [
        /\bjs-agent\.newrelic\.com\b/i,   // official CDN
        /\bbam(?:-cell)?\.nr-data\.net\b/i, // beacon (sometimes fetched)
        /\bnr-data\.net\b/i,                 // fallback host match
        /\/newrelic\.js\b/i,                 // common self-hosted filename
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Blockthrough Ad Recovery",
      category: "BlockthroughDetect",
      // Blockthrough Ad Recovery — anti-adblock / ad-recovery loader.
      // Detects blockers via bait elements + image pixels + CSP
      // violation events, probes network-level filters via DNS
      // lookups to dns-finder.com, harvests TCF consent data, and
      // re-serves ads from cdn.btmessage.com/script/rlink.js when
      // conditions allow. High risk — actively circumvents user
      // intent (adblock). Signatures confirmed from btloader.com/tag.
      globals: [
        "__bt",                       // public API
        "__bt_edge_data",             // X-Acceptable-Ads + DNT signals from edge worker
        "__bt_tag_d",                 // tag metadata (orgID, siteInfo, version)
        "__bt_rlink_loaded_from_tag", // rlink recovery flag
        "__bt_intrnl",                // internal state (traceID, tcData, aaDetection)
        "__bt_already_invoked",       // re-entry guard
      ],
      globalPrefixes: ["__bt_"],
      keyPatterns: [
        /^BT_traceID$/,
        /^BT_EXP_FLAGS$/,
        /^BT_SESSION_ACTIONS$/,
        /^BT_sid$/,
        /^BT_BUNDLE_VERSION_/,        // BT_BUNDLE_VERSION_<siteID>
        /^BT_DIGEST_VERSION_/,        // BT_DIGEST_VERSION_<siteID>
        /^BT_AA_DETECTION$/,
        /^btUserCountry/i,            // btUserCountry, btUserCountryExpiry, btUserIsFromRestrictedCountry
      ],
      scriptSrcPatterns: [
        /\bbtloader\.com\b/i,           // primary loader + trusted iframe
        /\bapi\.btloader\.com\b/i,      // API + beacon host
        /\bcdn\.btmessage\.com\b/i,     // rlink.js recovery CDN
        /\b(?:ab|wb)\.dns-finder\.com\b/i, // NLF (network-level filter) DNS probe
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Admiral",
      category: "AdmiralDetect",
      // Admiral (getadmiral.com) — anti-adblock surveillance platform.
      // Uses rotating disposable loader domains (pearpouch.com,
      // succeedscene.com, merequartz.com, html-load.com,
      // content-loader.com, error-report.com) to evade filter lists,
      // so detection relies primarily on stable globals / cookies /
      // storage keys rather than script URLs. High risk — detects
      // adblock + VPN + piracy tools and reports to publishers.
      globals: [
        "admiral",
        "4dm1r11545242527",             // hardcoded obfuscated magic global — distinctive enough on its own
      ],
      globalPrefixes: [],
      keyPatterns: [
        /^_awl$/,                        // Admiral cookie
        /^_admrla$/,                     // Admiral cookie
        /^_alvd$/,                       // Admiral cookie
        /^_admrlri$/,                    // obfuscated storage key
        /^_admlValRec$/,                 // localStorage record
        /^afsvisits$/,                   // sessionStorage visit history
      ],
      scriptSrcPatterns: [
        /\bgetadmiral\.com\b/i,          // official site + CDN
        /\bcdn\.admiral\.com\b/i,        // older CDN host
        // Rotating disposable loader hosts seen in the wild:
        /\bpearpouch\.com\b/i,
        /\bsucceedscene\.com\b/i,
        /\bmerequartz\.com\b/i,
        /\bhtml-load\.com\b/i,
        /\bcontent-loader\.com\b/i,
        /\berror-report\.com\b/i,
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Publift Fuse",
      category: "PubliftFuseDetect",
      // Publift Fuse — header-bidding / ad-stack orchestrator that
      // loads Prebid.js, Google Publisher Tag, Amazon UAM, Quantcast
      // CMP and 23 SSP bidders (AppNexus, Criteo, Rubicon, PubMatic,
      // Index Exchange, Trade Desk etc.) on behalf of publishers.
      // Fuse itself doesn't set cookies — the downstream SSPs do —
      // so detection relies on the fusetag global plus URL patterns.
      globals: [
        "fusetag",               // primary API (activateZone, addQueue, etc.)
      ],
      globalPrefixes: [],
      keyPatterns: [],
      scriptSrcPatterns: [
        /\bcdn\.fuseplatform\.net\b/i,   // primary loader CDN
        /\bfuseplatform\.net\b/i,         // fallback host
        /\bpublift\.com\b/i,              // company site / legacy
        /\/publift\/tags\//i,             // publisher tag path pattern
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Media.net",
      category: "MediaNetDetect",
      // Media.net Warp — Yahoo-owned ad network tag that bundles
      // Prebid.js + user-ID modules (UID2, RampID, Criteo, TDID,
      // Kargo etc.) + Index Exchange / other SSP adapters. Was the
      // original backing network for Bing contextual ads. Loader
      // served from warp.media.net/js/tags/clientag.js with bids
      // and creatives via contextual.media.net / adservetx.media.net.
      globals: [
        "mnjs",                  // Media.net duplicate-load guard (distinctive)
      ],
      globalPrefixes: [
        "_mN",                   // catches _mNHandle, _mNDetails etc. across legacy tags
      ],
      keyPatterns: [],
      scriptSrcPatterns: [
        /\bwarp\.media\.net\b/i,          // primary loader host
        /\bcontextual\.media\.net\b/i,    // ad backend
        /\bstatic\.media\.net\b/i,        // CDN
        /\badservetx\.media\.net\b/i,     // ad serving
        /\bmedia\.net\b/i,                // generic fallback (catches other media.net subhosts)
        /\/clientag\.js\b/i,              // distinctive tag filename
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Tealium iQ",
      category: "TealiumDetect",
      // Tealium iQ (utag.js) — enterprise tag management system,
      // competitor to Google Tag Manager and Adobe Launch. Itself
      // does minimal fingerprinting but orchestrates downstream
      // trackers (Adobe Analytics, GA4, Facebook Pixel, ClickTale,
      // OneTrust CMP etc.). Commonly deployed via customer CNAME
      // (tags.<publisher>.com) to evade adblockers — detection must
      // catch both the standard tiqcdn.com CDN and /utag/ path +
      // utag*.js filenames on arbitrary first-party hosts.
      globals: [
        "utag",                  // main Tealium object (loader, handler, sender, cfg)
        "utag_data",             // page data layer
        "utag_cfg_ovrd",         // config overrides
        "utag_condload",         // conditional load flag
        "utag_events",           // legacy event queue
      ],
      globalPrefixes: [],
      keyPatterns: [
        /^utag_main/i,           // utag_main, utag_main_v_id, utag_main__ss, utag_main__se, utag_main__sn, utag_main__pn, utag_main__st etc.
        /^utagdb$/i,             // debug-mode cookie
        /^tealium_va/i,          // localStorage visitor attributes
      ],
      scriptSrcPatterns: [
        /\btags\.tiqcdn\.com\b/i,  // standard Tealium CDN
        /\btiqcdn\.com\b/i,         // fallback host
        /\/utag\/[^/]+\/[^/]+\/[^/]+\/utag/i, // /utag/<account>/<profile>/<env>/utag*.js path pattern
        /\/utag(?:\.sync|\.loader)?\.js\b/i,   // utag.js / utag.sync.js / utag.loader.js filenames
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "WordPress.com Stats",
      category: "WPComStatsDetect",
      // WordPress.com Stats / Jetpack Stats — Automattic's analytics
      // service used on WordPress.com-hosted sites and any WordPress
      // site running the Jetpack plugin. Lightweight: navigator.userAgent
      // + performance paint timing + referrer + UTM params only.
      // Pageviews beacon via pixel.wp.com/g.gif GET requests.
      globals: [
        "_stq",                  // primary queue array (_stq.push([...]))
        "wpcom",                 // namespace (wpcom.stats)
      ],
      globalPrefixes: [],
      keyPatterns: [],             // script sets no cookies / storage of its own
      scriptSrcPatterns: [
        /\bstats\.wp\.com\b/i,     // loader host (script served as /e-<siteID>.js)
        /\bpixel\.wp\.com\b/i,      // beacon host (g.gif / c.gif / b.gif)
        /\/e-\d+\.js\b/i,            // site-numbered loader filename pattern
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Comscore ScorecardResearch",
      category: "ScorecardResearchDetect",
      // Comscore ScorecardResearch — audience measurement beacon
      // used by publishers and broadcasters for Comscore's panel +
      // census measurement service. First-party persistent _scor_uid
      // UUID cookie with ~33-year TTL. Consent-aware (TCF 2.0 / GPP
      // 1.1 / USP v1). Lightweight fingerprinting surface.
      globals: [
        "COMSCORE",              // main export function
        "_comscore",             // queue array (_comscore.push([...]))
        "ns_p",                  // Image beacon reference
      ],
      globalPrefixes: [],
      keyPatterns: [
        /^_scor_uid$/i,          // first-party 33-year UUID cookie
      ],
      scriptSrcPatterns: [
        /\bscorecardresearch\.com\b/i,   // primary host (sb / b / www subs)
        /\bcomscore\.com\b/i,              // parent company CDN
        /\/beacon\.js\b/i,                 // distinctive loader filename
        /\/aaq\/vzm\/cs_\d/i,              // Yahoo-CDN-served Comscore module (s.yimg.com/aaq/vzm/cs_<ver>.js)
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Google Tag / Analytics",
      category: "GoogleTagDetect",
      // Google Tag Manager (gtm.js) + Google tag (gtag.js) — the
      // most widely deployed tag loader on the web. Covers Google
      // Analytics 4, Universal Analytics (legacy), Google Ads,
      // Campaign Manager / Floodlight, and serves as the loader
      // for the dataLayer + gtag() API. First-party cookies + UA
      // hints, not an entropy collector. Beacons to /g/collect
      // (GA4) and /collect (UA legacy).
      globals: [
        "gtag",                  // GA4 API function
        "dataLayer",             // tag event queue (array)
        "google_tag_manager",    // GTM container object (keyed by GTM-XXXX)
        "google_tag_data",       // GTM runtime state
        "ga",                    // legacy Universal Analytics
        "_gaq",                  // very legacy ga.js queue
      ],
      globalPrefixes: [],
      keyPatterns: [
        /^_ga$/i,                // GA client ID
        /^_ga_/i,                // _ga_<stream-id> GA4 session
        /^_gid$/i,               // UA session
        /^_gat$/i,                // UA throttle
        /^_gat_gtag_/i,           // gtag throttle
        /^_gac_/i,                // Google Ads conversion linker
        /^_dc_gtm_/i,             // GTM debug counter
      ],
      scriptSrcPatterns: [
        /\bgoogletagmanager\.com\b/i,        // gtm.js + gtag loader
        /\bgoogle-analytics\.com\b/i,        // legacy GA endpoints (/collect, /analytics.js)
        /\banalytics\.google\.com\b/i,       // GA4 reporting + some tag paths
        /\bgoogleads\.g\.doubleclick\.net\b/i, // Google Ads conversion
        /\bstats\.g\.doubleclick\.net\b/i,    // GA conversion linker
        /\/gtag\/js\b/i,                      // gtag loader path
        /\/gtm\.js\b/i,                       // GTM container
        /\/analytics\.js\b/i,                  // legacy UA loader
        /\/ga\.js\b/i,                         // ancient GA loader
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Google Publisher Tag",
      category: "GoogleGPTDetect",
      // Google Publisher Tag (GPT) — Google Ad Manager's publisher-
      // side ad-serving library. Distinct from gtag/GA: GPT requests
      // ads and renders creatives via googletag.pubads() /
      // defineSlot() / display(). Doesn't fingerprint itself — the
      // downstream ad creatives do (canvas / WebGL / audio hooks will
      // fire independently when they run). Usually seen alongside
      // GoogleTagDetect on publishers running GA + ads.
      globals: [
        "googletag",             // primary API (googletag.cmd, googletag.pubads)
      ],
      globalPrefixes: [],
      keyPatterns: [],             // relies on DoubleClick third-party cookies (IDE/DSID) — not set by GPT itself
      scriptSrcPatterns: [
        /\bpagead2\.googlesyndication\.com\b/i,  // primary loader + ad request
        /\bgoogletagservices\.com\b/i,             // legacy GPT host
        /\bsecurepubads\.g\.doubleclick\.net\b/i,  // GPT limited-ads mode
        /\/tag\/js\/gpt\.js\b/i,                   // distinctive GPT path
        /\/gampad\/ads\b/i,                         // GPT ad request endpoint
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Yahoo / Oath",
      category: "YahooOathDetect",
      // Yahoo / Oath / Verizon Media tracking stack. Covers Yahoo
      // Analytics (Rapid framework, YAHOO.i13n) served from s.yimg.com
      // and the Oath CMP served from consent.cmp.oath.com. Seen on
      // Yahoo News / Mail / Finance / AOL / HuffPost / TechCrunch /
      // Engadget and sites licensing Oath's CMP. Avoids IAB standard
      // globals (__tcfapi / __gpp / __uspapi) since every CMP sets
      // those — relies on Yahoo-specific guce / GUC cookies and the
      // YAHOO.i13n Rapid global.
      globals: [
        "YAHOO",                 // Rapid framework namespace (YAHOO.i13n, YAHOO.comscore)
        "YahooCJS",              // consent / CMP bridge
        "YAWebBridge",           // mobile app bridge
      ],
      globalPrefixes: [],
      keyPatterns: [
        /^GUC$/,                 // primary Oath consent + ID cookie
        /^guce_/i,               // guce_* cross-domain consent cookies
        /^A1$/, /^A1S$/, /^A3$/, // Yahoo ID cookies
        /^B$/,                   // legacy Yahoo bucket cookie (short — exact match only)
        /^ySID$/i,               // Yahoo session ID
        /^_vuid$/i,              // visit UID localStorage
        /^_vuidList$/i,
      ],
      scriptSrcPatterns: [
        /\bs\.yimg\.com\b/i,            // Yahoo CDN (serves analytics-*.js + cs_*.js)
        /\bconsent\.cmp\.oath\.com\b/i, // Oath CMP host
        /\bguce\.(?:oath|yahoo|aol|techcrunch|huffpost|engadget)\.com\b/i, // GUCE consent hosts
        /\bgeo\.yahoo\.com\b/i,          // geo beacon
        /\b3p-(?:geo|udc)\.yahoo\.com\b/i, // cross-domain beacons
        /\bganon\.yahoo\.com\b/i,         // anonymous analytics
        /\/ss\/analytics-[\d.]+\.js\b/i, // Rapid analytics filename pattern
      ],
      // Note: Yahoo Rapid uses data-ylk / data-rapid-skip on content
      // elements (links, divs), not <script> tags, so they don't fit
      // the registry's domAttributes (<script>-only) model.
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Kameleoon",
      category: "KameleoonDetect",
      // Kameleoon — French A/B testing, personalization and feature-
      // flagging SaaS (competitor to Optimizely / VWO / Dynamic Yield).
      // Loader served from <customer-hash>.kameleoon.eu/kameleoon.js
      // with a full SDK at /kameleoon-full.js. Tracks visitor codes,
      // experiment exposures, conversions and custom data; uses
      // BroadcastChannel + iframe postMessage for cross-tab/domain sync.
      globals: [
        "Kameleoon",                    // primary namespace
        "kameleoonQueue",               // event queue
        "kameleoonDisplayPage",
        "kameleoonEvents",
      ],
      globalPrefixes: [],
      keyPatterns: [
        /^kameleoon/i,                   // kameleoonVisitorCode, kameleoonData,
                                          // kameleoonExperiment-<id>,
                                          // kameleoonSimulationVisitorData,
                                          // kameleoonGlobalPersonalizationExposition,
                                          // kameleoonTabId — all share prefix
      ],
      scriptSrcPatterns: [
        /\bkameleoon\.eu\b/i,            // primary host (customer CNAMEs)
        /\bkameleoon\.com\b/i,           // company site + API
        /\/kameleoon(?:-full)?\.js\b/i,  // loader + full SDK filenames
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Webtrekk / Mapp Intelligence",
      category: "WebtrekkMappDetect",
      // Webtrekk (acquired by Mapp Digital in 2019, now branded
      // "Mapp Intelligence") — German-founded analytics platform
      // heavily used by DACH publishers (heise, Zeit Online, Der
      // Spiegel) and European e-commerce. Beacons to a distinctive
      // /resp/api/(get|v4|v5)/ path on customer CNAMEs like
      // responder.wt.<publisher>.de, with Mapp's EU infrastructure
      // at wt-eu01.net / wt-eu02.net. Everest visitor IDs in the
      // wt_eid / wtstp_eid cookie family.
      globals: [
        "webtrekk",
        "webtrekkV3",
        "wtSmart",
        "mappIntelligence",
      ],
      globalPrefixes: [],
      keyPatterns: [
        /^wt_/i,                         // wt_eid, wt_3_eid, wt_mmie, wt_nc, wt_rla etc.
        /^wtstp_/i,                      // wtstp_eid and related
        /^wtCB_/i,                       // callback-related localStorage
        /^wt_loadtime/i,
      ],
      scriptSrcPatterns: [
        /\/resp\/api\/(?:get|v\d+)\b/i,  // distinctive beacon / tag endpoint path
        /\bwt-eu\d+\.net\b/i,            // Mapp EU infrastructure hosts
        /\bwebtrekk\.(?:com|de|net)\b/i,
        /\bmapp\.com\/mapp-intelligence\b/i,
        /\bresponder\.wt\.[^/]+\b/i,     // customer CNAME pattern responder.wt.<publisher>.(de|com)
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Pushly",
      category: "PushlyDetect",
      // Pushly — push-notification SaaS platform. Page-side loader
      // (pushly.min.js) registers a background service worker
      // (pushly-sw.min.js) which handles PushManager subscription,
      // notification display, and interaction tracking. Beacons to
      // k.p-n.io/event-stream. Note that the PushSubscription
      // endpoint itself is a per-device fingerprint — already hooked
      // via permissions.js pushManager.subscribe.
      globals: [
        "Pushly",                // page-side SDK namespace
        "PushlySDK",             // alternate export name
      ],
      globalPrefixes: [],
      keyPatterns: [
        /^_pn(?:_[0-9A-Za-z]{8})?$/, // Pushly cookie pattern _pn or _pn_<8chars>
        /^pn_ll$/,                    // log level localStorage
        /^pn_store$/,                 // IndexedDB database name
      ],
      scriptSrcPatterns: [
        /\bp-n\.io\b/i,              // CDN (cdn.p-n.io) + API (k.p-n.io)
        /\bpushly\.com\b/i,           // company site / legacy
        /\/pushly(?:-sw)?(?:\.min)?\.js\b/i, // pushly.min.js / pushly-sw.min.js
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Quantcast",
      category: "QuantcastDetect",
      // Quantcast — combined analytics (Quantcast Measure, served via
      // quant.js) and CMP (Quantcast Choice, TCF 2.0 / GPP / USP).
      // One of the oldest publisher trackers on the web. Classic
      // _qevents.push({qacct:"..."}) tag pattern plus the __qca
      // first-party cookie with 30-year TTL. Beacons to
      // pixel.quantcount.com / pixel.quantserve.com, rules engine
      // at rules.quantcount.com.
      globals: [
        "__qc",                  // main API object
        "_qevents",              // event queue
        "quantserve",            // legacy alias
        "_qmeta",                // metadata carrier
      ],
      globalPrefixes: [],
      keyPatterns: [
        /^__qca$/,               // primary 30-year ID cookie
        /^_qcses_/i,             // _qcses_<pcode> session
        /^__qcdbgc$/,            // debug flag
      ],
      scriptSrcPatterns: [
        /\bquantserve\.com\b/i,  // main host family (secure / pixel / legacy)
        /\bquantcount\.com\b/i,  // pixel + rules hosts
        /\/quant\.js\b/i,         // distinctive tag filename
        /\/rules-[^/]+\.js\b/i,   // dynamic rule loader filename
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Microsoft Clarity",
      category: "ClarityDetect",
      // Microsoft Clarity — free session-replay + heatmap tool,
      // competitor to Hotjar. Loader stub (/tag/<projectID>) ~707
      // bytes, injects the real script from scripts.clarity.ms.
      // Records mouse / scroll / keystroke / DOM mutations for
      // session playback. Deliberately avoids MUID / MR / ANONCHK
      // / SM cookies since those are Microsoft's broader ad cookies
      // (Bing, LinkedIn) — using Clarity-specific _clck / _clsk /
      // CLID only.
      globals: [
        "clarity",               // primary global (clarity.q async queue)
      ],
      globalPrefixes: [],
      keyPatterns: [
        /^_clck$/,               // Clarity client ID
        /^_clsk$/,               // Clarity session
        /^CLID$/,                // Clarity internal ID
      ],
      scriptSrcPatterns: [
        // Host-only match: clarity.ms covers all subs (www, scripts, c,
        // j, k, l). Not matching the bare /tag/<projectID> path
        // separately because "/tag/<alphanumeric>" is too generic and
        // would false-positive on unrelated sites.
        /\bclarity\.ms\b/i,
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "RUM Vision",
      category: "RUMVisionDetect",
      // RUM Vision (rumvision.com) — lightweight Real User Monitoring
      // that measures Core Web Vitals (LCP / FID / CLS / INP / TTFB /
      // FCP) on top of Google's web-vitals library. Served as
      // per-site CloudFront builds with a distinctive
      // /RUM-<hex>/v<digit>-<domain>.js path. No cookies, no
      // globals, no localStorage — URL-only detection. Beacons to
      // an AWS API Gateway host (subdomain is per-customer).
      globals: [],
      globalPrefixes: [],
      keyPatterns: [],
      scriptSrcPatterns: [
        /\brumvision\.com\b/i,                 // canonical company host
        /\/RUM-[A-F0-9]{6,}\/v\d+-[^/]+\.js\b/i, // CloudFront per-site build path
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Nativo",
      category: "NativoDetect",
      // Nativo (formerly PostRelease) — native advertising platform
      // used by major publishers (Forbes, Time, NBC, CBS, etc.).
      // Primary loader at s.ntv.io/serve/load.js (~900KB bundle
      // including jQuery 2.1.1). Tracks ad viewability, impressions,
      // clicks; integrates with header-bidding stacks.
      globals: [
        "Nativo",                    // main namespace
        "nativoSDK",                 // SDK entry
        "ntv",                       // short alias
        "ntvConfig",
        "ntvArticleTracker",
        "ntvToutAds",
        "ntvViewableImpressionTracker",
        "PostRelease",               // legacy pre-rebrand global
      ],
      globalPrefixes: [],
      keyPatterns: [],                // Nativo relies on header-bidding partner cookies, doesn't set distinctive first-party cookies
      scriptSrcPatterns: [
        /\bntv\.io\b/i,              // all subs (s / serve / cache / static)
        /\bpostrelease\.com\b/i,     // legacy company domain
        /\/serve\/load\.js\b/i,      // distinctive loader path
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Geniuslink",
      category: "GeniuslinkDetect",
      // Geniuslink — affiliate link converter. Publisher-side
      // snippet rewrites Amazon / Google Play / iTunes / Microsoft
      // Store affiliate links into geo-routed geni.us short links
      // for correct regional store attribution. Common on blogs,
      // podcast sites and creator pages. Click-time redirect
      // tracking at geni.us, not pervasive surveillance.
      globals: [
        "Genius",                    // primary namespace (with .snippet/.amazon/.google/.itunes/.microsoft)
      ],
      globalPrefixes: [],
      keyPatterns: [],                // snippet itself doesn't set cookies/storage — tracking happens on the geni.us redirect
      scriptSrcPatterns: [
        /\bgeniuslinkcdn\.com\b/i,   // primary CDN
        /\bgeni\.us\b/i,              // short-link domain (click tracking)
        /\bcdn\.geni\.us\b/i,         // alternate CDN host
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Google Funding Choices",
      category: "GoogleFundingChoicesDetect",
      // Google Funding Choices — Google's CMP for AdSense / Ad
      // Manager publishers (rebranded "Privacy & Messaging" in the
      // AdSense UI). Shows GDPR / CCPA consent banners and optional
      // ad-blocking messages on AdSense-monetised sites. Served from
      // fundingchoicesmessages.google.com/i/pub-<id>. Deliberately
      // avoids __gpi / __gads cookies since those are shared with
      // GPT / AdSense — using FC-specific FCCDCF / FCIDCF / FCNEC
      // cookies only.
      globals: [
        "googlefc",                  // primary namespace
        "googlefcInactive",          // inactive flag
        "googlefcLoaded",            // loaded flag
        "googlefcPresent",           // presence sentinel
      ],
      globalPrefixes: [],
      keyPatterns: [
        /^FCCDCF$/,                  // content feature consent
        /^FCIDCF$/,                  // content feature ID
        /^FCNEC$/,                   // non-essential cookies consent
      ],
      scriptSrcPatterns: [
        /\bfundingchoicesmessages\.google\.com\b/i,  // primary host
        /\/i\/pub-\d+\b/i,                             // distinctive publisher instance path
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Chartbeat",
      category: "ChartbeatDetect",
      // Chartbeat — real-time publisher analytics. Ubiquitous on
      // news sites (NYT, WSJ, BBC, CNN, Guardian, Washington Post).
      // The pSUPERFLY global name dates back to Chartbeat's
      // original internal project name "Superfly" — stable for
      // 15+ years. Loader at static.chartbeat.com, pings to
      // ping.chartbeat.net.
      globals: [
        "_sf_async_config",          // classic init object (_sf_async_config.uid = "...")
        "pSUPERFLY",                 // main namespace (legacy codename)
        "pSUPERFLY_mab",             // multi-arm bandit module
        "pSUPERFLY_pub",             // publisher data module
      ],
      globalPrefixes: [],
      keyPatterns: [
        /^cbt$/,
        /^cb_svref$/,
        /^cbEventId$/,
        /^cb_shared$/,
        /^cb_rec$/,
        /^cb_ip$/,
        /^cb_optout$/,
        /^cb(?:qpush|_test|_ls_test)$/,
      ],
      scriptSrcPatterns: [
        /\bchartbeat\.com\b/i,       // loader hosts (static / www)
        /\bchartbeat\.net\b/i,        // ping / beacon hosts
        /\/chartbeat(?:_mab|_video)?\.js\b/i, // distinctive loader filenames
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "Ziff Davis Consent",
      category: "ZiffDavisDetect",
      // Ziff Davis consent wrapper (zdconsent.js) — custom CMP layer
      // used across ZD properties (ZDNet, PCMag, IGN, Mashable,
      // RetailMeNot, Speedtest/Ookla, Humble Bundle, etc.). Wraps
      // OneTrust and orchestrates consent-gating for downstream
      // trackers (Comscore, Chartbeat, HubSpot, ad networks).
      // Deliberately skips OneTrustStub / __tcfapi / _hsq /
      // _sf_async_config references — those are third-party
      // trackers ZD loads, not ZD-specific signals.
      globals: [
        "zdconsent",                 // primary namespace
        "_ZDCABADML",                // ZD-specific consent flag
        "_ZDCCOMSCORE",              // ZD-specific Comscore consent gate
      ],
      globalPrefixes: [],
      keyPatterns: [],                // wrapper delegates storage to OneTrust — no ZD-owned cookies
      scriptSrcPatterns: [
        /\bziffstatic\.com\b/i,      // ZD CDN
        /\bziffdavis\.com\b/i,       // company site
        /\/zdconsent\.js\b/i,         // distinctive filename
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "HubSpot",
      category: "HubSpotDetect",
      // HubSpot — CRM + marketing automation. One of the most
      // deployed marketing trackers on the web. Multi-domain stack:
      // hubspot.com (main), hscta.net (CTAs), hsforms.net (forms),
      // hsleadflows.net (lead flows), hs-scripts.com (tracking code),
      // hs-analytics.net (analytics), hs-banner.com (banners),
      // hubapi.com (API). Distinctive __hstc / __hssc / hubspotutk
      // cookie family — and yes, HubSpot literally sets a cookie
      // named __hsfp ("HubSpot fingerprint").
      globals: [
        "_hsq",                      // main event queue (_hsq.push([...]))
        "hbspt",                     // namespace (hbspt.cta, hbspt.forms)
        "hsVars",
        "hsCallsToActionsReady",
        "hsCtasOnReady",
      ],
      globalPrefixes: [
        "__PRIVATE__Hubspot",        // __PRIVATE__HubspotCtaClient etc.
        "_hs",                        // _hsOnlyTrackHubspotCTAS, _hstc_loaded etc.
      ],
      keyPatterns: [
        /^__hstc$/,                  // visitor tracking
        /^__hssc$/,                  // session
        /^__hssrc$/,                 // session source
        /^__hsfp$/,                  // "HubSpot fingerprint" hash cookie
        /^hubspotutk$/,              // user identifier
        /^_hsenc$/,                  // encoded parameter / cookie
      ],
      scriptSrcPatterns: [
        /\bhubspot\.com\b/i,         // main company domain (blog / cdn / js)
        /\bhscta\.net\b/i,            // CTAs loader
        /\bhsforms\.(?:net|com)\b/i,  // forms loader
        /\bhsleadflows\.net\b/i,      // lead flows
        /\bhs-scripts\.com\b/i,       // tracking code
        /\bhs-analytics\.net\b/i,     // analytics beacon
        /\bhs-banner\.com\b/i,        // smart banners
        /\bhubapi\.com\b/i,           // public API
        /\bhsappstatic\.net\b/i,      // app CDN
        /\bhsadspixel\.net\b/i,       // HubSpot Ads conversion pixel
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
    {
      name: "LinkedIn Insight Tag",
      category: "LinkedInInsightDetect",
      // LinkedIn Insight Tag — LinkedIn's marketing analytics and
      // retargeting pixel. Used by B2B marketers for website-visitor
      // tracking, audience building and conversion measurement on
      // LinkedIn ad campaigns. Loader at
      // snap.licdn.com/li.lms-analytics/insight.min.js, pixel/beacon
      // traffic to px.ads.linkedin.com and dc.ads.linkedin.com.
      globals: [
        "lintrk",                    // public event API (window.lintrk('track', {...}))
        "_lintrk",                   // internal queue
        "_linkedin_data_partner_id", // legacy single partner ID
        "_linkedin_data_partner_ids", // newer multi-partner array
        "_already_called_lintrk",
        "_wait_for_lintrk",
        "ORIBILI",                   // internal LinkedIn namespace
      ],
      globalPrefixes: [],
      keyPatterns: [
        /^li_fat_id$/i,              // primary first-party ID (also forwarded by Meta Pixel)
        /^li_gc$/i,                  // guest consent
        /^li_mc$/i,                  // member consent
      ],
      scriptSrcPatterns: [
        /\bsnap\.licdn\.com\b/i,     // primary CDN loader host
        /\blicdn\.com\b/i,            // fallback
        /\bpx\.ads\.linkedin\.com\b/i, // pixel beacon
        /\bdc\.ads\.linkedin\.com\b/i, // data collection
        /\/li\.lms-analytics\//i,     // distinctive tag path
        /\/insight(?:\.min)?\.js\b/i, // insight.min.js filename
      ],
      domAttributes: [],
      classifyOrigin: true,
    },
  ];

  // ── Shared fired-key dedupe ──────────────────────────────────────────
  // Single Set shared across all libraries. Keys are namespaced by
  // library name to prevent cross-library collisions.
  const fired = new Set();
  function fireOnce(library, signalKey, label, detail) {
    const k = library.name + "|" + signalKey;
    if (fired.has(k)) return;
    fired.add(k);
    record(library.category, label, detail);
  }

  // ── Origin classification (FingerprintJS only opts in currently) ─────
  function classifyOrigin(url) {
    try {
      const u = new URL(url, location.href);
      const pageHost = location.hostname;
      const scriptHost = u.hostname;
      if (!scriptHost) return "unknown";
      if (scriptHost === pageHost) return "1p (same origin)";
      const pageParts = pageHost.split(".");
      const scriptParts = scriptHost.split(".");
      if (pageParts.length >= 2 && scriptParts.length >= 2) {
        const pageSuffix = pageParts.slice(-2).join(".");
        const scriptSuffix = scriptParts.slice(-2).join(".");
        if (pageSuffix === scriptSuffix) {
          return "1p (custom subdomain: " + scriptHost + ")";
        }
      }
      return "3p (" + scriptHost + ")";
    } catch {
      return "unknown";
    }
  }

  // ── Scan implementations ─────────────────────────────────────────────
  function scanGlobals() {
    // Snapshot window keys ONCE for all libraries to share
    let windowKeys = null;
    try { windowKeys = Object.keys(window); } catch { windowKeys = []; }

    for (let li = 0; li < LIBRARIES.length; li++) {
      const lib = LIBRARIES[li];
      // Explicit globals
      for (let i = 0; i < lib.globals.length; i++) {
        const name = lib.globals[i];
        try {
          if (name in window && window[name] !== undefined && window[name] !== null) {
            fireOnce(lib, "global:" + name, "Global variable", "window." + name);
          }
        } catch { /* throws on some globals */ }
      }
      // Prefix matches against shared window-keys snapshot
      if (lib.globalPrefixes && lib.globalPrefixes.length > 0) {
        for (let k = 0; k < windowKeys.length; k++) {
          const key = windowKeys[k];
          if (typeof key !== "string") continue;
          for (let p = 0; p < lib.globalPrefixes.length; p++) {
            if (key.indexOf(lib.globalPrefixes[p]) === 0) {
              fireOnce(lib, "global-pattern:" + key,
                "Global variable (pattern match)", "window." + key);
              break;
            }
          }
        }
      }
      // Anomaly check (e.g. Date.prototype.getTimeAlias for Matomo)
      if (lib.anomaly && lib.anomaly.check()) {
        fireOnce(lib, "anomaly:" + lib.anomaly.key,
          lib.anomaly.label, lib.anomaly.detail);
      }
    }
  }

  function keyMatchesAnyLibrary(key) {
    if (typeof key !== "string" || !key) return null;
    for (let li = 0; li < LIBRARIES.length; li++) {
      const lib = LIBRARIES[li];
      if (!lib.keyPatterns) continue;
      for (let p = 0; p < lib.keyPatterns.length; p++) {
        if (lib.keyPatterns[p].test(key)) return lib;
      }
    }
    return null;
  }

  function scanStorage(store, kind) {
    try {
      for (let i = 0; i < store.length; i++) {
        const key = store.key(i);
        const lib = keyMatchesAnyLibrary(key);
        if (lib) {
          fireOnce(lib, kind + ":" + key, kind + " key", key);
        }
      }
    } catch { /* no-op */ }
  }

  function scanCookies() {
    try {
      const cookies = document.cookie;
      if (!cookies || typeof cookies !== "string") return;
      const parts = cookies.split(";");
      for (let i = 0; i < parts.length; i++) {
        const eq = parts[i].indexOf("=");
        const name = (eq > -1 ? parts[i].slice(0, eq) : parts[i]).trim();
        const lib = keyMatchesAnyLibrary(name);
        if (lib) {
          fireOnce(lib, "cookie:" + name, "Cookie key", name);
        }
      }
    } catch { /* no-op */ }
  }

  // ── Script URL / resource matching ───────────────────────────────────
  // Checks a URL against every library's scriptSrcPatterns. Returns
  // the matching library (and optional origin classification) or null.
  function matchScriptUrl(url) {
    if (typeof url !== "string" || url.length < 4) return null;
    for (let li = 0; li < LIBRARIES.length; li++) {
      const lib = LIBRARIES[li];
      if (!lib.scriptSrcPatterns || lib.scriptSrcPatterns.length === 0) continue;
      for (let p = 0; p < lib.scriptSrcPatterns.length; p++) {
        if (lib.scriptSrcPatterns[p].test(url)) return lib;
      }
    }
    return null;
  }

  function reportLoader(url, source) {
    const lib = matchScriptUrl(url);
    if (!lib) return;
    let label, key;
    if (lib.classifyOrigin) {
      const cls = classifyOrigin(url);
      label = source + " (" + cls + ")";
      key = source + ":" + cls;
    } else {
      label = source;
      key = source;
    }
    fireOnce(lib, key, label, url.slice(0, 200));
  }

  // ── Scan a single <script> for library signals ───────────────────────
  function scanScript(script) {
    if (!script || script.nodeType !== 1 || script.tagName !== "SCRIPT") return;
    // data-* attributes
    if (typeof script.hasAttribute === "function") {
      for (let li = 0; li < LIBRARIES.length; li++) {
        const lib = LIBRARIES[li];
        if (!lib.domAttributes || lib.domAttributes.length === 0) continue;
        for (let a = 0; a < lib.domAttributes.length; a++) {
          if (script.hasAttribute(lib.domAttributes[a])) {
            fireOnce(lib, "dom-attr:" + lib.domAttributes[a],
              "DOM integration tag",
              "<script " + lib.domAttributes[a] + ">");
          }
        }
      }
    }
    // src URL
    const src = typeof script.getAttribute === "function"
      ? script.getAttribute("src") : null;
    if (src) reportLoader(src, "DOM <script src>");
  }

  function scanAllScripts() {
    try {
      const scripts = document.getElementsByTagName("script");
      for (let i = 0; i < scripts.length; i++) scanScript(scripts[i]);
    } catch { /* no-op */ }
  }

  // ── Combined runner ──────────────────────────────────────────────────
  function runScans() {
    scanGlobals();
    try { if (typeof localStorage !== "undefined" && localStorage) scanStorage(localStorage, "localStorage"); } catch { /* no-op */ }
    try { if (typeof sessionStorage !== "undefined" && sessionStorage) scanStorage(sessionStorage, "sessionStorage"); } catch { /* no-op */ }
    scanCookies();
    scanAllScripts();
  }

  // Shared scan points — runs all libraries in one pass.
  // Skip the install-time scan (we're at document_start before any
  // page scripts have run — nothing to find yet). PerformanceObserver
  // + MutationObserver below DO start immediately so we don't miss
  // early resource loads.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", runScans, { once: true });
  } else {
    runScans();
  }
  setTimeout(runScans, 2000);
  window.addEventListener("load", runScans, { once: true });

  // ── Single shared PerformanceObserver ────────────────────────────────
  if (typeof PerformanceObserver !== "undefined") {
    try {
      const observer = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        for (let i = 0; i < entries.length; i++) {
          const entry = entries[i];
          if (entry.entryType === "resource") {
            reportLoader(entry.name, "loader");
          }
        }
      });
      observer.observe({ entryTypes: ["resource"] });
      // Retroactive scan of already-completed resources
      try {
        const existing = performance.getEntriesByType("resource");
        for (let i = 0; i < existing.length; i++) {
          reportLoader(existing[i].name, "loader");
        }
      } catch { /* no-op */ }
    } catch { /* not supported */ }
  }

  // ── Single shared MutationObserver for <script> tag injections ───────
  if (typeof MutationObserver !== "undefined") {
    try {
      const domObserver = new MutationObserver((mutations) => {
        for (let i = 0; i < mutations.length; i++) {
          const added = mutations[i].addedNodes;
          for (let j = 0; j < added.length; j++) {
            const node = added[j];
            if (!node || node.nodeType !== 1) continue;
            if (node.tagName === "SCRIPT") scanScript(node);
            if (typeof node.querySelectorAll === "function") {
              const nested = node.querySelectorAll("script");
              for (let k = 0; k < nested.length; k++) scanScript(nested[k]);
            }
          }
        }
      });
      function startObserving() {
        const root = document.documentElement || document.body;
        if (root) domObserver.observe(root, { childList: true, subtree: true });
      }
      if (document.documentElement) {
        startObserving();
      } else {
        document.addEventListener("DOMContentLoaded", startObserving, { once: true });
      }
    } catch { /* no-op */ }
  }
}
