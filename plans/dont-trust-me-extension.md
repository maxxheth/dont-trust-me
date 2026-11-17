# Don't Trust Me: Zero-Trust Security-Header Extension, Implementation Plan

## 1. Context

**The problem.** Browsers made HTTPS the baseline by labelling HTTP pages "Not secure" and putting full-page warnings in front of broken certificates. Nothing comparable exists for the response headers that limit what JavaScript on a page may do. A site can send no Content-Security-Policy at all and still show a padlock.

**What prompted this.** On 16 Nov 2026 an attacker exploited a flaw in Optimizely's Experimentation signup flow and wrote a loader into customers' Project JavaScript (the attack has been dubbed "OPTIMJACK"). Report URI found the malicious code in 188 of 1,611 Optimizely snippets it checked, belonging to 178 organisations including the BBC, CNN, Zoom, HSBC and Salesforce. The snippets were still served from `cdn.optimizely.com` with a valid certificate, so every browser trusted them. The loader:
- pulled `track.js` from `1688360[.]cc`, written as a plain URL, as a Base64 string decoded with `atob()`, or as an inline fallback copy;
- skimmed card numbers, expiry dates and security codes and posted them to `1688360[.]cc/card.php`;
- swapped cryptocurrency wallet addresses;
- collected cookies and screenshots;
- on iPhones and iPads, loaded iOS exploit kits through a hidden frame.

Reporting is a day old and details are still developing.

**The lesson.** TLS proved where the code came from, not that it was safe. Allowlisting `cdn.optimizely.com` in a CSP would not have stopped the poisoned script. Other parts of a strict policy would have contained it, though:
- `script-src` blocks the second-stage loader;
- `connect-src`, `img-src` and `form-action` block the exfiltration;
- `frame-src` blocks hidden exploit frames;
- `HttpOnly` keeps session cookies away from scripts;
- `report-to` tells the site owner something is wrong.

The policy did block the payload on at least two of the affected sites (reported by Amirul Cyber).

**The intended outcome.** A Manifest V3 extension built with [Extension.js](https://extension.js.org/) that grades every top-level document's security headers. If a document has no enforced CSP that governs scripts, the extension shows a full-page "Not Secure" warning before the page renders, the same way a browser treats a broken certificate. Weaker postures get a toolbar grade and in-page warnings.

### Decisions already made

| Topic | Decision |
|---|---|
| Interstitial trigger (default) | No enforced CSP that governs scripts (or plain HTTP). The threshold can be changed in Options. |
| Weak-but-present policies | Red badge, an in-page warning bar and warnings on sensitive fields; no block by default. |
| Browsers (v1) | Chromium (Chrome, Edge, Brave, Opera; version 128 or later) and Firefox (MV3). Safari comes later. |
| Runtime script and connection monitoring | Phase 2 add-on, not in v1. |
| UI stack | React and TypeScript for extension pages; plain TypeScript for the content script, to keep page weight low. |
| Privacy | All analysis is local. The extension makes no network requests of its own (one optional exception is described in §8). |

## 2. Goals and non-goals

**Goals (v1)**
1. Grade the response headers of every top-level HTTP(S) document (A+ to F) with explained findings.
2. Block before render, with no page script execution, any document whose verdict is **Not Secure**, using a browser-style warning page and a deliberate "Proceed (unsafe)" path.
3. Show a per-tab toolbar icon and badge that the page cannot spoof.
4. Warn inside the page on sites that are Weak or that the user bypassed, especially on password, card and crypto-address fields. This mirrors Chrome's "Login not secure" warning on HTTP.
5. Provide a trust list, exclusions and threshold settings, with no telemetry.

**Non-goals (v1):** grading subframes, runtime script monitoring (Phase 2), Safari, enterprise policy, and remote blocklist updates.

## 3. What "proper security headers" means

### 3.1 Verdicts

| Verdict | Criteria | Default treatment |
|---|---|---|
| **Not Secure** | Plain HTTP document, **or** no *enforced* CSP whose policy contains `script-src`, `script-src-elem` or `default-src`. Report-Only does not count, and neither does a CSP that only sets `frame-ancestors` or `upgrade-insecure-requests`. | Pre-render interstitial, red icon, grade F |
| **Weak** | CSP is present but scripts are effectively unrestricted: `*`, `http:`, `https:` or `data:` in the effective script source list without `'strict-dynamic'`, or `'unsafe-inline'` without a nonce or hash. Also any grade of D or F. | Red badge, warning bar and sensitive-field warnings |
| **Partial** | Grade B or C | Amber badge |
| **Secure** | Grade A or A+ | Green badge |
| **Unverified** | No header data for this document (it was served from a service worker cache, the tab was open before install, etc.) | Grey badge and a "Re-check" button |

In Options, the interstitial threshold can be **Not Secure only** (the default), **Weak and below**, or **Never** (badge only).

### 3.2 Scoring (starts at 100; weights live in `src/analyzer/policy.ts` and are tunable)

| ID | Finding | Penalty | Why it matters (OPTIMJACK mapping) |
|---|---|---|---|
| T1 | Document served over HTTP | hard F | No integrity at all |
| C1 | No enforced CSP governing scripts (missing, Report-Only only, or no script/default directive) | hard F | Any injected or compromised script runs freely |
| C3 | Script sources allow `*`, `http:`, `https:` or `data:` | −35 | Loader can pull its second stage from anywhere |
| C4 | `'unsafe-inline'` without nonce or hash | −30 | Injected inline code runs |
| C5 | `'unsafe-eval'` | −10 | `eval`/`atob` style unpacking |
| C6 | Host allowlist without nonce, hash or `'strict-dynamic'` | −10 | Trusts every file on a vendor host (the OPTIMJACK vector) |
| C7 | `object-src` not `'none'` (directly or through `default-src`) | −10 | Plugin-based script execution |
| C8 | `base-uri` missing | −5 | Relative script URLs can be hijacked |
| E1 | `connect-src` unrestricted | −15 | Data exfiltration through `fetch`/XHR (`card.php`) |
| E2 | `frame-src`/`child-src` unrestricted | −10 | Hidden frames loading exploit kits |
| E3 | `form-action` missing | −5 | Forms posted to attacker hosts |
| E4 | `img-src` unrestricted | −5 | Exfiltration through image beacons |
| R1 | No `report-to`/`report-uri` | −5 | The site owner never finds out |
| H1 | No `frame-ancestors` and no `X-Frame-Options: DENY/SAMEORIGIN` | −15 | Clickjacking |
| H2 | HSTS missing (on HTTPS) | −20 | SSL-strip downgrade |
| H3 | HSTS `max-age` under one year | −10 | Weak downgrade protection |
| H4 | `X-Content-Type-Options: nosniff` missing | −10 | MIME-confusion script execution |
| H5 | `Referrer-Policy` missing or `unsafe-url`/`no-referrer-when-downgrade` | −5 | URL leakage |
| H6 | `Permissions-Policy` missing | −5 | Camera, microphone and payment APIs left open |
| H7 | `Cross-Origin-Opener-Policy` missing or `unsafe-none` | −5 | Cross-window attacks |
| K1 | A `Set-Cookie` without `Secure` (HTTPS) | −10 | Cookie theft over the network |
| K2 | A `Set-Cookie` without `HttpOnly` | −5 | Cookies readable by injected script (OPTIMJACK stole cookies) |
| + | Strict CSP (nonce or hash plus `'strict-dynamic'`, no host allowlist) | +10 | |
| + | `require-trusted-types-for 'script'` | +5 | DOM XSS sink control |
| + | HSTS `includeSubDomains; preload` | +5 | |

Grade bands: A+ ≥ 100, A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 45, otherwise F. A hard fail always means F. CORP, COEP, `X-XSS-Protection` and `Server`/`X-Powered-By` disclosure appear as informational findings only.

## 4. Architecture

```
 navigation (main_frame GET)
        │
        ▼
 ┌────────────────────────────── Chromium ──────────────────────────────┐
 │ DNR dynamic rule "gate" (response stage, Chrome 128+)                 │
 │   no script-governing CSP & not 3xx & not download & HTML            │
 │   → redirect to pages/interstitial.html#<url>  (page never renders)   │
 │ webRequest.onHeadersReceived (observe, extraHeaders) ─► analyzer      │
 └───────────────────────────────────────────────────────────────────────┘
 ┌────────────────────────────── Firefox ───────────────────────────────┐
 │ webRequest.onHeadersReceived (blocking) ─► analyzer ─► redirectUrl     │
 │   or add CSP header ("no-JS" mode)  (full threshold is pre-render)    │
 └───────────────────────────────────────────────────────────────────────┘
        │ report
        ▼
 background: tab-state (storage.session) ─► action icon/badge
        │                                  ─► content script (bar, field warnings)
        └─► popup / interstitial (React) via typed, sender-validated messages
```

### 4.1 Shared analyzer (`src/analyzer/`, pure TypeScript with no browser APIs)
- `csp.ts` parses one or more policies, including several CSP headers and comma-joined policies. It computes the effective directive for each fetch type, falling back through `script-src-elem` → `script-src` → `default-src`. It detects nonces, hashes, `'strict-dynamic'`, wildcards, scheme sources and keyword sources. Multiple policies are intersected, so the strictest one wins.
- `headers.ts` handles HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy, COOP/CORP/COEP and `Set-Cookie` flags.
- `findings.ts` is the finding catalogue: id, severity, category, a plain-language "why", a fix for site owners and an MDN link.
- `score.ts` applies the weights and produces the grade and verdict.
- `index.ts` exposes `analyze({url, statusCode, headers}) → Report`.

### 4.2 Chromium enforcement (`src/enforcement/dnr.ts`)
Dynamic rules are rebuilt from settings on `onInstalled` and `onStartup` and whenever settings change.
- **Gate** (priority 1, `redirect`):
  - Conditions: `resourceTypes: ["main_frame"]`, `requestMethods: ["get"]`, `regexFilter: "^https?://.*"`.
  - `excludedResponseHeaders`:
    - `{header:"content-security-policy", values:["*script-src*","*default-src*"]}`
    - `{header:"location"}` to let redirects through
    - `{header:"content-disposition", values:["attachment*"]}` to let downloads through
    - `{header:"content-type", excludedValues:["text/html*","application/xhtml+xml*"]}` to let PDFs, JSON and images through
  - Action: `regexSubstitution: "<runtime.getURL('pages/interstitial.html')>#\\0"`.
- **Trusted/excluded hosts** (priority 10, `allow`, `requestDomains`). The default exclusions are `localhost`, `127.0.0.1`, `[::1]`, `*.localhost` and `*.test`.
- **Per-tab bypass** (session rule, priority 20, `allow`, `requestDomains:[host]`, `tabIds:[tabId]`).
- **No-JS mode** (session rule, priority 30, `modifyHeaders`): appends a response header `Content-Security-Policy: script-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'`. Multiple CSPs are intersected, so appending can only tighten the policy.
- **"Weak and below" threshold (opt-in).** Chrome cannot run the analyzer before render. After the first load, the background therefore:
  1. redirects the tab with `tabs.update`;
  2. installs a *learned* response-stage rule: `requestDomains:[host]` plus `responseHeaders:[{header:"content-security-policy", values:[globEscape(observedValue)]}]`.

  Later visits are blocked before render until the site changes its policy, at which point the rule stops matching and the page is re-graded. The learned rules are kept in an LRU capped at 2,000, below the limit of 5,000 unsafe dynamic rules.
- A non-blocking `webRequest.onHeadersReceived` (`["responseHeaders","extraHeaders"]`) feeds the analyzer. `onBeforeRedirect` records which URL the gate blocked for each tab, so the interstitial never has to trust its own URL hash.

### 4.3 Firefox enforcement (`src/enforcement/webrequest-firefox.ts`)
A blocking `onHeadersReceived` listener for `main_frame` runs the analyzer synchronously, applying the same exclusions (it checks status codes directly).
- If the threshold is met and the host isn't bypassed, it returns `{redirectUrl}`.
- In No-JS mode it returns `{responseHeaders}` with the extra CSP.

Firefox enforces every threshold before render. MV3 host permissions are opt-in on Firefox, so onboarding calls `permissions.request({origins:["<all_urls>"]})`. Without that grant the icon shows **Protection off**.

### 4.4 Background (`src/background/`)
- `tab-state.ts` keeps pending and committed reports per tab in `storage.session`, because service workers are ephemeral. It promotes the pending report on `webNavigation.onCommitted` (frameId 0). It reuses a cached per-URL report for back/forward-cache restores, and cleans up on `tabs.onRemoved` and `onReplaced`.
- `icon.ts` sets the per-tab `action.setIcon`, the badge text (the grade) and the title.
- `messages.ts` is a typed router that checks `sender.id` and, for privileged messages, that `sender.url` is one of the extension's own pages. The manifest has no `externally_connectable`.

### 4.5 UI
- **Interstitial** (`pages/interstitial.html` with React from `src/interstitial/`), modelled on the browser's certificate error page:
  - Headline: "This site doesn't protect you from malicious scripts."
  - **Back to safety** is the primary button: `history.back()`, or close the tab if there is nothing to go back to.
  - **Advanced** shows the findings, **Continue without JavaScript**, and **Proceed to ‹host› (unsafe)** with a scope choice: this tab (the default), 24 hours, or always.
  - "Learn more" explains the OPTIMJACK case.
- **Popup**:
  - grade ring and verdict;
  - findings grouped as Script control, Exfiltration, Framing, Transport, Cookies and Other;
  - a raw header viewer;
  - Trust, Revoke trust and Re-check buttons;
  - the note "Analysed locally — nothing leaves your browser".
- **Options**:
  - threshold;
  - trusted sites, with expiry and removal;
  - excluded hosts;
  - default bypass scope;
  - toggles for the warning bar, field warnings and the "re-check unverified pages" fetch;
  - JSON export and import, and reset.
- **Content script** (`src/content/index.ts`; plain TS, isolated world, `document_start`, top frame only):
  - a dismissible warning bar in a closed Shadow DOM;
  - focus warnings on `input[type=password]`, `autocomplete^="cc-"`, and fields whose name or id matches `/card|cvc|cvv|iban|wallet|address/`.

  This is advisory only, since a page can tamper with it. The toolbar icon is the indicator users can trust.

## 5. Project layout and manifest

```
dont-trust-me/
  package.json  tsconfig.json  vitest.config.ts  playwright.config.ts
  manifest.json                     # wherever the template puts it (root or src/)
  pages/interstitial.html           # Extension.js special folder → dist/<browser>/pages/interstitial.html
  public/icons/{secure,partial,weak,not-secure,unknown,off}-{16,32,48,128}.png
  src/
    analyzer/{csp,headers,findings,score,policy,index}.ts
    enforcement/{dnr,webrequest-firefox,index}.ts
    background/{index,tab-state,icon,messages}.ts
    content/index.ts
    interstitial/  popup/  options/  ui/      # React
    shared/{settings,messages,url}.ts
  tests/unit/  tests/fixtures/headers/*.json
  e2e/  e2e/fixture-server.ts
  plans/
```

Manifest sketch. Extension.js prefixes filter keys at build time, and nested prefixes are supported.
```jsonc
{
  "manifest_version": 3,
  "name": "Don't Trust Me",
  "version": "0.1.0",
  "chromium:minimum_chrome_version": "128",
  "chromium:permissions": ["storage", "webRequest", "webNavigation", "declarativeNetRequestWithHostAccess"],
  "firefox:permissions": ["storage", "webRequest", "webRequestBlocking", "webNavigation"],
  "host_permissions": ["<all_urls>"],
  "background": { "service_worker": "src/background/index.ts" },
  "action": { "default_popup": "src/popup/index.html", "default_icon": { "32": "icons/unknown-32.png" } },
  "options_ui": { "page": "src/options/index.html", "open_in_tab": true },
  "content_scripts": [{ "matches": ["http://*/*", "https://*/*"], "js": ["src/content/index.ts"], "run_at": "document_start" }],
  "web_accessible_resources": [{ "resources": ["pages/interstitial.html"], "matches": ["<all_urls>"], "use_dynamic_url": true }],
  "firefox:browser_specific_settings": { "gecko": { "id": "dont-trust-me@<your-domain>", "strict_min_version": "128.0" } }
}
```

## 6. Phases

### Phase 0: Spike (validate platform assumptions before building)
Build a throwaway extension in `spike/` and record the results in `plans/spike-notes.md`:
1. The DNR gate with `excludedResponseHeaders` redirects to the extension page (`use_dynamic_url`), **and the blocked page's scripts never run**. Test this with a fixture page that sends a beacon.
2. The semantics of the `location`, `content-disposition` and `content-type excludedValues` exclusions, and of multiple CSP headers.
3. A session `allow` rule with `tabIds` suppresses the response-stage redirect, and a higher-priority `modifyHeaders` (append CSP) still applies.
4. `webRequest.onBeforeRedirect` sees the DNR redirect, and `extraHeaders` exposes `Set-Cookie`.
5. Extension.js: nested prefixes, the `pages/` output path matches the web-accessible resource, and the same source builds for Firefox.
6. Firefox: a blocking redirect to a `moz-extension:` page works from an MV3 event page, and the host-permission prompt flow works.

**Exit:** the rule shapes in §4.2 are confirmed or corrected.

### Phase 1: MVP (v1)
1. **Scaffold.** Run `npx extension@latest create` with `--template=react` (check `extension create --help` for in-place creation or a TS variant). Add `@types/chrome`, Vitest, Playwright and ESLint (`no-unsanitized` and React rules).
2. **Analyzer first, test-driven.** Write the CSP parser, the header checks and scoring against fixtures (§9) before any browser code.
3. **Background.** Tab state, the observer listener, the icon and badge, and the message router.
4. **Enforcement.** The DNR rules and bypass and No-JS session rules; the Firefox blocking listener. `enforcement/index.ts` picks the path from `runtime.getURL('')` (`moz-extension:` means Firefox).
5. **Interstitial**, then the **popup**, then **options** with settings-to-rule synchronisation.
6. **Content script** warnings.
7. **Icons** for six states, with colour-blind-safe shapes as well as colours (✓ / ! / ✕ / ?).
8. **Packaging.** `extension build --browser=chrome,firefox --zip`, `web-ext lint` on the Firefox output, and store-listing permission justifications for `<all_urls>`, DNR and webRequest.

### Phase 2: Runtime monitor (headers aren't enough against a compromised trusted vendor)
- An inventory of third-party scripts per page (MutationObserver plus `PerformanceObserver('resource')`), with SRI presence on cross-origin scripts.
- Trust-on-first-use baselines per site. Alert when a **new script origin or outbound connection domain** appears (OPTIMJACK's `1688360.cc`).
- Detect hidden zero-size or off-screen cross-origin iframes, and scripts created from `atob`-decoded URLs (a small MAIN-world hook).
- A bundled static DNR blocklist of known indicators (`1688360.cc`, `webshell.lol`), updated only through extension releases.
- Optional "Protected mode", which applies a user-side CSP (`connect-src`/`frame-src`) generated from the learned baseline.

### Phase 3: Later
Subframe grading, a Safari build (monitor-only), enterprise `storage.managed` policies (force-installed Chrome can use blocking webRequest), internationalisation, an accessibility audit and per-site history.

## 7. The extension's own security
- Extension pages use the strict default CSP (`script-src 'self'; object-src 'self'`). There is no remote code, `eval` or `dangerouslySetInnerHTML`. Header values are untrusted input and are rendered as text only.
- The "Proceed" target comes from the background's record of the blocked navigation, not the URL hash. It is parsed with `URL` and only `http:`/`https:` are allowed, which blocks `javascript:` injection.
- Privileged messages (bypass, trust, settings) are accepted only from extension pages, checked through `sender.url`. The content script can only *receive* verdicts.
- `use_dynamic_url` on the interstitial reduces fingerprinting and framing of the warning page.
- Minimal dependencies, a lockfile and `npm audit` in CI.

## 8. Edge cases and known limitations
- **CSP set through `<meta>`.** The gate only sees headers, so such sites get the interstitial. This is by design: a meta policy can't set `frame-ancestors`, `sandbox` or reporting. The interstitial says so, and the user can trust the site.
- **The request still reaches the server.** The gate acts on the response, so the server receives the request (and its cookies). What the gate prevents is rendering and script execution.
- **Pages served from a service worker cache or the back/forward cache** never reach the network layer. They show as Unverified (or reuse a cached report). An optional re-check sends one `fetch(url, {credentials:"omit", cache:"no-store"})` to the same site.
- **POST navigations aren't gated**, to avoid re-submitting forms. They are still graded and badged.
- **Chromium "Weak" threshold** works before render only from the second visit, through learned rules.
- **Expect many interstitials at first**, because most of the web sends no script-governing CSP. The "this tab" and "always" trust options and the No-JS mode keep that usable.
- **Headers measure policy, not behaviour.** An A-graded site can still be compromised through an allowlisted vendor. Phase 2 addresses this.

## 9. Verification
- **Unit tests (Vitest)** cover the CSP parser (multiple policies, fallback chains, nonce/hash/`strict-dynamic` handling) and scoring tables over `tests/fixtures/headers/*.json`. Fixtures to include:
  - `none`
  - `report-only`
  - `frame-ancestors-only`
  - `upgrade-insecure-only`
  - `optimjack-allowlist`: `script-src 'self' cdn.optimizely.com 'unsafe-inline'` with no `connect-src`, which must be **Weak**
  - `optimjack-hardened`: nonce with `'strict-dynamic'`, `connect-src 'self'`, `frame-src 'none'` and `report-to`, which must be **A or better**
  - `http`
- **E2E (Playwright, Chromium)** loads the built extension from Extension.js `ready.json` `distPath` (`launchPersistentContext`, `--load-extension`). It uses a local HTTPS fixture server (self-signed, `--ignore-certificate-errors`, `--host-resolver-rules="MAP *.dtm.example 127.0.0.1"`). Assertions:
  - `/no-csp` lands on the interstitial and the fixture server **never receives the page's beacon** (proves the block happens before render);
  - Proceed → the page loads, the badge shows F and the warning bar appears;
  - No-JS → the page loads and no beacon arrives;
  - a 301 to `/strict` loads normally with no interstitial;
  - `/download` and `/data.json` are not intercepted;
  - `/strict` gets a green badge and grade A or better;
  - trusting a site via the options page removes the interstitial on the next visit.
- **Firefox:** `npx extension dev --browser=firefox` against the same fixture server, following a manual checklist that mirrors the E2E cases, plus `web-ext lint`.
- **Manual smoke test:** a few real sites with strict CSP and with none. Confirm no interstitials appear during normal redirects or downloads, or on the extension's own pages.

## 10. References
- OPTIMJACK coverage: [Help Net Security](https://www.helpnetsecurity.com/2026/11/17/optimizely-vulnerability-malicious-javascript/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/optimizely-supply-chain-attack-delivers-malware-to-cnn-fox-news-bbc-salesforce-sites/), [matt.security write-up](https://www.matt.security/blog/optimjack-optimizely-supply-chain-attack)
- Extension.js: [docs](https://extension.js.org/docs.md), [special folders](https://extension.js.org/docs/features/special-folders.md), [manifest and prefixes](https://extension.js.org/docs/implementation-guide/manifest-json.md), [Playwright E2E](https://extension.js.org/docs/workflows/playwright-e2e.md)
- Chrome [declarativeNetRequest](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest) (response-header conditions, Chrome 128+); MDN [DNR RuleCondition](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/declarativeNetRequest/RuleCondition)
