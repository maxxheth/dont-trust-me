# Phase 0 spike notes

Verified on 2026-11-17 against Playwright's Chromium build (chromium-1255) with Extension.js 4.1.41. The
E2E suite in `e2e/gate.spec.ts` (11 tests) is the executable record of these results.

## Confirmed in Chromium

| Plan assumption (§4.2) | Result |
|---|---|
| A DNR `redirect` with `excludedResponseHeaders` blocks a response before render | **Confirmed.** A `/no-csp` page's inline `sendBeacon` and `fetch` never reach the server. |
| A CSP that sets only `frame-ancestors`, or only Report-Only, is still gated (`values: ["*script-src*","*default-src*"]`) | **Confirmed** |
| `{header:"location"}` exclusion lets 3xx redirects through | **Confirmed** (a 301 to `/strict` loads) |
| `content-disposition: attachment*` and `content-type excludedValues` exclusions | **Confirmed** (download and JSON not gated) |
| A session `allow` rule with `tabIds` overrides the response-stage redirect | **Confirmed** (Proceed works) |
| A higher-priority `modifyHeaders` rule that appends a CSP still applies alongside the allow rule | **Confirmed** (no-JS mode: page loads, no beacon) |
| `webRequest.onBeforeRedirect` sees the DNR redirect | **Confirmed** |
| Extension.js `pages/` folder → `pages/interstitial.html`; nested prefixes (`background.chromium:service_worker`, `chromium:use_dynamic_url`) | **Confirmed** |

## Surprises (fixed)

1. **With `use_dynamic_url`, the redirect target's origin isn't the one you might expect.**
   - `runtime.getURL('pages/interstitial.html')` returns the per-session dynamic origin.
   - Pages reached through the DNR redirect run under the **static** `chrome-extension://<id>` origin.
   - Fix: `isInterstitialUrl()` in `src/enforcement/env.ts` accepts exactly those two origins. Sender checks for privileged messages in `src/background/messages.ts` accept the same two.
2. **A ReferenceError while the service worker script first runs** (a `let` touched by top-level `boot()` before its declaration) makes Chrome treat the worker script as failed. Events such as `storage.onChanged` then stop being dispatched to the worker, although `worker.evaluate` still works. As a result no DNR rules were installed at all.
   - Fix: declare the variable before the call.
   - Rule: nothing at top level may run before the declarations it touches.

## Not yet verified

## Confirmed in Firefox 160

`npm run e2e:firefox` (`e2e/firefox/run.ts`) installs `dist/firefox` as a temporary add-on in the system Firefox. It drives Firefox over WebDriver BiDi using `puppeteer-core`, because Playwright's Firefox can't load extensions. All 10 cases pass, two runs in a row:
- Blocking before render works: no beacon is sent and the tab lands on `moz-extension://…/pages/interstitial.html`.
- The pass-through cases (301, JSON, strict, weak) load normally.
- Proceed, no-JS mode and trusted sites work.

Harness notes:
- WebDriver BiDi doesn't report navigations into `moz-extension:` pages; `page.url()` stays `about:blank`. Reading `document.URL` from inside the tab needs `MOZ_REMOTE_ALLOW_SYSTEM_ACCESS=1`.
- Host permissions are granted with `extensions.originControls.grantByDefault`, standing in for the user accepting the onboarding prompt. The real prompt flow is still in `e2e/FIREFOX-CHECKLIST.md`.
- Extension.js's bundled addons-linter flags `data_collection_permissions` as "reserved", but the current `web-ext lint` doesn't. `strict_min_version` was raised to 140, where the key is supported.

## Not yet verified (both browsers)

- Firefox download pass-through, the toolbar badge, and the warning bar. These are covered only in Chromium, or not at all.
- **"Weak and below" threshold learned rules** (`responseHeaders` value match with `extensionPath` redirect) have no E2E test yet.
- **Multiple CSP headers against DNR `values` globs.** Not tested in the browser; the analyzer side is unit-tested.
- **Service-worker-cached or back/forward-cache pages showing as "Unverified".** Not exercised.
