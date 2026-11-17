# Status

Progress against [dont-trust-me-extension.md](dont-trust-me-extension.md). [spike-notes.md](spike-notes.md) has the evidence for what's verified.

_Last updated 2026-11-17, at commit `2e168d5`._

**Legend:** ✅ done and verified · 🟡 done but not fully verified, or partly done · ⬜ not started

| Phase | Status |
|---|---|
| 0 · Spike | ✅ Done. Chromium and Firefox behaviour confirmed (see spike notes). |
| 1 · MVP | 🟡 Built and committed. The items below are still open. |
| 2 · Runtime monitor | ⬜ Not started |
| 3 · Later | ⬜ Not started |

## Phase 1: MVP

| # | Item (plan §6) | Status | Notes |
|---|---|---|---|
| 1 | Scaffold and tooling | 🟡 | React template, `@types/chrome`, Vitest and Playwright are in. **ESLint (`no-unsanitized` and React rules) has not been added.** |
| 2 | Analyzer, test-driven | ✅ | 41 unit tests over 10 header fixtures. Fails closed on internal errors. |
| 3 | Background: tab state, icon, badge, message router | ✅ | Badge grades are checked in the Chromium E2E tests. |
| 4 | Enforcement | 🟡 | Verified by 11 Chromium and 10 Firefox E2E cases. **Not covered by tests:** the opt-in "Weak and below" threshold with its learned rules, multiple CSP headers against DNR globs, and the Unverified state for pages served from cache. |
| 5 | Interstitial, popup, options | 🟡 | The interstitial is checked by E2E tests and a screenshot. **The popup and options page have only been built, not checked in a browser.** |
| 6 | Content-script warnings | 🟡 | The warning bar shows on Weak pages (Chromium screenshot). **It covers the top of the page instead of pushing it down. Sensitive-field warnings are untested.** |
| 7 | Icons | 🟡 | Per-tab state icons are drawn at runtime. **The packaged icons in `src/images/` are still the Extension.js template's.** |
| 8 | Packaging | 🟡 | Chrome and Firefox builds succeed and `web-ext lint` passes (warnings only, all in React's bundled code). **`npm run package` (zip) hasn't been run. Store-listing justifications for `<all_urls>`, DNR and webRequest haven't been written.** |

### Other open items
- **Firefox:** the download pass-through, toolbar badge and warning bar aren't covered by the automated suite. The real host-permission prompt still needs the manual run in [`e2e/FIREFOX-CHECKLIST.md`](../e2e/FIREFOX-CHECKLIST.md).
- **Supply chain (§7):** there's no CI yet, so `npm audit` doesn't run automatically. `npm install` reports advisories that haven't been reviewed.

## Phase 2: Runtime monitor (⬜)
- [ ] An inventory of third-party scripts on each page, with SRI presence on cross-origin scripts
- [ ] Per-site trust-on-first-use baselines, with alerts for new script origins or outbound connection domains
- [ ] Detection of hidden cross-origin iframes and of scripts loaded from `atob`-decoded URLs
- [ ] A bundled static DNR blocklist of known indicators (`1688360.cc`, `webshell.lol`)
- [ ] Optional "Protected mode": a user-side CSP built from the learned baseline

## Phase 3: Later (⬜)
- [ ] Grading embedded frames (subframes)
- [ ] A Safari build (monitor-only)
- [ ] Enterprise policies through `storage.managed`
- [ ] Internationalisation
- [ ] Accessibility audit
- [ ] Per-site grade history

## How to verify
```bash
npm test               # unit tests
npm run typecheck
npm run e2e            # Chromium (builds first)
npm run e2e:firefox    # Firefox 140+ at /usr/bin/firefox, or set FIREFOX_BIN
```
