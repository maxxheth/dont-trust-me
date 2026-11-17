# Firefox manual checklist

Mirrors `gate.spec.ts`. Run `npm run dev:firefox` (Firefox is at /usr/bin/firefox).

## Setup
- [ ] Start a fixture server. Easiest: write a small script calling `startFixtureServer()` from `e2e/fixture-server.ts` and print `port`. Note it, and the server is HTTPS with a self-signed cert.
- [ ] Add `127.0.0.1 site.dtm.example` to `/etc/hosts` (Firefox has no host-resolver-rules flag), or use `http://127.0.0.1` only for sanity (defaults exclude it from gating).
- [ ] Visit `https://site.dtm.example:<port>/strict` once and accept the certificate warning.
- [ ] Open `about:addons`, find "Don't Trust Me", Permissions tab: grant "Access your data for all websites" (host permission is optional in MV3 Firefox and not granted on install). Alternatively accept the permission prompt on first run.
- [ ] Reset settings: extension options page, "Reset to defaults".

URLs below are `https://site.dtm.example:<port><path>`. "Beacon" means the fixture server's `/beacon?p=...` hit counter (log or inspect `hits()`).

## Cases
- [ ] `/no-csp`: lands on the interstitial (`moz-extension://.../pages/interstitial.html`). Beacons `no-csp` and `no-csp-fetch` are NOT received after ~1s. (Firefox may gate via a blocking webRequest path; note any flash of page content.)
- [ ] `/frame-ancestors-only`: gated.
- [ ] `/report-only`: gated.
- [ ] `/strict`: loads normally, beacon `strict` received, toolbar badge starts with "A".
- [ ] `/weak`: loads (not gated at default threshold), badge shows a non-A grade.
- [ ] `/redirect`: ends on `/strict`, no interstitial.
- [ ] `/download`: download prompt/saves `x.txt`, no interstitial.
- [ ] `/data.json`: JSON viewer shows, no interstitial.
- [ ] Interstitial on `/no-csp`: click "Advanced", then "Proceed to site.dtm.example (unsafe)": page loads, beacon `no-csp` received.
- [ ] Interstitial on `/no-csp` (reset the counter): click "Continue without JavaScript": page loads at `/no-csp`, beacon NOT received.
- [ ] "Back to safety" navigates away from the page without loading it.
- [ ] Options page: add `site.dtm.example` as trusted: `/no-csp` loads without interstitial and beacon received.
- [ ] Extension's own pages (options, popup, interstitial) never get an interstitial.
