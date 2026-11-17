// Automated Firefox check for the gate (mirrors e2e/gate.spec.ts).
// Playwright's Firefox can't load extensions, so this drives the system Firefox over
// WebDriver BiDi with puppeteer-core and installs dist/firefox as a temporary add-on.
//
//   npm run build:firefox && npm run e2e:firefox
//   FIREFOX_BIN=/path/to/firefox npm run e2e:firefox   # override the binary
//
// Requires Firefox >= 140. Host names resolve to 127.0.0.1 via network.dns.localDomains.

import { resolve } from 'node:path'
import { existsSync } from 'node:fs'
import puppeteer, { type Browser, type Page } from 'puppeteer-core'
import { startFixtureServer, type FixtureServer } from '../fixture-server.ts'

const ROOT = resolve(import.meta.dirname, '../..')
const DIST = resolve(ROOT, 'dist/firefox')
const HOST = 'site.dtm.example'
const FIREFOX = process.env.FIREFOX_BIN ?? '/usr/bin/firefox'
const NEGATIVE_WINDOW_MS = 1000

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

async function waitFor<T>(fn: () => Promise<T> | T, ok: (v: T) => boolean, what: string, timeout = 10_000): Promise<T> {
  const end = Date.now() + timeout
  let last: T | undefined
  while (Date.now() < end) {
    try {
      last = await fn()
      if (ok(last)) return last
    } catch {
      /* page may be mid-navigation */
    }
    await sleep(100)
  }
  throw new Error(`Timed out waiting for ${what} (last: ${JSON.stringify(last)})`)
}

const isInterstitial = (u: string) => u.startsWith('moz-extension://') && u.includes('/pages/interstitial.html')

// WebDriver BiDi doesn't report navigations into moz-extension: pages (page.url() stays
// about:blank), so read the URL from inside the document. That needs system access.
const currentUrl = (page: Page): Promise<string> =>
  page.evaluate(() => document.URL).catch(() => page.url())

async function go(page: Page, url: string): Promise<void> {
  // A gated navigation never "completes" from BiDi's point of view; don't wait long for it.
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 3_000 }).catch(() => {})
}

async function clickText(page: Page, re: RegExp): Promise<void> {
  const clicked = await waitFor(
    () =>
      page.evaluate((src: string, flags: string) => {
        const rx = new RegExp(src, flags)
        const el = [...document.querySelectorAll<HTMLElement>('button, a, summary')].find((e) => rx.test(e.textContent ?? ''))
        if (!el) return false
        el.click()
        return true
      }, re.source, re.flags),
    Boolean,
    `clickable ${re}`,
  )
  if (!clicked) throw new Error(`No element for ${re}`)
}

const headingText = (page: Page) => page.evaluate(() => document.getElementById('h')?.textContent ?? null)

interface Ctx {
  browser: Browser
  server: FixtureServer
  url: (p: string) => string
  extOrigin?: string
}

/** Runs code in an extension page (options) so it can use chrome.storage / permissions. */
async function inExtension<T>(ctx: Ctx, fn: string): Promise<T> {
  if (!ctx.extOrigin) throw new Error('extension origin unknown yet')
  const p = await ctx.browser.newPage()
  try {
    const target = `${ctx.extOrigin}/options/index.html`
    await p.goto(target, { timeout: 3_000 }).catch(() => {}) // moz-extension: loads aren't reported
    await waitFor(() => p.evaluate(() => document.readyState === 'complete' && !!chrome?.storage).catch(() => false), Boolean, 'options page')
    return (await p.evaluate(`(async () => { ${fn} })()`)) as T
  } finally {
    await p.close()
  }
}

async function resetSettings(ctx: Ctx) {
  if (ctx.extOrigin) await inExtension(ctx, `await chrome.storage.local.remove('settings')`)
  await sleep(200)
  ctx.server.reset()
}

type Case = [name: string, fn: (ctx: Ctx, page: Page) => Promise<void>]

const cases: Case[] = [
  ['no-csp is gated before render (no beacon)', async (ctx, page) => {
    await go(page, ctx.url('/no-csp'))
    await waitFor(() => currentUrl(page), isInterstitial, 'interstitial')
    // URL#origin is 'null' for moz-extension: in Node; take scheme://host by hand.
    ctx.extOrigin ??= (await currentUrl(page)).split('/').slice(0, 3).join('/')
    await sleep(NEGATIVE_WINDOW_MS)
    if (ctx.server.hits('no-csp') + ctx.server.hits('no-csp-fetch') !== 0) throw new Error('blocked page ran its scripts')
  }],
  ['/frame-ancestors-only is gated', async (ctx, page) => {
    await go(page, ctx.url('/frame-ancestors-only'))
    await waitFor(() => currentUrl(page), isInterstitial, 'interstitial')
  }],
  ['/report-only is gated', async (ctx, page) => {
    await go(page, ctx.url('/report-only'))
    await waitFor(() => currentUrl(page), isInterstitial, 'interstitial')
  }],
  ['strict loads normally and runs scripts', async (ctx, page) => {
    await go(page, ctx.url('/strict'))
    await waitFor(() => headingText(page), (t) => t === 'strict', 'strict heading')
    await waitFor(() => ctx.server.hits('strict'), (n) => n > 0, 'strict beacon')
  }],
  ['weak loads (not gated under default threshold)', async (ctx, page) => {
    await go(page, ctx.url('/weak'))
    await waitFor(() => headingText(page), (t) => t === 'weak', 'weak heading')
    if (isInterstitial(await currentUrl(page))) throw new Error('weak was gated under default threshold')
  }],
  ['301 redirect to strict ends on strict', async (ctx, page) => {
    await go(page, ctx.url('/redirect'))
    await waitFor(() => headingText(page), (t) => t === 'strict', 'strict heading after redirect')
  }],
  ['json is not gated', async (ctx, page) => {
    await go(page, ctx.url('/data.json'))
    await sleep(500)
    if (isInterstitial(await currentUrl(page))) throw new Error('json was gated')
  }],
  ['Proceed (unsafe) loads the page and runs its scripts', async (ctx, page) => {
    await go(page, ctx.url('/no-csp'))
    await waitFor(() => currentUrl(page), isInterstitial, 'interstitial')
    await clickText(page, /advanced/i)
    await clickText(page, /Proceed to .*\(unsafe\)/i)
    await waitFor(() => headingText(page), (t) => t === 'no-csp', 'no-csp heading')
    await waitFor(() => ctx.server.hits('no-csp'), (n) => n > 0, 'no-csp beacon')
  }],
  ['Continue without JavaScript loads the page but no beacon', async (ctx, page) => {
    await go(page, ctx.url('/no-csp'))
    await waitFor(() => currentUrl(page), isInterstitial, 'interstitial')
    await clickText(page, /advanced/i)
    await clickText(page, /Continue without JavaScript/i)
    await waitFor(() => headingText(page), (t) => t === 'no-csp', 'no-csp heading')
    await sleep(NEGATIVE_WINDOW_MS)
    if (ctx.server.hits('no-csp') + ctx.server.hits('no-csp-fetch') !== 0) throw new Error('no-JS page ran its scripts')
  }],
  ['trusted site loads without interstitial', async (ctx, page) => {
    await inExtension(ctx, `await chrome.storage.local.set({ settings: { trustedSites: [{ host: '${HOST}', addedAt: Date.now() }] } })`)
    await sleep(300)
    await go(page, ctx.url('/no-csp'))
    await waitFor(() => headingText(page), (t) => t === 'no-csp', 'no-csp heading')
    await waitFor(() => ctx.server.hits('no-csp'), (n) => n > 0, 'no-csp beacon')
  }],
]

async function main() {
  if (!existsSync(resolve(DIST, 'manifest.json'))) throw new Error(`No build at ${DIST}; run npm run build:firefox`)
  const server = await startFixtureServer()
  const browser = await puppeteer.launch({
    browser: 'firefox',
    executablePath: FIREFOX,
    headless: process.env.HEADED ? false : true,
    acceptInsecureCerts: true,
    env: { ...process.env, MOZ_REMOTE_ALLOW_SYSTEM_ACCESS: '1' },
    extraPrefsFirefox: {
      'network.dns.localDomains': HOST,
      // Grant MV3 host permissions at install, as a user accepting the onboarding prompt would.
      'extensions.originControls.grantByDefault': true,
    },
  })
  const ctx: Ctx = { browser, server, url: (p) => `https://${HOST}:${server.port}${p}` }
  let failed = 0
  try {
    const id = await browser.installExtension(DIST)
    console.log(`Installed temporary add-on ${id} into ${(await browser.version())}`)
    await sleep(1000)
    for (const [name, fn] of cases) {
      await resetSettings(ctx)
      const page = await browser.newPage()
      const t0 = Date.now()
      try {
        await fn(ctx, page)
        console.log(`  ✓ ${name} (${Date.now() - t0}ms)`)
      } catch (e) {
        failed++
        console.log(`  ✘ ${name}\n      ${(e as Error).message}\n      at ${await currentUrl(page)}`)
      } finally {
        await page.close().catch(() => {})
      }
    }
  } finally {
    await browser.close().catch(() => {})
    server.close()
  }
  console.log(failed ? `${failed} failed` : `${cases.length} passed`)
  process.exit(failed ? 1 : 0)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
