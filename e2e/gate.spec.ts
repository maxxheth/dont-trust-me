import { test, expect } from './fixtures'
import type { Page } from '@playwright/test'

const INTERSTITIAL = /\/pages\/interstitial\.html/
const isInterstitial = (page: Page) => INTERSTITIAL.test(page.url()) && page.url().startsWith('chrome-extension://')

// Navigations to a blocked page may abort/redirect mid-flight; ignore that error.
async function go(page: Page, url: string) {
  await page.goto(url, { waitUntil: 'commit' }).catch(() => {})
}

async function gotoInterstitial(page: Page, url: string) {
  await go(page, url)
  await page.waitForURL((u) => u.protocol === 'chrome-extension:' && INTERSTITIAL.test(u.pathname))
}

const NEGATIVE_WINDOW_MS = 1000

test.describe('gate (Chromium)', () => {
  test('no-csp is gated before render (no beacon)', async ({ page, server, siteUrl }) => {
    await gotoInterstitial(page, siteUrl('/no-csp'))
    expect(page.url().startsWith('chrome-extension://')).toBe(true)
    await page.waitForTimeout(NEGATIVE_WINDOW_MS)
    expect(server.hits('no-csp')).toBe(0)
    expect(server.hits('no-csp-fetch')).toBe(0)
  })

  for (const path of ['/frame-ancestors-only', '/report-only']) {
    test(`${path} is gated`, async ({ page, server, siteUrl }) => {
      await gotoInterstitial(page, siteUrl(path))
      await page.waitForTimeout(NEGATIVE_WINDOW_MS)
      expect(server.hits(path.slice(1))).toBe(0)
    })
  }

  test('strict loads normally with grade A', async ({ page, server, siteUrl, ext }) => {
    const url = siteUrl('/strict')
    await page.goto(url)
    expect(isInterstitial(page)).toBe(false)
    await expect.poll(() => server.hits('strict')).toBeGreaterThan(0)
    await expect.poll(() => ext.badgeText(url)).toMatch(/^A/)
  })

  test('weak loads (not gated) with a non-A grade', async ({ page, server, siteUrl, ext }) => {
    const url = siteUrl('/weak')
    await page.goto(url)
    expect(isInterstitial(page)).toBe(false)
    await expect.poll(() => server.hits('weak')).toBeGreaterThan(0)
    await expect.poll(() => ext.badgeText(url)).toMatch(/^\S/)
    expect(await ext.badgeText(url)).not.toMatch(/^A/)
  })

  test('301 redirect to strict ends on strict without interstitial', async ({ page, server, siteUrl }) => {
    await page.goto(siteUrl('/redirect'))
    await expect.poll(() => new URL(page.url()).pathname).toBe('/strict')
    expect(isInterstitial(page)).toBe(false)
    await expect.poll(() => server.hits('strict')).toBeGreaterThan(0)
  })

  test('download is not gated', async ({ page, siteUrl }) => {
    const download = page.waitForEvent('download', { timeout: 10_000 })
    await go(page, siteUrl('/download'))
    const d = await download
    expect(d.suggestedFilename()).toBe('x.txt')
    expect(isInterstitial(page)).toBe(false)
  })

  test('json is not gated', async ({ page, siteUrl }) => {
    await page.goto(siteUrl('/data.json'))
    expect(isInterstitial(page)).toBe(false)
    await expect(page.locator('body')).toContainText('"ok":true')
  })

  test('Proceed (unsafe) loads the page and runs its scripts', async ({ page, server, siteUrl }) => {
    const url = siteUrl('/no-csp')
    await gotoInterstitial(page, url)
    await page.getByRole('button', { name: /advanced/i }).click()
    await page.getByText(/Proceed to .*\(unsafe\)/i).click()
    await page.waitForURL(url)
    await expect(page.locator('#h')).toHaveText('no-csp')
    await expect.poll(() => server.hits('no-csp')).toBeGreaterThan(0)
  })

  test('Continue without JavaScript loads the page but no beacon', async ({ page, server, siteUrl }) => {
    const url = siteUrl('/no-csp')
    await gotoInterstitial(page, url)
    await page.getByRole('button', { name: /advanced/i }).click()
    await page.getByText(/Continue without JavaScript/i).click()
    await page.waitForURL(url)
    await expect(page.locator('#h')).toHaveText('no-csp')
    await page.waitForTimeout(NEGATIVE_WINDOW_MS)
    expect(server.hits('no-csp')).toBe(0)
    expect(server.hits('no-csp-fetch')).toBe(0)
  })

  test('trusted site loads without interstitial', async ({ page, server, siteUrl, ext }) => {
    await ext.setSettings({
      trustedSites: [{ host: 'site.dtm.example', addedAt: Date.now() }],
    })
    // Settings apply asynchronously (storage.onChanged -> DNR rebuild); wait for the allow rule.
    await expect
      .poll(() =>
        ext.sw.evaluate(async () =>
          (await chrome.declarativeNetRequest.getDynamicRules()).some((r) =>
            r.condition.requestDomains?.includes('site.dtm.example'),
          ),
        ),
      )
      .toBe(true)
    await page.goto(siteUrl('/no-csp'))
    expect(isInterstitial(page)).toBe(false)
    await expect(page.locator('#h')).toHaveText('no-csp')
    await expect.poll(() => server.hits('no-csp')).toBeGreaterThan(0)
  })
})
