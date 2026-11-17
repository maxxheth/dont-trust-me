import { test as base, chromium, type BrowserContext, type Page, type Worker } from '@playwright/test'
import { execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { startFixtureServer, type FixtureServer } from './fixture-server'

const ROOT = resolve(process.cwd())
const DIST = resolve(ROOT, 'dist/chrome')

export interface Ext {
  id: string
  sw: Worker
  setSettings(partial: Record<string, unknown>): Promise<void>
  /** Badge text of the tab whose URL starts with `urlPrefix`. */
  badgeText(urlPrefix: string): Promise<string>
}

interface WorkerFixtures {
  server: FixtureServer
  extContext: BrowserContext
  ext: Ext
}
interface TestFixtures {
  page: Page
  /** Builds a URL on the fixture server under a non-excluded hostname. */
  siteUrl: (path: string, host?: string) => string
}

export const test = base.extend<TestFixtures, WorkerFixtures>({
  server: [
    async ({}, use) => {
      const s = await startFixtureServer()
      await use(s)
      await s.close()
    },
    { scope: 'worker' },
  ],

  extContext: [
    async ({}, use) => {
      execFileSync('npx', ['extension', 'build', '--browser=chrome', '--no-telemetry'], {
        cwd: ROOT,
        stdio: 'inherit',
      })
      if (!existsSync(resolve(DIST, 'manifest.json'))) throw new Error(`Build produced no manifest at ${DIST}`)
      const context = await chromium.launchPersistentContext('', {
        headless: false,
        args: [
          '--headless=new',
          `--disable-extensions-except=${DIST}`,
          `--load-extension=${DIST}`,
          '--ignore-certificate-errors',
          '--host-resolver-rules=MAP *.dtm.example 127.0.0.1',
        ],
      })
      await use(context)
      await context.close()
    },
    { scope: 'worker' },
  ],

  ext: [
    async ({ extContext }, use) => {
      let sw = extContext.serviceWorkers()[0]
      if (!sw) sw = await extContext.waitForEvent('serviceworker')
      const id = new URL(sw.url()).host
      const ext: Ext = {
        id,
        sw,
        async setSettings(partial) {
          await sw.evaluate(async (p) => {
            const cur = (await chrome.storage.local.get('settings')).settings ?? {}
            await chrome.storage.local.set({ settings: { ...cur, ...p } })
          }, partial)
        },
        async badgeText(urlPrefix) {
          return sw.evaluate(async (prefix) => {
            const tabs = await chrome.tabs.query({})
            const tab = tabs.find((t) => t.url?.startsWith(prefix))
            return tab?.id === undefined ? '' : chrome.action.getBadgeText({ tabId: tab.id })
          }, urlPrefix)
        },
      }
      await use(ext)
    },
    { scope: 'worker' },
  ],

  page: async ({ extContext, ext, server }, use) => {
    // Reset per-test state: default settings, no recorded beacons.
    await ext.sw.evaluate(() => chrome.storage.local.remove('settings'))
    server.reset()
    const page = await extContext.newPage()
    await use(page)
    await page.close()
  },

  siteUrl: async ({ server }, use) => {
    await use((path, host = 'site.dtm.example') => `https://${host}:${server.port}${path}`)
  },
})

export { expect } from '@playwright/test'
