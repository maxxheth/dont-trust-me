// Firefox enforcement: a blocking webRequest.onHeadersReceived that analyses each main-frame
// response before render and either redirects to the interstitial or appends the no-JS CSP.
// Bypass state lives in memory (mirrored to storage.session) because the listener must be synchronous.

import { getSettings, peekSettings } from '../background/settings-store'
import { observeResponse, recordBlocked } from '../background/tab-state'
import { activeTrustedHosts, hostMatches, type Settings } from '../shared/settings'
import type { Report } from '../shared/types'
import { hostOf } from '../shared/url'
import { headerValue, interstitialUrl, NO_JS_CSP } from './env'

interface Bypass {
  host: string
  mode: 'unsafe' | 'no-js'
}

const BYPASS_KEY = 'ff:bypass'
const bypasses = new Map<number, Bypass>()
let readyPromise: Promise<void> | null = null
let ready = false

function persist(): void {
  const obj: Record<string, Bypass> = {}
  for (const [k, v] of bypasses) obj[String(k)] = v
  void chrome.storage.session.set({ [BYPASS_KEY]: obj }).catch(() => undefined)
}

export function init(): Promise<void> {
  readyPromise ??= (async () => {
    try {
      const r = await chrome.storage.session.get(BYPASS_KEY)
      const obj = r[BYPASS_KEY] as Record<string, Bypass> | undefined
      if (obj) for (const [k, v] of Object.entries(obj)) if (!bypasses.has(Number(k))) bypasses.set(Number(k), v)
    } catch {
      // memory only
    }
    await getSettings()
    ready = true
  })()
  return readyPromise
}

export function rebuild(_settings: Settings): Promise<void> {
  return Promise.resolve() // settings are read live from the cache on every request
}

export function addBypass(tabId: number, host: string, mode: 'unsafe' | 'no-js'): Promise<void> {
  bypasses.set(tabId, { host, mode })
  persist()
  return Promise.resolve()
}

export function clearTab(tabId: number): Promise<void> {
  if (bypasses.delete(tabId)) persist()
  return Promise.resolve()
}

function meetsThreshold(settings: Settings, report: Report): boolean {
  if (settings.threshold === 'never') return false
  if (settings.threshold === 'weak') return report.verdict === 'not-secure' || report.verdict === 'weak'
  return report.verdict === 'not-secure'
}

function isHtml(contentType: string | undefined): boolean {
  if (!contentType) return true // browsers may sniff HTML from an untyped response
  const t = contentType.trim().toLowerCase()
  return t.startsWith('text/html') || t.startsWith('application/xhtml+xml')
}

function handle(d: chrome.webRequest.WebResponseHeadersDetails, settings: Settings): chrome.webRequest.BlockingResponse | undefined {
  // Always grade (feeds tab-state / badge), even for responses we never gate.
  const report = observeResponse({
    tabId: d.tabId,
    requestId: d.requestId,
    url: d.url,
    method: d.method,
    statusCode: d.statusCode,
    responseHeaders: d.responseHeaders,
  })
  if (!report) return undefined // 3xx, non-http, or no tab

  const host = hostOf(d.url)
  const bypass = bypasses.get(d.tabId)
  const bypassed = !!bypass && hostMatches(host, [bypass.host])

  if (bypassed && bypass.mode === 'no-js') {
    return { responseHeaders: [...(d.responseHeaders ?? []), { name: 'Content-Security-Policy', value: NO_JS_CSP }] }
  }
  if (bypassed) return undefined

  if (d.method.toUpperCase() !== 'GET') return undefined
  const cd = headerValue(d.responseHeaders, 'content-disposition')
  if (cd && /^\s*attachment/i.test(cd)) return undefined
  if (!isHtml(headerValue(d.responseHeaders, 'content-type'))) return undefined
  if (hostMatches(host, [...settings.excludedHosts, ...activeTrustedHosts(settings)])) return undefined
  if (!meetsThreshold(settings, report)) return undefined

  void recordBlocked(d.tabId, d.url, report)
  return { redirectUrl: `${interstitialUrl()}#${d.url}` }
}

/** Must be called synchronously at background top level. */
export function registerListeners(): void {
  chrome.webRequest.onHeadersReceived.addListener(
    (d) => {
      if (d.frameId !== 0) return undefined
      const s = peekSettings()
      if (ready && s) return handle(d, s)
      // Event page just woke up: Firefox accepts a Promise from blocking listeners.
      const p: Promise<chrome.webRequest.BlockingResponse | undefined> = init().then(async () => handle(d, await getSettings()))
      return p as unknown as chrome.webRequest.BlockingResponse
    },
    { urls: ['<all_urls>'], types: ['main_frame'] },
    ['blocking', 'responseHeaders'],
  )
}
