// Per-tab state in chrome.storage.session (the service worker is ephemeral). Every record is also
// mirrored in an in-memory map so same-turn reads (and Firefox's synchronous listeners) never race
// the asynchronous storage write.

import { analyze } from '../analyzer'
import { isInterstitialUrl } from '../enforcement/env'
import type { HttpHeader, Report, TabState } from '../shared/types'
import { hostOf, safeHttpUrl } from '../shared/url'

const mem = new Map<string, unknown>()

async function kvGet<T>(key: string): Promise<T | undefined> {
  if (mem.has(key)) return mem.get(key) as T
  try {
    const r = await chrome.storage.session.get(key)
    if (key in r) {
      mem.set(key, r[key])
      return r[key] as T
    }
  } catch {
    // storage.session unavailable: memory only.
  }
  return undefined
}

function kvSet(key: string, value: unknown): Promise<void> {
  mem.set(key, value)
  return chrome.storage.session.set({ [key]: value }).catch(() => undefined)
}

function kvRemove(key: string): Promise<void> {
  mem.delete(key)
  return chrome.storage.session.remove(key).catch(() => undefined)
}

const stripHash = (u: string): string => {
  const i = u.indexOf('#')
  return i < 0 ? u : u.slice(0, i)
}

// ---- Tab state ----------------------------------------------------------------------------

export function getTabState(tabId: number): Promise<TabState | undefined> {
  return kvGet<TabState>(`tab:${tabId}`)
}

export function setTabState(state: TabState): Promise<void> {
  return kvSet(`tab:${state.tabId}`, state)
}

// ---- Pending reports (headers seen, navigation not yet committed) --------------------------

interface Pending {
  url: string
  requestId: string
  method: string
  report: Report
  ts: number
}

const PENDING_MAX_AGE_MS = 5 * 60_000

export interface ObservedResponse {
  tabId: number
  requestId: string
  url: string
  method: string
  statusCode: number
  responseHeaders?: chrome.webRequest.HttpHeader[]
}

/**
 * Analyzes a main-frame response and records it as the tab's pending report.
 * Redirect (3xx) hops are ignored: only the final document is graded.
 */
export function observeResponse(d: ObservedResponse): Report | null {
  if (d.tabId < 0 || !safeHttpUrl(d.url)) return null
  if (d.statusCode >= 300 && d.statusCode < 400) return null
  const headers: HttpHeader[] = (d.responseHeaders ?? []).map((h) => ({ name: h.name, value: h.value }))
  let report: Report
  try {
    report = analyze({ url: d.url, statusCode: d.statusCode, headers })
  } catch {
    return null
  }
  const p: Pending = { url: d.url, requestId: d.requestId, method: d.method, report, ts: Date.now() }
  void kvSet(`pending:${d.tabId}`, p)
  return report
}

async function takePending(tabId: number, url: string): Promise<Pending | undefined> {
  const p = await kvGet<Pending>(`pending:${tabId}`)
  if (!p) return undefined
  if (stripHash(p.url) !== stripHash(url) || Date.now() - p.ts > PENDING_MAX_AGE_MS) return undefined
  await kvRemove(`pending:${tabId}`)
  return p
}

export function peekPending(tabId: number, url: string): Promise<Pending | undefined> {
  return kvGet<Pending>(`pending:${tabId}`).then((p) => (p && stripHash(p.url) === stripHash(url) ? p : undefined))
}

// ---- Blocked navigations (interstitial) -----------------------------------------------------

export interface BlockedRecord {
  url: string
  report?: Report
}

export async function recordBlocked(tabId: number, url: string, report?: Report): Promise<void> {
  if (!safeHttpUrl(url)) return
  const r = report ?? (await peekPending(tabId, url))?.report
  await kvSet(`blocked:${tabId}`, { url, report: r } satisfies BlockedRecord)
}

export function getBlocked(tabId: number): Promise<BlockedRecord | undefined> {
  return kvGet<BlockedRecord>(`blocked:${tabId}`)
}

// ---- Per-tab bypass records -----------------------------------------------------------------

export interface BypassRecord {
  host: string
  mode: 'unsafe' | 'no-js'
}

export function setBypassRecord(tabId: number, rec: BypassRecord): Promise<void> {
  return kvSet(`bypass:${tabId}`, rec)
}

export function getBypassRecord(tabId: number): Promise<BypassRecord | undefined> {
  return kvGet<BypassRecord>(`bypass:${tabId}`)
}

// ---- Per-URL report cache (LRU) for back/forward restores ----------------------------------

const CACHE_KEY = 'reportCache'
const CACHE_MAX = 200
interface CacheEntry {
  url: string
  report: Report
}
let cacheChain: Promise<unknown> = Promise.resolve()

function withCache<T>(fn: (list: CacheEntry[]) => T): Promise<T> {
  const run = async (): Promise<T> => {
    const list = (await kvGet<CacheEntry[]>(CACHE_KEY)) ?? []
    const result = fn(list)
    await kvSet(CACHE_KEY, list)
    return result
  }
  const p = cacheChain.then(run, run)
  cacheChain = p.catch(() => undefined)
  return p
}

export function cacheReport(url: string, report: Report): Promise<void> {
  const key = stripHash(url)
  return withCache((list) => {
    const i = list.findIndex((e) => e.url === key)
    if (i >= 0) list.splice(i, 1)
    list.push({ url: key, report })
    while (list.length > CACHE_MAX) list.shift()
  })
}

export function cachedReport(url: string): Promise<Report | undefined> {
  const key = stripHash(url)
  return withCache((list) => list.find((e) => e.url === key)?.report)
}

// ---- Commit handling ------------------------------------------------------------------------

export interface Promotion {
  state: TabState | null // null: not a tracked page (chrome://, about:, ...)
  method?: string
  isInterstitial: boolean
}

/** Promotes the pending report (or derives a fallback) when a top-level navigation commits. */
export async function promoteOnCommit(
  tabId: number,
  url: string,
  qualifiers: string[],
): Promise<Promotion> {
  if (isInterstitialUrl(url)) {
    const blocked = await getBlocked(tabId)
    const state: TabState = blocked
      ? {
          tabId,
          url: blocked.url,
          verdict: blocked.report?.verdict ?? 'not-secure',
          report: blocked.report,
          blockedUrl: blocked.url,
        }
      : { tabId, url, verdict: 'unverified' }
    await setTabState(state)
    return { state, isInterstitial: true }
  }

  // Any ordinary navigation ends the blocked episode.
  await kvRemove(`blocked:${tabId}`)

  if (!safeHttpUrl(url)) {
    await Promise.all([kvRemove(`tab:${tabId}`), kvRemove(`pending:${tabId}`)])
    return { state: null, isInterstitial: false }
  }

  const bypass = await getBypassRecord(tabId)
  const bypassForHost = bypass && bypass.host === hostOf(url) ? bypass.mode : undefined

  const pending = await takePending(tabId, url)
  let report: Report | undefined = pending?.report
  if (!report && qualifiers.includes('forward_back')) report = await cachedReport(url)

  const state: TabState = report
    ? { tabId, url, verdict: report.verdict, report }
    : { tabId, url, verdict: 'unverified' }
  if (bypassForHost) state.bypass = bypassForHost
  await setTabState(state)
  if (pending) await cacheReport(url, pending.report)
  return { state, method: pending?.method, isInterstitial: false }
}

// ---- Lifecycle ------------------------------------------------------------------------------

export async function clearTabRecords(tabId: number): Promise<void> {
  await Promise.all(
    ['tab', 'pending', 'blocked', 'bypass'].map((p) => kvRemove(`${p}:${tabId}`)),
  )
}

/** Prerender / instant swap: move everything recorded for `removed` onto `added`. */
export async function moveTabRecords(removed: number, added: number): Promise<TabState | undefined> {
  for (const p of ['pending', 'blocked', 'bypass']) {
    const v = await kvGet<unknown>(`${p}:${removed}`)
    if (v !== undefined) await kvSet(`${p}:${added}`, v)
  }
  const st = await getTabState(removed)
  let moved: TabState | undefined
  if (st) {
    moved = { ...st, tabId: added }
    await setTabState(moved)
  }
  await clearTabRecords(removed)
  return moved
}
