// Chromium enforcement: declarativeNetRequest response-stage gate + allow/bypass/no-JS/learned rules.
// See plans/dont-trust-me-extension.md section 4.2.

import { getBypassRecord, observeResponse, peekPending, recordBlocked } from '../background/tab-state'
import { activeTrustedHosts, hostMatches, type Settings } from '../shared/settings'
import type { Report } from '../shared/types'
import { hostOf, INTERSTITIAL_PATH, safeHttpUrl } from '../shared/url'
import { interstitialUrl, isInterstitialUrl, NO_JS_CSP } from './env'

const GATE_ID = 1
const ALLOW_ID = 2
const LEARNED_MIN_ID = 1000
const LEARNED_CAP = 2000
const LEARNED_KEY = 'learnedRules'
const PRIORITY = { gate: 1, allow: 10, bypass: 20, noJs: 30 } as const

// @types/chrome 0.0.287 predates the response-header conditions (Chrome 128), so describe the rule shape here.
interface HeaderInfo {
  header: string
  values?: string[]
  excludedValues?: string[]
}
interface DnrRule {
  id: number
  priority: number
  action: {
    type: 'redirect' | 'allow' | 'modifyHeaders'
    redirect?: { regexSubstitution?: string; extensionPath?: string }
    responseHeaders?: { header: string; operation: 'append'; value: string }[]
  }
  condition: {
    regexFilter?: string
    requestDomains?: string[]
    tabIds?: number[]
    resourceTypes: string[]
    requestMethods?: string[]
    responseHeaders?: HeaderInfo[]
    excludedResponseHeaders?: HeaderInfo[]
  }
}

const dnr = chrome.declarativeNetRequest
const asRules = (r: DnrRule[]): chrome.declarativeNetRequest.Rule[] => r as unknown as chrome.declarativeNetRequest.Rule[]
const fromRules = (r: chrome.declarativeNetRequest.Rule[]): DnrRule[] => r as unknown as DnrRule[]

// Serialise every rule mutation so id allocation and diffing never race.
let chain: Promise<unknown> = Promise.resolve()
function serial<T>(fn: () => Promise<T>): Promise<T> {
  const p = chain.then(fn, fn)
  chain = p.catch(() => undefined)
  return p
}

const PASS_THROUGH_EXCLUSIONS: HeaderInfo[] = [
  { header: 'location' },
  { header: 'content-disposition', values: ['attachment*'] },
  { header: 'content-type', excludedValues: ['text/html*', 'application/xhtml+xml*'] },
]

/** Escapes DNR header-value glob metacharacters (`*`, `?`) and the escape char itself. */
export function globEscape(s: string): string {
  return s.replace(/[\\*?]/g, '\\$&')
}

function gateRule(): DnrRule {
  return {
    id: GATE_ID,
    priority: PRIORITY.gate,
    action: { type: 'redirect', redirect: { regexSubstitution: `${interstitialUrl()}#\\0` } },
    condition: {
      regexFilter: '^https?://.*',
      resourceTypes: ['main_frame'],
      requestMethods: ['get'],
      excludedResponseHeaders: [
        { header: 'content-security-policy', values: ['*script-src*', '*default-src*'] },
        ...PASS_THROUGH_EXCLUSIONS,
      ],
    },
  }
}

function allowRule(settings: Settings): DnrRule | null {
  const hosts = [...new Set([...settings.excludedHosts, ...activeTrustedHosts(settings)])].sort()
  if (!hosts.length) return null
  return { id: ALLOW_ID, priority: PRIORITY.allow, action: { type: 'allow' }, condition: { requestDomains: hosts, resourceTypes: ['main_frame'] } }
}

// ---- Learned rules (threshold 'weak') -------------------------------------------------------

interface Learned {
  id: number
  host: string
  csp: string
  ts: number
}

async function readLearned(): Promise<Learned[]> {
  const r = await chrome.storage.local.get(LEARNED_KEY)
  const v = r[LEARNED_KEY]
  return Array.isArray(v) ? (v as Learned[]) : []
}

// ---- Public API -----------------------------------------------------------------------------

/** Rebuilds gate + allow rules from settings. No-op when the installed rules already match. */
export function rebuild(settings: Settings): Promise<void> {
  return serial(async () => {
    const existing = fromRules(await dnr.getDynamicRules())
    const wantGate = settings.threshold !== 'never'
    const desired: DnrRule[] = []
    if (wantGate) desired.push(gateRule())
    const allow = allowRule(settings)
    if (allow) desired.push(allow)

    const removeIds: number[] = []
    const keep = (id: number) => id !== GATE_ID && id !== ALLOW_ID
    // Learned rules only make sense for the 'weak' threshold.
    const dropLearned = settings.threshold !== 'weak'
    for (const r of existing) if (!keep(r.id) || (dropLearned && r.id >= LEARNED_MIN_ID)) removeIds.push(r.id)
    if (dropLearned) await chrome.storage.local.remove(LEARNED_KEY)

    const current = existing.filter((r) => r.id === GATE_ID || r.id === ALLOW_ID)
    const same = JSON.stringify(current) === JSON.stringify(desired) && removeIds.length === current.length
    if (same) return

    try {
      await dnr.updateDynamicRules({ removeRuleIds: removeIds, addRules: asRules(desired) })
    } catch (err) {
      // An unsupported host form (e.g. an IPv6 literal) makes Chrome reject the whole rule; retry without them.
      const safe = desired.map((r) =>
        r.id === ALLOW_ID && r.condition.requestDomains
          ? { ...r, condition: { ...r.condition, requestDomains: r.condition.requestDomains.filter((h) => !h.includes(':') && !h.includes('[')) } }
          : r,
      ).filter((r) => r.id !== ALLOW_ID || (r.condition.requestDomains?.length ?? 0) > 0)
      console.warn("Don't Trust Me: rule update failed, retrying without IPv6 hosts", err)
      await dnr.updateDynamicRules({ removeRuleIds: removeIds, addRules: asRules(safe) })
    }
  })
}

/** Tab-scoped bypass (and, for 'no-js', the header-appending rule) for one host. */
export function addBypass(tabId: number, host: string, mode: 'unsafe' | 'no-js'): Promise<void> {
  return serial(async () => {
    const existing = fromRules(await dnr.getSessionRules())
    const sameTarget = (r: DnrRule) => r.condition.tabIds?.includes(tabId) && r.condition.requestDomains?.includes(host)
    const removeRuleIds = existing.filter(sameTarget).map((r) => r.id)
    const base = existing.reduce((m, r) => Math.max(m, r.id), 0) + 1
    const condition = { requestDomains: [host], tabIds: [tabId], resourceTypes: ['main_frame'] }
    // The allow rule keeps the gate from firing; for no-js the higher-priority modifyHeaders rule still applies.
    const rules: DnrRule[] = [{ id: base, priority: PRIORITY.bypass, action: { type: 'allow' }, condition }]
    if (mode === 'no-js') {
      rules.push({
        id: base + 1,
        priority: PRIORITY.noJs,
        action: { type: 'modifyHeaders', responseHeaders: [{ header: 'content-security-policy', operation: 'append', value: NO_JS_CSP }] },
        condition,
      })
    }
    await dnr.updateSessionRules({ removeRuleIds, addRules: asRules(rules) })
  })
}

export function clearTab(tabId: number): Promise<void> {
  return serial(async () => {
    const existing = fromRules(await dnr.getSessionRules())
    const ids = existing.filter((r) => r.condition.tabIds?.includes(tabId)).map((r) => r.id)
    if (ids.length) await dnr.updateSessionRules({ removeRuleIds: ids })
  })
}

/**
 * Threshold 'weak': Chromium cannot analyse before render, so after a committed Weak page we
 * (a) send the tab to the interstitial and (b) learn a response-stage rule so later visits are
 * blocked before render. Returns true if the tab was redirected.
 */
export async function learnWeak(tabId: number, url: string, report: Report, settings: Settings, method?: string): Promise<boolean> {
  if (settings.threshold !== 'weak' || report.verdict !== 'weak') return false
  if (method && method.toUpperCase() !== 'GET') return false
  const host = hostOf(url)
  if (!host || hostMatches(host, [...settings.excludedHosts, ...activeTrustedHosts(settings)])) return false
  const bypass = await getBypassRecord(tabId)
  if (bypass && bypass.host === host) return false

  const csps = report.headers.filter((h) => h.name.toLowerCase() === 'content-security-policy' && h.value)
  if (csps.length === 1 && csps[0].value) await addLearned(host, csps[0].value)

  await recordBlocked(tabId, url, report)
  try {
    await chrome.tabs.update(tabId, { url: `${interstitialUrl()}#${url}` })
  } catch {
    return false
  }
  return true
}

function addLearned(host: string, csp: string): Promise<void> {
  return serial(async () => {
    const learned = await readLearned()
    const live = new Set((await dnr.getDynamicRules()).map((r) => r.id))
    const kept = learned.filter((l) => live.has(l.id))
    const dup = kept.find((l) => l.host === host && l.csp === csp)
    if (dup) {
      dup.ts = Date.now()
      await chrome.storage.local.set({ [LEARNED_KEY]: kept })
      return
    }
    const removeRuleIds: number[] = []
    kept.sort((a, b) => a.ts - b.ts)
    while (kept.length >= LEARNED_CAP) {
      const old = kept.shift()
      if (old) removeRuleIds.push(old.id)
    }
    const maxId = (await dnr.getDynamicRules()).reduce((m, r) => Math.max(m, r.id), LEARNED_MIN_ID - 1)
    const id = maxId + 1
    const rule: DnrRule = {
      id,
      priority: PRIORITY.gate,
      // extensionPath avoids a regex rule: dynamic regex rules are capped far below 2000.
      // The interstitial reads the blocked URL from the background record, not from the URL.
      action: { type: 'redirect', redirect: { extensionPath: '/' + INTERSTITIAL_PATH } },
      condition: {
        requestDomains: [host],
        resourceTypes: ['main_frame'],
        requestMethods: ['get'],
        responseHeaders: [{ header: 'content-security-policy', values: [globEscape(csp)] }],
        excludedResponseHeaders: PASS_THROUGH_EXCLUSIONS,
      },
    }
    await dnr.updateDynamicRules({ removeRuleIds, addRules: asRules([rule]) })
    kept.push({ id, host, csp, ts: Date.now() })
    await chrome.storage.local.set({ [LEARNED_KEY]: kept })
  })
}

/** Must be called synchronously at background top level. */
export function registerListeners(): void {
  chrome.webRequest.onHeadersReceived.addListener(
    (d) => {
      if (d.frameId !== 0) return
      observeResponse({
        tabId: d.tabId,
        requestId: d.requestId,
        url: d.url,
        method: d.method,
        statusCode: d.statusCode,
        responseHeaders: d.responseHeaders,
      })
    },
    { urls: ['<all_urls>'], types: ['main_frame'] },
    ['responseHeaders', 'extraHeaders'],
  )

  chrome.webRequest.onBeforeRedirect.addListener(
    (d) => {
      if (d.frameId !== 0 || d.tabId < 0) return
      if (!isInterstitialUrl(d.redirectUrl) || !safeHttpUrl(d.url)) return
      void peekPending(d.tabId, d.url).then((p) => recordBlocked(d.tabId, d.url, p?.report))
    },
    { urls: ['<all_urls>'], types: ['main_frame'] },
  )
}

export async function init(): Promise<void> {
  // Rules persist across service worker restarts and are re-read from DNR when needed; nothing to restore.
}
