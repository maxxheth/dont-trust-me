// Typed, sender-validated router for Request messages.

import { analyze } from '../analyzer'
import { enforcement } from '../enforcement'
import { interstitialUrl, isInterstitialUrl } from '../enforcement/env'
import { PRIVILEGED_TYPES, type BlockedInfo, type Request, type Response, type VerdictPush } from '../shared/messages'
import { isValidHost, normalizeSettings, type BypassScope, type Settings } from '../shared/settings'
import type { HttpHeader, Report, TabState } from '../shared/types'
import { safeHttpUrl } from '../shared/url'
import { getSettings, saveSettings } from './settings-store'
import {
  cacheReport,
  getBlocked,
  getTabState,
  setBypassRecord,
  setTabState,
} from './tab-state'
import { applyState, buildPush } from './verdict'

const DAY_MS = 24 * 60 * 60 * 1000

const ok = <T>(data: T): Response<T> => ({ ok: true, data })
const fail = (error: string): Response<never> => ({ ok: false, error })

const stripHash = (u: string): string => u.split('#', 1)[0]

const originOf = (u: string): string | null => {
  try {
    return new URL(u).origin
  } catch {
    return null
  }
}

/**
 * True when the sender is one of this extension's own pages. The interstitial is a
 * web-accessible resource with use_dynamic_url, so on Chromium it runs under a per-session
 * random origin that differs from getURL('') — accept both origins, nothing else.
 */
function isExtensionPage(sender: chrome.runtime.MessageSender): boolean {
  if (typeof sender.url !== 'string') return false
  const origin = originOf(sender.url)
  return origin !== null && (origin === originOf(chrome.runtime.getURL('')) || origin === originOf(interstitialUrl()))
}

function isRequest(m: unknown): m is Request {
  return !!m && typeof m === 'object' && typeof (m as { type?: unknown }).type === 'string'
}

async function trust(settings: Settings, host: string, scope: BypassScope): Promise<Settings> {
  // 'tab' is not a persistent scope: treat as the shortest persistent one (24h).
  const expiresAt = scope === 'always' ? undefined : Date.now() + DAY_MS
  const rest = settings.trustedSites.filter((t) => t.host !== host)
  return saveSettings({ ...settings, trustedSites: [...rest, { host, expiresAt, addedAt: Date.now() }] })
}

async function handleProceed(
  msg: Extract<Request, { type: 'proceed' }>,
  sender: chrome.runtime.MessageSender,
): Promise<Response<null>> {
  const tabId = sender.tab?.id
  if (tabId === undefined) return fail('No tab')
  if (!isInterstitialUrl(sender.url)) return fail('Only the warning page can proceed')
  if (msg.mode !== 'unsafe' && msg.mode !== 'no-js') return fail('Bad mode')
  if (msg.scope !== 'tab' && msg.scope !== '24h' && msg.scope !== 'always') return fail('Bad scope')

  // Never trust the page hash: the target is the background's own record of the blocked navigation.
  const blocked = await getBlocked(tabId)
  const target = safeHttpUrl(blocked?.url)
  if (!target) return fail('No blocked navigation recorded for this tab')
  const host = target.hostname.toLowerCase()
  if (!isValidHost(host)) return fail('Invalid host')

  if (msg.mode === 'unsafe' && msg.scope !== 'tab') {
    const s = await trust(await getSettings(), host, msg.scope)
    await enforcement.rebuild(s)
  }
  // No-JS is always tab-scoped, whatever scope was requested.
  await enforcement.addBypass(tabId, host, msg.mode)
  await setBypassRecord(tabId, { host, mode: msg.mode })
  await chrome.tabs.update(tabId, { url: target.href })
  return ok(null)
}

async function handleRecheck(tabId: number): Promise<Response<null>> {
  if (!Number.isInteger(tabId)) return fail('Bad tab')
  const settings = await getSettings()
  const state = await getTabState(tabId)
  const target = safeHttpUrl(state?.url)
  if (settings.recheckUnverified && state?.verdict === 'unverified' && target) {
    try {
      const res = await fetch(target.href, { method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'manual' })
      if (res.type !== 'opaqueredirect' && res.status < 300) {
        const headers: HttpHeader[] = []
        res.headers.forEach((value, name) => headers.push({ name, value }))
        const report: Report = analyze({ url: target.href, statusCode: res.status, headers })
        const next: TabState = { ...state, verdict: report.verdict, report }
        await setTabState(next)
        await cacheReport(target.href, report)
        await applyState(tabId, next, settings)
        return ok(null)
      }
    } catch {
      // fall through to a plain reload
    }
  }
  await chrome.tabs.reload(tabId)
  return ok(null)
}

async function route(msg: Request, sender: chrome.runtime.MessageSender): Promise<Response<unknown>> {
  switch (msg.type) {
    case 'getMyVerdict': {
      const tabId = sender.tab?.id
      if (tabId === undefined) return fail('No tab')
      const state = await getTabState(tabId)
      // Ignore state belonging to a previous page (commit promotion may still be in flight).
      if (!state || !sender.url || stripHash(state.url) !== stripHash(sender.url)) return ok<VerdictPush | null>(null)
      return ok<VerdictPush | null>(buildPush(state, await getSettings()))
    }
    case 'getTabState':
      if (!isExtensionPage(sender)) return fail('Forbidden')
      if (!Number.isInteger(msg.tabId)) return fail('Bad tab')
      return ok<TabState | null>((await getTabState(msg.tabId)) ?? null)
    case 'getSettings':
      if (!isExtensionPage(sender)) return fail('Forbidden')
      return ok<Settings>(await getSettings())
    case 'getBlocked': {
      if (!isExtensionPage(sender)) return fail('Forbidden')
      const tabId = sender.tab?.id
      if (tabId === undefined) return fail('No tab')
      const b = await getBlocked(tabId)
      const u = safeHttpUrl(b?.url)
      if (!b || !u) return fail('No blocked navigation recorded for this tab')
      return ok<BlockedInfo>({ url: u.href, host: u.hostname.toLowerCase(), report: b.report })
    }
    case 'proceed':
      return handleProceed(msg, sender)
    case 'trustSite': {
      const host = typeof msg.host === 'string' ? msg.host.toLowerCase() : ''
      if (!isValidHost(host)) return fail('Invalid host')
      const s = await trust(await getSettings(), host, msg.scope)
      await enforcement.rebuild(s)
      return ok(s)
    }
    case 'revokeTrust': {
      const host = typeof msg.host === 'string' ? msg.host.toLowerCase() : ''
      const cur = await getSettings()
      const s = await saveSettings({ ...cur, trustedSites: cur.trustedSites.filter((t) => t.host !== host) })
      await enforcement.rebuild(s)
      return ok(s)
    }
    case 'saveSettings': {
      const s = await saveSettings(normalizeSettings(msg.settings))
      await enforcement.rebuild(s)
      return ok(s)
    }
    case 'recheck':
      return handleRecheck(msg.tabId)
    default:
      return fail('Unknown message')
  }
}

export async function handleMessage(msg: unknown, sender: chrome.runtime.MessageSender): Promise<Response<unknown>> {
  try {
    if (sender.id !== chrome.runtime.id) return fail('Forbidden')
    if (!isRequest(msg)) return fail('Bad request')
    if ((PRIVILEGED_TYPES as readonly string[]).includes(msg.type) && !isExtensionPage(sender)) return fail('Forbidden')
    return await route(msg, sender)
  } catch (err) {
    return fail(err instanceof Error ? err.message : 'Internal error')
  }
}

/** Register synchronously at background top level. */
export function registerMessageListener(): void {
  chrome.runtime.onMessage.addListener((msg: unknown, sender, sendResponse) => {
    void handleMessage(msg, sender).then(sendResponse)
    return true // async response
  })
}
