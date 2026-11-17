// Typed runtime messages. The background router (src/background/messages.ts) is the only
// receiver of Request messages; it validates sender before acting on privileged ones.

import type { BypassScope, Settings } from './settings'
import type { Report, TabState } from './types'

/** Messages any extension context may send (read-only). */
export type ReadRequest =
  | { type: 'getTabState'; tabId: number } // popup asks about a tab
  | { type: 'getBlocked' } // interstitial asks about its own tab (sender.tab.id)
  | { type: 'getSettings' }
  | { type: 'getMyVerdict' } // content script asks about its own tab

/** Privileged messages: accepted only when sender.url is an extension page (popup/options/interstitial). */
export type PrivilegedRequest =
  | { type: 'proceed'; mode: 'unsafe' | 'no-js'; scope: BypassScope } // from interstitial, acts on sender.tab
  | { type: 'trustSite'; host: string; scope: BypassScope }
  | { type: 'revokeTrust'; host: string }
  | { type: 'saveSettings'; settings: Settings }
  | { type: 'recheck'; tabId: number }

export type Request = ReadRequest | PrivilegedRequest

export const PRIVILEGED_TYPES: ReadonlyArray<PrivilegedRequest['type']> = [
  'proceed',
  'trustSite',
  'revokeTrust',
  'saveSettings',
  'recheck',
]

export type Response<T> = { ok: true; data: T } | { ok: false; error: string }

export interface BlockedInfo {
  url: string
  host: string
  report?: Report
}

/** Background -> content script push (via chrome.tabs.sendMessage). */
export interface VerdictPush {
  type: 'verdict'
  state: TabState
  showWarningBar: boolean
  showFieldWarnings: boolean
}

export function send<T>(msg: Request): Promise<Response<T>> {
  return chrome.runtime.sendMessage(msg) as Promise<Response<T>>
}
