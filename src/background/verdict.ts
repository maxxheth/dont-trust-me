// Applies a tab's state to the UI surfaces: toolbar icon/badge and the in-page content script.

import type { VerdictPush } from '../shared/messages'
import type { Settings } from '../shared/settings'
import type { TabState } from '../shared/types'
import { resetIcon, updateIcon } from './icon'

let protectionOff = false

export function isProtectionOff(): boolean {
  return protectionOff
}

export function setProtectionOff(off: boolean): void {
  protectionOff = off
}

export function buildPush(state: TabState, settings: Settings): VerdictPush {
  return { type: 'verdict', state, showWarningBar: settings.showWarningBar, showFieldWarnings: settings.showFieldWarnings }
}

export async function applyState(tabId: number, state: TabState | null, settings: Settings, isInterstitial = false): Promise<void> {
  if (!state) {
    await resetIcon(tabId, protectionOff)
    return
  }
  await updateIcon(tabId, state, protectionOff)
  if (isInterstitial) return // extension page: no content script
  try {
    await chrome.tabs.sendMessage(tabId, buildPush(state, settings), { frameId: 0 })
  } catch {
    // No content script (yet, or on this page): it will pull via getMyVerdict.
  }
}
