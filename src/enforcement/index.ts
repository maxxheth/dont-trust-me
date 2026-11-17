// Chooses the Chromium (DNR) or Firefox (blocking webRequest) enforcement path.

import type { Settings } from '../shared/settings'
import type { Report } from '../shared/types'
import * as chromium from './dnr'
import { isFirefox } from './env'
import * as firefox from './webrequest-firefox'

export interface Enforcement {
  /** Call synchronously at background top level (registers webRequest listeners). */
  registerListeners(): void
  init(): Promise<void>
  /** Re-sync gate/allow rules (Chromium) from settings. Idempotent and cheap when nothing changed. */
  rebuild(settings: Settings): Promise<void>
  /** Tab-scoped bypass for `host`. 'no-js' also appends a script-blocking CSP to that host's documents. */
  addBypass(tabId: number, host: string, mode: 'unsafe' | 'no-js'): Promise<void>
  clearTab(tabId: number): Promise<void>
  /** Chromium 'weak' threshold: after a Weak page commits, redirect the tab and learn a rule. Returns true if redirected. */
  onCommittedReport(tabId: number, url: string, report: Report, settings: Settings, method?: string): Promise<boolean>
}

const chromiumImpl: Enforcement = {
  registerListeners: chromium.registerListeners,
  init: chromium.init,
  rebuild: chromium.rebuild,
  addBypass: chromium.addBypass,
  clearTab: chromium.clearTab,
  onCommittedReport: (tabId, url, report, settings, method) => chromium.learnWeak(tabId, url, report, settings, method),
}

const firefoxImpl: Enforcement = {
  registerListeners: firefox.registerListeners,
  init: firefox.init,
  rebuild: firefox.rebuild,
  addBypass: firefox.addBypass,
  clearTab: firefox.clearTab,
  onCommittedReport: () => Promise.resolve(false), // Firefox gates before render
}

export const enforcement: Enforcement = isFirefox() ? firefoxImpl : chromiumImpl
export { isFirefox }
