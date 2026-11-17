// Background entry (MV3 service worker on Chromium, event page on Firefox).
// All listeners are registered synchronously at top level so they survive worker restarts.

import { enforcement, isFirefox } from '../enforcement'
import { activeTrustedHosts, hostMatches } from '../shared/settings'
import { hostOf } from '../shared/url'
import { updateIcon } from './icon'
import { registerMessageListener } from './messages'
import { getSettings, handleStorageChange, onSettingsChanged } from './settings-store'
import { clearTabRecords, getTabState, moveTabRecords, promoteOnCommit, setTabState } from './tab-state'
import { applyState, isProtectionOff, setProtectionOff } from './verdict'

// ---- Listeners (synchronous registration) ---------------------------------------------------

enforcement.registerListeners()
registerMessageListener()

chrome.storage.onChanged.addListener(handleStorageChange)
onSettingsChanged((s) => {
  void enforcement.rebuild(s).then(refreshAllIcons)
})

chrome.runtime.onInstalled.addListener((details) => {
  void boot().then(() => {
    if (details.reason === 'install') void chrome.runtime.openOptionsPage()
  })
})
chrome.runtime.onStartup.addListener(() => void boot())

chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId !== 0) return
  void onCommitted(d.tabId, d.url, d.transitionQualifiers ?? [])
})

chrome.tabs.onRemoved.addListener((tabId) => {
  void Promise.all([clearTabRecords(tabId), enforcement.clearTab(tabId)])
})

chrome.tabs.onReplaced.addListener((added, removed) => {
  void (async () => {
    const state = await moveTabRecords(removed, added)
    await enforcement.clearTab(removed)
    const settings = await getSettings()
    await applyState(added, state ?? null, settings)
  })()
})

// Firefox: <all_urls> is an optional grant. Track it so the icon can show "Protection off".
chrome.permissions?.onAdded?.addListener(() => void syncPermission())
chrome.permissions?.onRemoved?.addListener(() => void syncPermission())

// Declared before the top-level boot() call: touching it earlier is a TDZ ReferenceError,
// which makes Chrome mark the service worker script as failed and stop delivering events.
let booting: Promise<void> | null = null

void boot()

// ---- Implementation ----------------------------------------------------------------------

function boot(): Promise<void> {
  booting ??= (async () => {
    const settings = await getSettings()
    await enforcement.init()
    await enforcement.rebuild(settings).catch((e) => console.warn("Don't Trust Me: rebuild failed", e))
    await syncPermission()
  })().finally(() => {
    booting = null
  })
  return booting
}

async function syncPermission(): Promise<void> {
  if (!isFirefox()) return setProtectionOff(false)
  let granted = true
  try {
    granted = await chrome.permissions.contains({ origins: ['<all_urls>'] })
  } catch {
    // assume granted
  }
  const changed = granted === isProtectionOff()
  setProtectionOff(!granted)
  if (changed) await refreshAllIcons()
}

async function refreshAllIcons(): Promise<void> {
  const tabs = await chrome.tabs.query({}).catch(() => [])
  await Promise.all(
    tabs.map(async (t) => {
      if (t.id === undefined) return
      const state = await getTabState(t.id)
      await updateIcon(t.id, state ?? null, isProtectionOff())
    }),
  )
}

async function onCommitted(tabId: number, url: string, qualifiers: string[]): Promise<void> {
  try {
    const settings = await getSettings()
    const { state, method, isInterstitial } = await promoteOnCommit(tabId, url, qualifiers)

    if (state && !isInterstitial) {
      const host = hostOf(url)
      // A Not Secure page that loaded anyway because the user trusted the host counts as a bypass.
      if (state.report?.verdict === 'not-secure' && !state.bypass && host && hostMatches(host, activeTrustedHosts(settings))) {
        state.bypass = 'unsafe'
        await setTabState(state)
      }
      // Chromium 'weak' threshold: send the tab to the interstitial and learn a rule for next time.
      if (state.report && state.report.verdict === 'weak' && !state.bypass) {
        if (await enforcement.onCommittedReport(tabId, url, state.report, settings, method)) return
      }
      // Expired 24h trust may still be in the allow rule: re-sync (cheap no-op when unchanged).
      if (settings.trustedSites.some((t) => t.expiresAt !== undefined && t.expiresAt <= Date.now())) {
        void enforcement.rebuild(settings)
      }
    }
    await applyState(tabId, state, settings, isInterstitial)
  } catch (err) {
    console.warn("Don't Trust Me: commit handling failed", err)
  }
}
