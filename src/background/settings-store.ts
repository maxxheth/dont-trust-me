// In-memory settings cache backed by chrome.storage.local (SETTINGS_KEY).

import { normalizeSettings, SETTINGS_KEY, type Settings } from '../shared/settings'

let cache: Settings | null = null
let loading: Promise<Settings> | null = null
const listeners = new Set<(s: Settings) => void>()

export function getSettings(): Promise<Settings> {
  if (cache) return Promise.resolve(cache)
  loading ??= chrome.storage.local
    .get(SETTINGS_KEY)
    .then((r) => {
      cache = normalizeSettings(r[SETTINGS_KEY])
      return cache
    })
    .catch(() => {
      cache = normalizeSettings(undefined)
      return cache
    })
    .finally(() => {
      loading = null
    })
  return loading
}

/** Synchronous read; null until the first load completes. */
export function peekSettings(): Settings | null {
  return cache
}

export async function saveSettings(next: Settings): Promise<Settings> {
  const clean = normalizeSettings(next)
  cache = clean
  await chrome.storage.local.set({ [SETTINGS_KEY]: clean })
  return clean
}

export function onSettingsChanged(fn: (s: Settings) => void): void {
  listeners.add(fn)
}

/** Call from a top-level chrome.storage.onChanged listener. */
export function handleStorageChange(changes: Record<string, chrome.storage.StorageChange>, area: string): void {
  if (area !== 'local' || !changes[SETTINGS_KEY]) return
  cache = normalizeSettings(changes[SETTINGS_KEY].newValue)
  for (const fn of listeners) fn(cache)
}
