import { useEffect, useState } from 'react'
import './styles.css'
import { send } from '../shared/messages'
import {
  DEFAULT_SETTINGS, isValidHost, normalizeSettings,
  type BypassScope, type InterstitialThreshold, type Settings,
} from '../shared/settings'

const THRESHOLDS: Array<[InterstitialThreshold, string, string]> = [
  ['not-secure', 'Not Secure only', 'Show the warning page only when no script-restricting policy exists. Recommended.'],
  ['weak', 'Weak and below', 'Also warn when a policy exists but is easy to bypass.'],
  ['never', 'Never — badge only', 'Never block pages; only show the toolbar badge.'],
]

export function OptionsApp() {
  const [s, setS] = useState<Settings | null>(null)
  const [msg, setMsg] = useState<{ text: string; bad?: boolean } | null>(null)
  const [newHost, setNewHost] = useState('')
  const [hostErr, setHostErr] = useState('')
  const [granted, setGranted] = useState<boolean | null>(null)

  const refresh = async () => {
    const r = await send<Settings>({ type: 'getSettings' })
    if (r.ok) setS(r.data)
    else setMsg({ text: r.error, bad: true })
  }
  useEffect(() => {
    void refresh()
    chrome.permissions.contains({ origins: ['<all_urls>'] }).then(setGranted).catch(() => setGranted(true))
  }, [])

  const save = async (next: Settings) => {
    setS(next)
    try {
      const r = await send<void>({ type: 'saveSettings', settings: next })
      if (!r.ok) setMsg({ text: r.error, bad: true })
      else setMsg({ text: 'Saved.' })
    } catch (e) {
      setMsg({ text: String(e), bad: true })
    }
    await refresh()
  }

  if (!s) return <div className="options"><p>Loading…</p>{msg ? <p className="err">{msg.text}</p> : null}</div>
  const patch = (p: Partial<Settings>) => save({ ...s, ...p })

  const addHost = () => {
    const h = newHost.trim().toLowerCase()
    if (!isValidHost(h)) return setHostErr('Enter a valid host name, e.g. example.com')
    setHostErr('')
    setNewHost('')
    if (!s.excludedHosts.includes(h)) void patch({ excludedHosts: [...s.excludedHosts, h] })
  }

  const exportJson = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(s, null, 2)], { type: 'application/json' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'dont-trust-me-settings.json'
    a.click()
    URL.revokeObjectURL(url)
  }
  const importJson = async (file: File | undefined) => {
    if (!file) return
    try {
      const raw: unknown = JSON.parse(await file.text())
      await save(normalizeSettings(raw))
    } catch {
      setMsg({ text: 'That file is not valid JSON.', bad: true })
    }
  }
  const grant = async () => {
    try {
      setGranted(await chrome.permissions.request({ origins: ['<all_urls>'] }))
    } catch (e) {
      setMsg({ text: String(e), bad: true })
    }
  }

  const toggles: Array<[keyof Pick<Settings, 'showWarningBar' | 'showFieldWarnings' | 'recheckUnverified'>, string, string]> = [
    ['showWarningBar', 'Show warning bar on Not Secure pages', 'A dismissible bar at the top of the page. Advisory only; the toolbar icon is the trusted indicator.'],
    ['showFieldWarnings', 'Warn when focusing password and payment fields', 'Advisory notice on sensitive inputs of unprotected pages.'],
    ['recheckUnverified', 'Re-check unverified pages', 'Fetch the page again to read its headers when none were captured. This makes one extra request to the site.'],
  ]

  return (
    <main className="options">
      <h1>Don&rsquo;t Trust Me</h1>
      {granted === false ? (
        <div className="banner" role="region" aria-label="Permission needed">
          <p><strong>Access to all sites is needed.</strong> Without it the extension cannot read response headers.</p>
          <button className="primary" onClick={grant}>Grant access to all sites</button>
        </div>
      ) : null}
      <div aria-live="polite">{msg ? <p className={msg.bad ? 'err' : 'ok'}>{msg.text}</p> : null}</div>

      <h2>When to show the warning page</h2>
      <fieldset style={{ border: 0, padding: 0, margin: 0 }}>
        <legend className="sr-only">Warning threshold</legend>
        {THRESHOLDS.map(([v, label, hint]) => (
          <label className="opt" key={v}>
            <input type="radio" name="threshold" checked={s.threshold === v} onChange={() => patch({ threshold: v })} /> {label}
            <span className="hint">{hint}</span>
          </label>
        ))}
      </fieldset>

      <h2>Default choice when proceeding</h2>
      <div className="inline">
        <label htmlFor="scope">Remember my choice for:</label>
        <select id="scope" value={s.defaultBypassScope} onChange={(e) => patch({ defaultBypassScope: e.target.value as BypassScope })}>
          <option value="tab">This tab only</option>
          <option value="24h">24 hours</option>
          <option value="always">Always</option>
        </select>
      </div>

      <h2>Trusted sites</h2>
      {s.trustedSites.length === 0 ? <p className="muted">No trusted sites.</p> : (
        <table>
          <thead><tr><th>Host</th><th>Expires</th><th><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {s.trustedSites.map((t) => (
              <tr key={t.host}>
                <td>{t.host}</td>
                <td>{t.expiresAt === undefined ? 'Never' : new Date(t.expiresAt).toLocaleString()}</td>
                <td><button onClick={async () => { await send<void>({ type: 'revokeTrust', host: t.host }); await refresh() }} aria-label={`Remove ${t.host}`}>Remove</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Excluded hosts</h2>
      <p className="muted">These hosts and their subdomains are never checked.</p>
      <ul className="hosts">
        {s.excludedHosts.map((h) => (
          <li key={h}><span>{h}</span><button onClick={() => patch({ excludedHosts: s.excludedHosts.filter((x) => x !== h) })} aria-label={`Remove ${h}`}>Remove</button></li>
        ))}
      </ul>
      <div className="inline">
        <label htmlFor="newhost">Add host:</label>
        <input id="newhost" type="text" value={newHost} onChange={(e) => setNewHost(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addHost()} aria-describedby="hosterr" />
        <button onClick={addHost}>Add</button>
      </div>
      <p id="hosterr" className="err" role="alert">{hostErr}</p>

      <h2>Behaviour</h2>
      {toggles.map(([k, label, hint]) => (
        <label className="opt" key={k}>
          <input type="checkbox" checked={s[k]} onChange={(e) => patch({ [k]: e.target.checked })} /> {label}
          <span className="hint">{hint}</span>
        </label>
      ))}

      <h2>Backup</h2>
      <div className="inline">
        <button onClick={exportJson}>Export JSON</button>
        <label htmlFor="import">Import JSON:</label>
        <input id="import" type="file" accept="application/json,.json" onChange={(e) => { void importJson(e.target.files?.[0]); e.target.value = '' }} />
      </div>
      <div className="inline">
        <button className="danger" onClick={() => { if (confirm('Reset all settings to defaults?')) void save({ ...DEFAULT_SETTINGS, excludedHosts: [...DEFAULT_SETTINGS.excludedHosts] }) }}>Reset to defaults</button>
      </div>
      <p className="muted">Analysed locally — nothing leaves your browser.</p>
    </main>
  )
}
