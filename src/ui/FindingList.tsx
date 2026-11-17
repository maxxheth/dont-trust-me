import type { Finding, FindingCategory } from '../shared/types'

const CATEGORIES: Array<[FindingCategory, string]> = [
  ['script-control', 'Script control'],
  ['exfiltration', 'Exfiltration'],
  ['framing', 'Framing'],
  ['transport', 'Transport'],
  ['cookies', 'Cookies'],
  ['other', 'Other'],
]

function FindingItem({ f }: { f: Finding }) {
  const mdn = f.mdn && /^https:\/\/developer\.mozilla\.org\//.test(f.mdn) ? f.mdn : undefined
  return (
    <li className="finding">
      <div className="head">
        <span className={`chip sev-${f.severity}`}>{f.severity}</span>
        <strong>{f.title}</strong>
      </div>
      {f.evidence ? (
        <div>
          <code>{f.evidence}</code>
        </div>
      ) : null}
      <details>
        <summary>Why this matters and how site owners fix it</summary>
        <p>{f.why}</p>
        <p>
          <strong>Fix: </strong>
          {f.fix}
        </p>
        {mdn ? (
          <p>
            <a href={mdn} target="_blank" rel="noopener noreferrer">
              Learn more on MDN
            </a>
          </p>
        ) : null}
      </details>
    </li>
  )
}

export function FindingList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return <p className="muted">No findings.</p>
  return (
    <div className="findings">
      {CATEGORIES.map(([cat, label]) => {
        const items = findings.filter((f) => f.category === cat)
        if (items.length === 0) return null
        return (
          <section key={cat} aria-label={label}>
            <h3>{label}</h3>
            <ul>
              {items.map((f, i) => (
                <FindingItem key={`${f.id}-${i}`} f={f} />
              ))}
            </ul>
          </section>
        )
      })}
    </div>
  )
}
