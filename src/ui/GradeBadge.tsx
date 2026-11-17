import type { Grade, Verdict } from '../shared/types'

const ICON: Record<Verdict, string> = {
  'not-secure': 'M4 4l8 8M12 4l-8 8', // cross
  weak: 'M8 3v6M8 12v.5', // exclamation
  partial: 'M3 8h10', // dash
  secure: 'M3 8.5l3.5 3.5L13 4.5', // check
  unverified: 'M6 6a2 2 0 114 0c0 1.5-2 1.5-2 3M8 12v.5', // question
}

export const VERDICT_TEXT: Record<Verdict, string> = {
  'not-secure': 'Not Secure',
  weak: 'Weak',
  partial: 'Partial',
  secure: 'Secure',
  unverified: 'Unverified',
}

export function VerdictIcon({ verdict, size = 14 }: { verdict: Verdict; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={ICON[verdict]} />
    </svg>
  )
}

export function GradeBadge({ verdict, grade, size = 64 }: { verdict: Verdict; grade?: Grade; size?: number }) {
  return (
    <span className={`grade-badge v-${verdict}`} style={{ width: size, height: size }} role="img" aria-label={`${VERDICT_TEXT[verdict]}${grade ? `, grade ${grade}` : ''}`}>
      <span className="grade" style={{ fontSize: size * 0.4 }}>{grade ?? '?'}</span>
      <VerdictIcon verdict={verdict} size={Math.round(size * 0.28)} />
    </span>
  )
}

export function VerdictLabel({ verdict }: { verdict: Verdict }) {
  return (
    <span className={`verdict-label v-${verdict}`}>
      <VerdictIcon verdict={verdict} />
      {VERDICT_TEXT[verdict]}
    </span>
  )
}
