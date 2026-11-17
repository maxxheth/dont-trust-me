import type { HttpHeader } from '../shared/types'
import { hasScriptGoverningPolicy, parseCspValues } from './csp'
import { getHeaderValues } from './headers'

export { analyze } from './score'
export { CATALOG } from './findings'
export { WEIGHTS, GRADE_BANDS, gradeFor, HARD_FAIL_IDS } from './policy'
export { parseCspValues, parsePolicy, effectiveDirective, analyzeSources } from './csp'

/**
 * True iff at least one enforced CSP policy contains script-src, script-src-elem or
 * default-src. Report-Only headers never count.
 */
export function isScriptGoverningCspPresent(headers: HttpHeader[]): boolean {
  try {
    return hasScriptGoverningPolicy(parseCspValues(getHeaderValues(headers, 'content-security-policy')))
  } catch {
    return false
  }
}
