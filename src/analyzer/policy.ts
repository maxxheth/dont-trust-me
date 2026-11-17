// Tunable scoring weights and grade bands (plan §3.2). Edit here to retune.
import type { FindingId, Grade } from '../shared/types'

/** Findings that force grade F and verdict not-secure. */
export const HARD_FAIL_IDS: readonly FindingId[] = ['T1', 'C1']

/** Points shown on hard-fail findings; they are not subtracted from the score. */
export const HARD_FAIL_POINTS = -100

/** Score is capped here (top of the F band) when a hard fail is present. */
export const HARD_FAIL_SCORE_CAP = 44

export const BASE_SCORE = 100

export const WEIGHTS: Record<FindingId, number> = {
  T1: HARD_FAIL_POINTS,
  C1: HARD_FAIL_POINTS,
  C3: -35,
  C4: -30,
  C5: -10,
  C6: -10,
  C7: -10,
  C8: -5,
  E1: -15,
  E2: -10,
  E3: -5,
  E4: -5,
  R1: -5,
  H1: -15,
  H2: -20,
  H3: -10,
  H4: -10,
  H5: -5,
  H6: -5,
  H7: -5,
  K1: -10,
  K2: -5,
  B1: 10,
  B2: 5,
  B3: 5,
  I1: 0,
  I2: 0,
  I3: 0,
  I4: 0,
}

/** Minimum score for each grade, best first. */
export const GRADE_BANDS: ReadonlyArray<readonly [Grade, number]> = [
  ['A+', 100],
  ['A', 90],
  ['B', 75],
  ['C', 60],
  ['D', 45],
]

export function gradeFor(score: number): Grade {
  for (const [grade, min] of GRADE_BANDS) if (score >= min) return grade
  return 'F'
}
