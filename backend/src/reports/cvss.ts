import type { Severity } from '../types.js';

/**
 * CVSS v3.1 base-score ESTIMATES for findings.
 *
 * These are heuristic estimates (documented as such in every report), not
 * analyst-verified scores: BugSeek maps severity+category to a representative
 * metric set and computes the official CVSS v3.1 base-score formula from it.
 * The vector string is always emitted so the estimate is auditable.
 */

export interface CvssEstimate {
  score: number; // 0.0 – 10.0, rounded to 1 decimal
  vector: string; // CVSS:3.1/... vector string
}

interface MetricSet {
  av: 'N' | 'A' | 'L' | 'P';
  ac: 'L' | 'H';
  pr: 'N' | 'L' | 'H';
  ui: 'N' | 'R';
  s: 'U' | 'C';
  c: 'N' | 'L' | 'H';
  i: 'N' | 'L' | 'H';
  a: 'N' | 'L' | 'H';
}

const WEIGHTS = {
  av: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  ac: { L: 0.77, H: 0.44 },
  prU: { N: 0.85, L: 0.62, H: 0.27 },
  prC: { N: 0.85, L: 0.68, H: 0.5 },
  ui: { N: 0.85, R: 0.62 },
  cia: { N: 0, L: 0.22, H: 0.56 },
};

function roundUp1(n: number): number {
  return Math.ceil(n * 10) / 10;
}

function baseScore(m: MetricSet): number {
  const iss = 1 - (1 - WEIGHTS.cia[m.c]) * (1 - WEIGHTS.cia[m.i]) * (1 - WEIGHTS.cia[m.a]);
  const impact = m.s === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const prW = m.s === 'U' ? WEIGHTS.prU[m.pr] : WEIGHTS.prC[m.pr];
  const exploit = 8.22 * WEIGHTS.av[m.av] * WEIGHTS.ac[m.ac] * prW * WEIGHTS.ui[m.ui];
  if (impact <= 0) return 0;
  const score = m.s === 'U' ? Math.min(impact + exploit, 10) : Math.min(1.08 * (impact + exploit), 10);
  return roundUp1(score);
}

const CATEGORY_METRICS: Record<string, Partial<MetricSet>> = {
  xss: { c: 'L', i: 'L', a: 'N', ui: 'R', s: 'C' },
  sqli: { c: 'H', i: 'H', a: 'H', s: 'C' },
  idor: { c: 'H', i: 'L', a: 'N', pr: 'L', s: 'U' },
  cors: { c: 'L', i: 'H', a: 'N', ui: 'R', s: 'C' },
  auth: { c: 'H', i: 'H', a: 'L', s: 'C' },
  secrets: { c: 'H', i: 'H', a: 'N', s: 'C' },
  headers: { c: 'N', i: 'L', a: 'N', s: 'U' },
  cookies: { c: 'L', i: 'L', a: 'N', s: 'U' },
  ratelimit: { c: 'N', i: 'L', a: 'L', s: 'U' },
};

const SEVERITY_IMPACT: Record<Severity, { c: 'N' | 'L' | 'H'; i: 'N' | 'L' | 'H'; a: 'N' | 'L' | 'H' }> = {
  critical: { c: 'H', i: 'H', a: 'H' },
  high: { c: 'H', i: 'H', a: 'L' },
  medium: { c: 'L', i: 'L', a: 'N' },
  low: { c: 'L', i: 'N', a: 'N' },
  info: { c: 'N', i: 'N', a: 'N' },
};

export function estimateCvss(severity: Severity, category: string): CvssEstimate {
  const cat = CATEGORY_METRICS[category.toLowerCase()] ?? {};
  const sev = SEVERITY_IMPACT[severity];
  const m: MetricSet = {
    av: 'N',
    ac: 'L',
    pr: 'N',
    ui: cat.ui ?? 'N',
    s: cat.s ?? 'U',
    c: cat.c ?? sev.c,
    i: cat.i ?? sev.i,
    a: cat.a ?? sev.a,
  };
  // Clamp: never let a heuristic exceed the severity band.
  const raw = baseScore(m);
  const bandMax: Record<Severity, number> = { critical: 10, high: 8.9, medium: 6.9, low: 3.9, info: 0 };
  const score = severity === 'info' ? 0 : Math.min(raw, bandMax[severity]);
  const vector = `CVSS:3.1/AV:${m.av}/AC:${m.ac}/PR:${m.pr}/UI:${m.ui}/S:${m.s}/C:${m.c}/I:${m.i}/A:${m.a}`;
  return { score: Math.round(score * 10) / 10, vector };
}

export function severityLabel(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}
