/**
 * Honeypot / trap detection (product plan §4.5).
 *
 * Every finding gets a trap-probability score in [0, 1] from multiple
 * signals, combined with noisy-or so independent signals reinforce each
 * other. Findings at or above TRAP_FLAG_THRESHOLD are flagged
 * (finding.honeypotSuspect = true) and presented as "possible trap — verify
 * manually", NOT reported as vulnerabilities.
 *
 * Signals (from the plan):
 *  - Suspiciously easy discovery: trivially findable "vulnerabilities"
 *    (e.g. /admin with admin:admin on the first try).
 *  - Known trap signatures: Thinkst Canary tokens, Cowrie/HoneyDB markers.
 *  - Inconsistency: the rest of the app is well-secured but one endpoint is
 *    absurdly open.
 *  - Behavioral anomalies: a login that accepts ANY credentials without
 *    establishing a session; forms that accept anything with identical
 *    generic responses.
 *  - Response analysis: deliberately-vulnerable demo apps get a small bump.
 */
import { TRAP_FLAG_THRESHOLD } from './config';
import type { Finding } from './types';

export interface TrapContext {
  /** Total findings in this scan (a lone critical among many clean checks is suspicious). */
  totalFindings: number;
  /** True when security headers are broadly present. */
  headerPostureGood: boolean;
  /** True when cookies are broadly well-flagged. */
  cookiePostureGood: boolean;
  /** Lowercased hostname of the target (demo apps get a small bump). */
  targetHost: string;
}

export interface TrapScore {
  probability: number;
  signals: string[];
  suspect: boolean;
}

/** Thinkst Canary token host patterns and other known trap markers. */
const CANARY_HOST_RE =
  /(^|\.)canarytokens\.(com|org|net)$|canarytoken/i;
const CANARY_VALUE_RE =
  /canary|thinkst/i;
const HONEYPOT_TOOL_RE =
  /cowrie|honeyd|honeydb|dionaea|kippo|glastopf|conpot/i;
/** Paths that scream "deliberate trap" when paired with trivial access. */
const TRAP_PATH_RE =
  /\/(admin|administrator|wp-admin|phpmyadmin)(\/|$)/i;
/** Well-known default credential pairs (public knowledge, not secrets). */
const DEFAULT_CREDS_RE =
  /\badmin\s*[:/]\s*(admin|password|123456)\b/i;
/** Hosts that are intentionally vulnerable by design. */
const DEMO_HOST_RE =
  /(juice|dvwa|demo|test|vuln|hackthebox|tryhackme|pentest|bWAPP|mutillidae)/i;

interface Signal {
  weight: number;
  label: string;
  test: (f: Finding, ctx: TrapContext) => boolean;
}

const SIGNALS: Signal[] = [
  {
    weight: 0.65,
    label: 'Known trap signature: canary token or honeypot tool marker detected',
    test: (f) => {
      const hay = `${f.location ?? ''} ${f.evidence ?? ''} ${f.title}`;
      return (
        CANARY_HOST_RE.test(hay) ||
        CANARY_VALUE_RE.test(f.evidence ?? '') ||
        HONEYPOT_TOOL_RE.test(hay)
      );
    },
  },
  {
    weight: 0.45,
    label:
      'Suspiciously easy discovery: trivial path/credential yielded a critical result immediately',
    test: (f) => {
      const hay = `${f.location ?? ''} ${f.title} ${f.description}`;
      const trivialPath =
        TRAP_PATH_RE.test(f.location ?? '') && f.requestCount !== undefined && f.requestCount <= 3;
      const trivialCreds =
        (f.tags ?? []).includes('default-creds') &&
        DEFAULT_CREDS_RE.test(`${f.title} ${f.evidence ?? ''}`);
      return (
        trivialPath ||
        trivialCreds ||
        (/first attempt/i.test(hay) && f.severity === 'critical')
      );
    },
  },
  {
    weight: 0.35,
    label:
      'Behavioral anomaly: authentication accepts arbitrary credentials without establishing a real session',
    test: (f) =>
      (f.tags ?? []).includes('auth-anomaly') ||
      /accepts any credentials|never actually authenticates/i.test(
        `${f.title} ${f.description}`,
      ),
  },
  {
    weight: 0.3,
    label:
      'Inconsistency: rest of the application is well-secured but this one issue is glaringly open',
    test: (f, ctx) =>
      (f.severity === 'critical' || f.severity === 'high') &&
      f.mode === 'active' &&
      ctx.headerPostureGood &&
      ctx.cookiePostureGood &&
      !(f.tags ?? []).includes('xss-confirmed'),
  },
  {
    weight: 0.15,
    label:
      'Target looks like a deliberately vulnerable demo app — findings may be intentional',
    test: (_f, ctx) => DEMO_HOST_RE.test(ctx.targetHost),
  },
];

/** Noisy-or combination: 1 - Π(1 - w_i). */
function combine(weights: number[]): number {
  let p = 0;
  for (const w of weights) p = p + w - p * w;
  return Math.min(1, Math.max(0, p));
}

export function scoreTrapProbability(
  f: Finding,
  ctx: TrapContext,
): TrapScore {
  const hit: string[] = [];
  const weights: number[] = [];
  for (const s of SIGNALS) {
    let matched = false;
    try {
      matched = s.test(f, ctx);
    } catch {
      matched = false;
    }
    if (matched) {
      hit.push(s.label);
      weights.push(s.weight);
    }
  }
  const probability = Math.round(combine(weights) * 100) / 100;
  return {
    probability,
    signals: hit,
    suspect: probability >= TRAP_FLAG_THRESHOLD,
  };
}

/**
 * Attach trap scores to every finding in place. Returns the subset that was
 * flagged as possible traps.
 */
export function applyTrapScoring(
  findings: Finding[],
  ctx: TrapContext,
): Finding[] {
  const flagged: Finding[] = [];
  for (const f of findings) {
    const score = scoreTrapProbability(f, ctx);
    f.trapProbability = score.probability;
    f.trapSignals = score.signals;
    f.honeypotSuspect = score.suspect;
    if (score.suspect) flagged.push(f);
  }
  return flagged;
}
