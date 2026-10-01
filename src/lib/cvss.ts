/**
 * CVSS v3.1 base-score calculator with per-finding presets and justifications.
 *
 * Implements the official FIRST CVSS v3.1 specification formulas, plus a
 * preset table mapping each active-testing finding kind to suggested metrics
 * and a human-readable justification (product plan: "CVSS v3.1 severity
 * scoring with justification for each finding").
 */

export type AvMetric = 'N' | 'A' | 'L' | 'P';
export type AcMetric = 'L' | 'H';
export type PrMetric = 'N' | 'L' | 'H';
export type UiMetric = 'N' | 'R';
export type ScopeMetric = 'U' | 'C';
export type CiaMetric = 'N' | 'L' | 'H';

export interface CvssMetrics {
  AV: AvMetric;
  AC: AcMetric;
  PR: PrMetric;
  UI: UiMetric;
  S: ScopeMetric;
  C: CiaMetric;
  I: CiaMetric;
  A: CiaMetric;
}

export interface CvssResult {
  score: number;
  vector: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'none';
}

const AV_VAL: Record<AvMetric, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC_VAL: Record<AcMetric, number> = { L: 0.77, H: 0.44 };
const UI_VAL: Record<UiMetric, number> = { N: 0.85, R: 0.62 };
const CIA_VAL: Record<CiaMetric, number> = { N: 0, L: 0.22, H: 0.56 };

function prValue(pr: PrMetric, scopeChanged: boolean): number {
  if (pr === 'N') return 0.85;
  if (pr === 'L') return scopeChanged ? 0.68 : 0.62;
  return scopeChanged ? 0.5 : 0.27;
}

/** Official CVSS v3.1 Roundup: smallest 1-decimal number >= input. */
function roundup(input: number): number {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  const floored = Math.floor(intInput / 10000) * 10000;
  return (floored + 10000) / 100000;
}

export function calculateCvss(m: CvssMetrics): CvssResult {
  const scopeChanged = m.S === 'C';
  const iscBase =
    1 -
    (1 - CIA_VAL[m.C]) * (1 - CIA_VAL[m.I]) * (1 - CIA_VAL[m.A]);

  let impact: number;
  if (!scopeChanged) {
    impact = 6.42 * iscBase;
  } else if (iscBase <= 0) {
    impact = 0;
  } else {
    impact =
      7.52 * (iscBase - 0.029) -
      3.25 * Math.pow(iscBase - 0.02, 15);
  }

  const exploitability =
    8.22 * AV_VAL[m.AV] * AC_VAL[m.AC] * prValue(m.PR, scopeChanged) * UI_VAL[m.UI];

  let score: number;
  if (impact <= 0) {
    score = 0;
  } else if (!scopeChanged) {
    score = roundup(Math.min(impact + exploitability, 10));
  } else {
    score = roundup(Math.min(1.08 * (impact + exploitability), 10));
  }
  // Normalize -0 / floating artifacts.
  score = Math.round(score * 10) / 10;

  const vector =
    `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}` +
    `/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;

  const severity =
    score >= 9.0 ? 'critical'
    : score >= 7.0 ? 'high'
    : score >= 4.0 ? 'medium'
    : score > 0 ? 'low'
    : 'none';

  return { score, vector, severity };
}

/** A preset: metrics + the justification shown to the user. */
export interface CvssPreset {
  metrics: CvssMetrics;
  justification: string;
  references: string[];
}

/**
 * Preset key → CVSS preset. Keys are '<category>:<kind>' chosen by each
 * active module; unknown keys fall back to a conservative default.
 */
const PRESETS: Record<string, CvssPreset> = {
  'cors:wildcard-credentials': {
    metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'H', I: 'L', A: 'N' },
    justification:
      'Exploitable remotely over the network with no privileges. The victim must visit an attacker-controlled page (UI:R). ' +
      'With Access-Control-Allow-Origin: * plus Allow-Credentials, any site can read credentialed responses, giving high confidentiality impact; ' +
      'limited integrity impact since the attacker can only read, not write, via this vector.',
    references: ['https://cwe.mitre.org/data/definitions/942.html'],
  },
  'cors:reflected-credentials': {
    metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'H', I: 'L', A: 'N' },
    justification:
      'The server reflects arbitrary Origin values with credentials allowed. Any attacker site can issue credentialed cross-origin ' +
      'requests and read the responses (UI:R — victim visits attacker page). High confidentiality impact on session-bound data.',
    references: ['https://cwe.mitre.org/data/definitions/942.html'],
  },
  'cors:null-origin': {
    metrics: { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' },
    justification:
      'The server trusts the "null" origin with credentials. Exploitation needs a sandboxed context (AC:H) and victim interaction (UI:R), ' +
      'so impact is limited, but allow-listed null origins are a known bypass primitive.',
    references: ['https://cwe.mitre.org/data/definitions/942.html'],
  },
  'cors:reflected-no-credentials': {
    metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
    justification:
      'Origin is reflected but credentials are not allowed, so only public resources are readable cross-origin. Low confidentiality impact; ' +
      'flagged because reflection often coexists with credential support on other endpoints.',
    references: ['https://cwe.mitre.org/data/definitions/942.html'],
  },
  'xss:confirmed': {
    metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' },
    justification:
      'Reflected XSS was CONFIRMED by executing a marker payload and observing the DOM change. Network-exploitable, no privileges needed, ' +
      'victim interaction required (UI:R). Scope changes because script runs in the application origin, compromising session-scoped ' +
      'confidentiality and integrity of the victim session.',
    references: ['https://cwe.mitre.org/data/definitions/79.html'],
  },
  'xss:review-hint': {
    metrics: { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' },
    justification:
      'Input is reflected in the response but payload execution was NOT confirmed (blocked by CSP, encoding, or context). ' +
      'High attack complexity reflects the unconfirmed status — treat as a manual review hint, not a vulnerability.',
    references: ['https://cwe.mitre.org/data/definitions/79.html'],
  },
  'graphql:introspection': {
    metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
    justification:
      'GraphQL introspection is enabled, disclosing the full schema (types, queries, mutations) to unauthenticated users. ' +
      'Low direct confidentiality impact, but it materially assists targeted follow-on attacks.',
    references: ['https://cwe.mitre.org/data/definitions/200.html'],
  },
  'graphql:dangerous-mutation': {
    metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'H', A: 'N' },
    justification:
      'Mutations with destructive or privileged semantics are exposed. Depending on authorization checks, an unauthenticated ' +
      'attacker may be able to modify or delete data — high integrity impact is assumed pending access-control verification.',
    references: ['https://cwe.mitre.org/data/definitions/862.html'],
  },
  'graphql:batching': {
    metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'L' },
    justification:
      'The endpoint executes batched queries, which amplifies brute-force and enumeration attacks against login or token fields. ' +
      'Low direct impact; relevant as a force multiplier in attack chains.',
    references: ['https://cwe.mitre.org/data/definitions/799.html'],
  },
  'idor:predictable-ids': {
    metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },
    justification:
      'Sequential/predictable resource identifiers allow unauthenticated enumeration of records. Neighboring IDs returned record-shaped ' +
      'data, indicating missing object-level authorization — high confidentiality impact if records belong to other users.',
    references: ['https://cwe.mitre.org/data/definitions/639.html'],
  },
  'idor:review-hint': {
    metrics: { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
    justification:
      'Predictable identifiers were observed but access-control behavior was inconclusive (neighbors rejected or identical). ' +
      'Manual verification of object-level authorization is recommended.',
    references: ['https://cwe.mitre.org/data/definitions/639.html'],
  },
  'auth:default-credentials': {
    metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
    justification:
      'A well-known default credential pair was accepted by the login form (explicitly authorized test). Full authentication bypass ' +
      'with the privileges of the default account — total compromise of confidentiality, integrity, and availability of that account.',
    references: ['https://cwe.mitre.org/data/definitions/798.html'],
  },
  'auth:brute-force-indicators': {
    metrics: { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
    justification:
      'No brute-force protections were observed (no rate limiting, lockout, or CAPTCHA signals on repeated failed logins). ' +
      'This is a missing control rather than an exploited flaw — high attack complexity because exploitation still needs credential guessing.',
    references: ['https://cwe.mitre.org/data/definitions/307.html'],
  },
  'api:docs-exposed': {
    metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
    justification:
      'Machine-readable API documentation (Swagger/OpenAPI) is publicly accessible, disclosing endpoints, parameters, and data models. ' +
      'Aids targeted attacks; no direct data compromise.',
    references: ['https://cwe.mitre.org/data/definitions/200.html'],
  },
  'api:sensitive-endpoint': {
    metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
    justification:
      'An administrative, debug, or internal endpoint is reachable. Direct impact depends on its authorization checks, which were not ' +
      'bypassed during testing — review manually for exposed functionality.',
    references: ['https://cwe.mitre.org/data/definitions/200.html'],
  },
  'api:endpoint-discovered': {
    metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N' },
    justification:
      'Informational: an API endpoint was discovered and is reachable. Recorded for attack-surface mapping; not a vulnerability by itself.',
    references: [],
  },
  'network:sensitive-query-params': {
    metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
    justification:
      'Credentials or session tokens are transmitted in URL query strings, where they leak into browser history, logs, and Referer headers. ' +
      'High confidentiality impact for the exposed token material.',
    references: ['https://cwe.mitre.org/data/definitions/598.html'],
  },
  'network:mixed-content': {
    metrics: { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' },
    justification:
      'Active content is loaded over plain HTTP on an HTTPS page, enabling network attackers to tamper with it (AC:H — requires network position; ' +
      'UI:R — victim loads the page).',
    references: ['https://cwe.mitre.org/data/definitions/319.html'],
  },
  'network:cors-observed': {
    metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'H', I: 'L', A: 'N' },
    justification:
      'Observed in live traffic: the response allows any origin with credentials. Same impact as a probed wildcard CORS misconfiguration.',
    references: ['https://cwe.mitre.org/data/definitions/942.html'],
  },
  'network:interesting-endpoint': {
    metrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N' },
    justification:
      'Informational: an interesting endpoint (API, admin, debug, GraphQL) was observed in the tab traffic. Useful for scoping follow-up tests.',
    references: [],
  },
};

const DEFAULT_PRESET: CvssPreset = {
  metrics: { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
  justification:
    'Conservative default: remotely reachable with no privileges, but exploitability or impact is unconfirmed. Adjust after manual review.',
  references: [],
};

/** Look up a preset by key, falling back to the conservative default. */
export function cvssPresetFor(key: string): CvssPreset {
  return PRESETS[key] ?? DEFAULT_PRESET;
}

/**
 * Score a finding: returns score/vector/justification/references.
 * Callers pass the preset key chosen by their module.
 */
export function scoreFinding(presetKey: string): CvssResult & {
  justification: string;
  references: string[];
} {
  const preset = cvssPresetFor(presetKey);
  const result = calculateCvss(preset.metrics);
  return {
    ...result,
    justification: preset.justification,
    references: preset.references,
  };
}
