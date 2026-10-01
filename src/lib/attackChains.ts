/**
 * Attack-chain reasoning hooks (product plan §4.4 / Phase 3 intelligence).
 *
 * Individual findings are linked into higher-impact chains (e.g.
 * "CORS misconfiguration + state-changing API → account takeover") using
 * tag/category/title predicates. The structures and the local matcher run
 * entirely in the extension; the backend AI agent can deepen them later via
 * apiClient.deepenAttackChains() — the hooks for that handoff live here.
 */
import type { AttackChain, Finding, Severity } from './types';
import { SEVERITY_ORDER } from './types';

let chainSeq = 0;

function hasTag(f: Finding, ...tags: string[]): boolean {
  return (f.tags ?? []).some((t) => tags.includes(t));
}

function titleHas(f: Finding, ...needles: string[]): boolean {
  const t = f.title.toLowerCase();
  return needles.some((n) => t.includes(n.toLowerCase()));
}

interface ChainPattern {
  id: string;
  title: string;
  description: string;
  impact: string;
  /** Minimum severity for the chain regardless of members. */
  minSeverity: Severity;
  confidence: 'high' | 'medium' | 'low';
  /** All groups must match at least one finding each (AND of ORs). */
  groups: Array<(f: Finding) => boolean>;
}

/**
 * Chain patterns. Predicates deliberately overlap tags from the active
 * modules (see docs/schemas.md for the tag vocabulary).
 */
const PATTERNS: ChainPattern[] = [
  {
    id: 'cors-to-account-takeover',
    title: 'CORS misconfiguration → cross-site request forgery → account takeover',
    description:
      'A CORS policy that allows attacker origins with credentials combines with reachable state-changing API endpoints. ' +
      'An attacker site can issue credentialed cross-origin requests as the victim and read the responses.',
    impact:
      'Full account takeover: attacker can read and invoke privileged API actions in the victim session.',
    minSeverity: 'high',
    confidence: 'medium',
    groups: [
      (f) => hasTag(f, 'cors-creds'),
      (f) => hasTag(f, 'api-endpoint') || f.category === 'api',
    ],
  },
  {
    id: 'xss-to-session-hijack',
    title: 'Confirmed XSS + session cookie without HttpOnly → session hijacking',
    description:
      'A confirmed cross-site scripting sink executes in the application origin while the session cookie lacks the HttpOnly flag, ' +
      'so injected script can exfiltrate the session token.',
    impact:
      'Session hijacking: attacker steals the victim session and acts as the victim.',
    minSeverity: 'high',
    confidence: 'high',
    groups: [
      (f) => hasTag(f, 'xss-confirmed'),
      (f) =>
        f.category === 'cookies' &&
        (titleHas(f, 'httponly') || /httponly/i.test(f.description)),
    ],
  },
  {
    id: 'idor-to-data-exposure',
    title: 'Predictable resource IDs → mass record enumeration',
    description:
      'Sequential resource identifiers return record-shaped data for neighboring IDs, and the records carry personal-data field names. ' +
      'Combined, this suggests missing object-level authorization across an enumerable ID space.',
    impact:
      'Bulk exposure of other users’ records (PII) via trivial ID enumeration.',
    minSeverity: 'high',
    confidence: 'medium',
    groups: [
      (f) => hasTag(f, 'idor-enumerable'),
      (f) => hasTag(f, 'idor-pii-fields'),
    ],
  },
  {
    id: 'default-creds-to-admin',
    title: 'Default credentials + exposed admin surface → full compromise',
    description:
      'Default credentials were accepted (authorized test) and an administrative endpoint/panel is reachable, giving the ' +
      'default account a privileged attack surface.',
    impact:
      'Full application compromise with the privileges of the default account.',
    minSeverity: 'critical',
    confidence: 'high',
    groups: [
      (f) => hasTag(f, 'default-creds'),
      (f) => hasTag(f, 'api-admin') || titleHas(f, 'admin'),
    ],
  },
  {
    id: 'graphql-introspection-to-mutation',
    title: 'GraphQL introspection + dangerous mutations → data manipulation',
    description:
      'An enabled introspection endpoint discloses the schema while mutations with destructive or privileged semantics are exposed. ' +
      'The schema knowledge makes targeted mutation abuse practical.',
    impact:
      'Unauthorized data modification or deletion via exposed mutations.',
    minSeverity: 'high',
    confidence: 'medium',
    groups: [
      (f) => hasTag(f, 'graphql-introspection'),
      (f) => hasTag(f, 'graphql-mutation-dangerous'),
    ],
  },
  {
    id: 'secret-to-api-abuse',
    title: 'Exposed API secret + discovered API surface → API abuse',
    description:
      'A hardcoded API key or token was found in client-side code while the API surface it likely authorizes was mapped. ' +
      'The secret may grant direct API access outside the application’s controls.',
    impact:
      'Abuse of backend APIs with a leaked credential (data access, quota burn, privilege-dependent actions).',
    minSeverity: 'high',
    confidence: 'medium',
    groups: [
      (f) => f.category === 'secrets',
      (f) => hasTag(f, 'api-endpoint'),
    ],
  },
  {
    id: 'query-token-to-session-theft',
    title: 'Tokens in URLs + reflected XSS hint → token theft',
    description:
      'Sensitive tokens travel in URL query strings (leaking to history/logs/Referer) while reflected input hints at an XSS sink ' +
      'that could exfiltrate them from the DOM.',
    impact: 'Theft of session/API tokens via log exposure or script injection.',
    minSeverity: 'medium',
    confidence: 'low',
    groups: [
      (f) => hasTag(f, 'sensitive-query-param'),
      (f) => hasTag(f, 'xss-hint') || hasTag(f, 'xss-confirmed'),
    ],
  },
];

function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER[a] <= SEVERITY_ORDER[b] ? a : b;
}

/**
 * Match chain patterns against findings. Mutates findings by appending the
 * chain id to finding.attackChainIds. Returns the built chains.
 */
export function buildAttackChains(findings: Finding[]): AttackChain[] {
  const chains: AttackChain[] = [];
  const usable = findings.filter((f) => !f.honeypotSuspect);

  for (const pattern of PATTERNS) {
    const members: Finding[] = [];
    const seen = new Set<string>();
    let matched = true;
    for (const group of pattern.groups) {
      const hit = usable.find((f) => !seen.has(f.id) && group(f));
      if (!hit) {
        matched = false;
        break;
      }
      seen.add(hit.id);
      members.push(hit);
    }
    if (!matched || members.length === 0) continue;

    chainSeq++;
    const id = `chain-${pattern.id}-${chainSeq}`;
    const severity = members.reduce<Severity>(
      (acc, f) => maxSeverity(acc, f.severity),
      pattern.minSeverity,
    );
    const cvssScores = members
      .map((f) => f.cvssScore ?? 0)
      .filter((s) => s > 0);
    const chain: AttackChain = {
      id,
      title: pattern.title,
      description: pattern.description,
      findingIds: members.map((f) => f.id),
      severity,
      confidence: pattern.confidence,
      cvssScore:
        cvssScores.length > 0 ? Math.max(...cvssScores) : undefined,
      impact: pattern.impact,
    };
    chains.push(chain);

    for (const m of members) {
      m.attackChainIds = [...(m.attackChainIds ?? []), id];
      if (m.category !== 'chain') {
        // keep original category; chain membership is tracked via attackChainIds
      }
    }
  }

  return chains.sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
}

/**
 * Payload the backend AI agent consumes to deepen/verify chains.
 * The extension serializes chains + the member findings; the backend
 * returns verdicts which the popup can display (see apiClient).
 */
export interface ChainDeepeningRequest {
  targetUrl: string;
  chains: Array<{
    id: string;
    title: string;
    description: string;
    impact: string;
    findingIds: string[];
  }>;
  findings: Array<{
    id: string;
    title: string;
    severity: Severity;
    cvssScore?: number;
    evidence?: string;
    location?: string;
  }>;
}

export function buildChainDeepeningRequest(
  targetUrl: string,
  chains: AttackChain[],
  findings: Finding[],
): ChainDeepeningRequest {
  const byId = new Map(findings.map((f) => [f.id, f]));
  return {
    targetUrl,
    chains: chains.map((c) => ({
      id: c.id,
      title: c.title,
      description: c.description,
      impact: c.impact,
      findingIds: c.findingIds,
    })),
    findings: chains
      .flatMap((c) => c.findingIds)
      .filter((id, i, arr) => arr.indexOf(id) === i)
      .map((id) => byId.get(id))
      .filter((f): f is Finding => !!f)
      .map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        cvssScore: f.cvssScore,
        evidence: f.evidence,
        location: f.location,
      })),
  };
}
