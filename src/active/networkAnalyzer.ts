/**
 * Network traffic analysis (active testing).
 *
 * Consumes the TrafficLog (the tab's own requests + our probe traffic) and
 * surfaces interesting endpoints and parameters as findings:
 *  - sensitive parameter names in URLs (tokens, session ids, passwords)
 *  - CORS misconfigurations observed in live traffic
 *  - interesting endpoints (API, admin, debug, GraphQL, actuators…)
 *  - mixed-content subresources, unusual methods, auth header usage
 *
 * All evidence is metadata-level: parameter names and header values only,
 * never bodies or parameter values.
 */
import { scoreFinding } from '../lib/cvss';
import type { Finding } from '../lib/types';
import { SENSITIVE_PARAM_RE, type TrafficEntry } from './traffic';
import { redactedSnippet } from './httpClient';

let findingSeq = 0;
const MAX_FINDINGS = 25;

function nextId(kind: string): string {
  findingSeq++;
  return `net-${kind}-${findingSeq}`;
}

function cvssFields(presetKey: string): Pick<
  Finding, 'cvssScore' | 'cvssVector' | 'cvssJustification' | 'references'
> {
  const s = scoreFinding(presetKey);
  return {
    cvssScore: s.score,
    cvssVector: s.vector,
    cvssJustification: s.justification,
    references: s.references,
  };
}

/** Path segments that mark an endpoint as interesting. */
const INTERESTING_PATH_RE =
  /\/(api|rest|v\d+|graphql|graphiql|admin|administrator|debug|console|actuator|metrics|health|status|internal|private|test|staging|dev|swagger|openapi|wp-json)\b/i;

const UNUSUAL_METHODS = new Set(['PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS']);

export interface NetworkAnalysis {
  findings: Finding[];
  /** Distinct API-ish paths seen — reused by apiDiscovery/idor. */
  endpointPaths: string[];
  /** True when the overall posture looks good (feeds honeypot inconsistency signal). */
  postureGood: boolean;
}

export function analyzeTraffic(entries: TrafficEntry[]): NetworkAnalysis {
  const findings: Finding[] = [];
  const push = (f: Finding): void => {
    if (findings.length < MAX_FINDINGS) findings.push(f);
  };

  // --- 1. Sensitive parameter names in query strings (CWE-598). ---
  const sensitiveParams = new Map<string, string>(); // "host+path" -> param names
  for (const e of entries) {
    const hits = e.paramNames.filter((n) => SENSITIVE_PARAM_RE.test(n));
    if (hits.length > 0) {
      const key = `${e.host}${e.path}`;
      sensitiveParams.set(key, [...new Set([...(sensitiveParams.get(key)?.split(', ') ?? []), ...hits])].join(', '));
    }
  }
  for (const [where, params] of sensitiveParams) {
    push({
      id: nextId('query-params'),
      category: 'network',
      mode: 'active',
      tags: ['sensitive-query-param'],
      title: 'Sensitive data transmitted in URL query string',
      description:
        `The parameter(s) ${params} appear in request URLs to ${where}. ` +
        'Tokens, session identifiers, and passwords in URLs leak into browser history, server logs, proxies, and Referer headers. ' +
        'Values were not recorded — only parameter names were observed.',
      severity: 'high',
      confidence: 'high',
      confirmed: true,
      location: where,
      evidence: `query params: ${params}`,
      remediation:
        'Move secrets out of URLs: use Authorization headers or POST bodies over HTTPS, and rotate any tokens known to have traveled in URLs.',
      ...cvssFields('network:sensitive-query-params'),
      reproSteps: [
        `Observe requests to ${where} in the extension's traffic capture.`,
        'Note the sensitive parameter names in the query string.',
        'Confirm the same parameters are not also sent via headers/body.',
      ],
      requestCount: 0,
    });
  }

  // --- 2. CORS misconfigurations observed in live traffic. ---
  const corsBad = new Map<string, string>();
  for (const e of entries) {
    const h = e.responseHeaders;
    if (!h) continue;
    const acao = h['access-control-allow-origin'] ?? '';
    const acac = (h['access-control-allow-credentials'] ?? '').toLowerCase() === 'true';
    if (acao === '*' && acac) {
      corsBad.set(`${e.host}${e.path}`, 'wildcard + credentials');
    } else if (acao && acao !== '*' && acao !== 'null' && acac) {
      // Can't prove reflection from one sample; note as candidate.
      corsBad.set(`${e.host}${e.path}`, `allows-origin ${acao} + credentials`);
    }
  }
  for (const [where, what] of corsBad) {
    push({
      id: nextId('cors-observed'),
      category: 'cors',
      mode: 'active',
      tags: ['cors-creds'],
      title: 'Overly permissive CORS policy observed in traffic',
      description:
        `A response from ${where} sets ${what}. Any website can make credentialed cross-origin requests and read the responses.`,
      severity: 'high',
      confidence: 'high',
      confirmed: true,
      location: where,
      evidence: what,
      remediation:
        'Replace wildcard/reflected origins with an explicit allow-list of trusted origins, and only send Access-Control-Allow-Credentials for those origins. Consider Vary: Origin.',
      ...cvssFields('network:cors-observed'),
      reproSteps: [
        `Request ${where} with an arbitrary Origin header.`,
        'Observe Access-Control-Allow-Origin echoing the origin with credentials allowed.',
      ],
      requestCount: 0,
    });
  }

  // --- 3. Interesting endpoints observed. ---
  const interesting = new Map<string, { methods: Set<string>; types: Set<string> }>();
  for (const e of entries) {
    if (!INTERESTING_PATH_RE.test(e.path)) continue;
    // Skip static assets.
    if (/\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|map)(\?|$)/i.test(e.path)) continue;
    const key = `${e.host}${e.path}`;
    let rec = interesting.get(key);
    if (!rec) {
      rec = { methods: new Set(), types: new Set() };
      interesting.set(key, rec);
    }
    rec.methods.add(e.method);
    if (e.contentType) rec.types.add(e.contentType);
    if (interesting.size > 40) break;
  }
  const endpointPaths = [...interesting.keys()].map((k) => {
    const idx = k.indexOf('/');
    return idx === -1 ? '/' : k.slice(idx);
  });
  if (interesting.size > 0) {
    const list = [...interesting.entries()]
      .slice(0, 15)
      .map(([k, v]) => `${[...v.methods].join(',')} ${k}`)
      .join('\n');
    push({
      id: nextId('endpoints'),
      category: 'network',
      mode: 'active',
      tags: ['api-endpoint'],
      title: `Interesting endpoints observed in traffic (${interesting.size})`,
      description:
        'API, admin, debug, or otherwise sensitive-looking endpoints were seen in the tab’s own traffic. ' +
        'These are the highest-value targets for follow-up testing (CORS, IDOR, auth checks).',
      severity: 'info',
      confidence: 'high',
      confirmed: true,
      location: `${interesting.size} endpoint(s)`,
      evidence: redactedSnippet(list, 400),
      remediation:
        'Review each endpoint for authentication, authorization, and CORS posture; remove or protect debug/internal endpoints in production.',
      ...cvssFields('network:interesting-endpoint'),
      requestCount: 0,
    });
  }

  // --- 4. Mixed content. ---
  const mixed = new Set<string>();
  for (const e of entries) {
    if (
      e.source === 'tab' &&
      e.url.startsWith('http://') &&
      !/^(localhost|127\.0\.0\.1)/.test(e.host)
    ) {
      mixed.add(`${e.method} ${e.host}${e.path}`);
    }
  }
  if (mixed.size > 0) {
    push({
      id: nextId('mixed-content'),
      category: 'network',
      mode: 'active',
      tags: ['mixed-content'],
      title: `Mixed content: ${mixed.size} plain-HTTP subresource(s) on an HTTPS page`,
      description:
        'Active subresources are loaded over plain HTTP, letting network attackers tamper with page content.',
      severity: 'medium',
      confidence: 'high',
      confirmed: true,
      evidence: redactedSnippet([...mixed].slice(0, 8).join('\n'), 400),
      remediation: 'Serve all subresources over HTTPS; add upgrade-insecure-requests to the Content-Security-Policy.',
      ...cvssFields('network:mixed-content'),
      requestCount: 0,
    });
  }

  // --- 5. Unusual HTTP methods in use. ---
  const unusual = new Set<string>();
  for (const e of entries) {
    if (UNUSUAL_METHODS.has(e.method)) unusual.add(`${e.method} ${e.host}${e.path}`);
  }
  if (unusual.size > 0) {
    push({
      id: nextId('methods'),
      category: 'network',
      mode: 'active',
      tags: ['unusual-method'],
      title: `Unusual HTTP methods observed (${unusual.size})`,
      description:
        'PUT/DELETE/PATCH/TRACE/OPTIONS requests were observed. Verify these methods are intentionally enabled and properly authorized — ' +
        'TRACE in particular enables cross-site tracing attacks.',
      severity: 'info',
      confidence: 'medium',
      confirmed: true,
      evidence: redactedSnippet([...unusual].slice(0, 10).join('\n'), 400),
      remediation: 'Disable unneeded HTTP methods (especially TRACE) at the server or WAF layer.',
      ...cvssFields('network:interesting-endpoint'),
      requestCount: 0,
    });
  }

  // --- 6. Authorization header usage (names only). ---
  const authUsage = new Set<string>();
  for (const e of entries) {
    if (e.paramNames.some((n) => /^authorization$/i.test(n))) {
      authUsage.add(`${e.host}${e.path}`);
    }
  }
  if (authUsage.size > 0) {
    push({
      id: nextId('auth-headers'),
      category: 'network',
      mode: 'active',
      tags: ['auth-header-usage'],
      title: `Authorization headers used on ${authUsage.size} endpoint(s)`,
      description:
        'Requests carry Authorization headers (header names only were recorded). Confirm tokens are short-lived, scoped, and never logged server-side.',
      severity: 'info',
      confidence: 'medium',
      confirmed: true,
      evidence: redactedSnippet([...authUsage].slice(0, 8).join('\n'), 400),
      remediation: 'Use short-lived tokens with least-privilege scopes; never log Authorization header values.',
      ...cvssFields('network:interesting-endpoint'),
      requestCount: 0,
    });
  }

  const postureGood =
    findings.filter((f) => f.severity === 'high' || f.severity === 'critical').length === 0;

  return { findings, endpointPaths, postureGood };
}
