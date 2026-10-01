/**
 * API endpoint discovery (active testing).
 *
 * Three sources, in order of signal quality:
 *  1. JavaScript bundles — fetch/XHR call strings and route patterns mined
 *     from the page's own scripts (same-origin, capped).
 *  2. Network traffic — paths observed in the TrafficLog.
 *  3. A small built-in wordlist of common API paths (no blind fuzzing:
 *     a fixed, conservative list — each candidate is one GET request).
 *
 * Every candidate is requested once via the rate-limited client and
 * classified by status code. Findings are aggregated so the report stays
 * readable; sensitive endpoints (admin/debug/docs) get their own findings.
 */
import { scoreFinding } from '../lib/cvss';
import type { Finding } from '../lib/types';
import type { ActiveHttpClient } from './httpClient';
import { redactedSnippet } from './httpClient';

let findingSeq = 0;
const MAX_CANDIDATES = 60;
const MAX_SCRIPT_BYTES = 500_000;
const MAX_SCRIPTS = 6;

function nextId(): string {
  findingSeq++;
  return `api-discover-${findingSeq}`;
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

/** Conservative built-in wordlist — common API paths only, no recursion. */
const COMMON_API_PATHS = [
  '/api', '/api/v1', '/api/v2', '/api/v3', '/v1', '/v2',
  '/rest', '/rest/v1', '/api/rest',
  '/graphql', '/graphiql', '/api/graphql', '/v1/graphql', '/graphql/console',
  '/api/docs', '/api/redoc', '/api/swagger', '/api/openapi.json',
  '/api/swagger.json', '/swagger.json', '/swagger-ui', '/openapi.json',
  '/api/schema', '/api/spec.json',
  '/api/health', '/api/status', '/health', '/status', '/ping',
  '/api/config', '/api/settings', '/api/version', '/api/info',
  '/api/users', '/api/user', '/api/me', '/api/profile', '/api/account',
  '/api/login', '/api/auth', '/api/token', '/api/register', '/api/logout',
  '/api/admin', '/api/internal', '/api/debug', '/api/test',
  '/api/metrics', '/metrics', '/actuator', '/actuator/health',
  '/api/search', '/api/upload', '/api/files', '/api/export',
  '/wp-json', '/wp-json/wp/v2',
  '/.well-known/security.txt', '/.well-known/change-password',
];

const STATIC_ASSET_RE = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|map|mp4|webm)(\?|#|$)/i;

/**
 * Mine candidate endpoint paths from JavaScript source: fetch/XHR strings,
 * axios/ajax url fields, and bare route-like literals.
 */
export function extractEndpointsFromCode(code: string): string[] {
  const found = new Set<string>();
  const patterns = [
    /\bfetch\s*\(\s*['"`]([^'"`]+)['"`]/g,
    /\baxios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(\s*['"`]([^'"`]+)['"`]/g,
    /\$\s*\.\s*ajax\s*\(\s*\{[^}]{0,400}?url\s*:\s*['"`]([^'"`]+)['"`]/g,
    /\burl\s*:\s*['"`](\/[^'"`\s]{1,120})['"`]/g,
    /\bnew\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]/g,
    /['"`](\/(?:api|rest|v\d+|graphql|graphiql|wp-json)[^'"`\s\\]{0,120})['"`]/g,
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    const fresh = new RegExp(re.source, re.flags);
    while ((m = fresh.exec(code)) !== null) {
      const raw = (m[1] ?? '').trim();
      if (!raw || raw.length > 160) continue;
      if (STATIC_ASSET_RE.test(raw)) continue;
      // Keep relative paths and same-origin absolute URLs; drop the rest.
      if (/^https?:\/\//i.test(raw)) {
        try {
          found.add(new URL(raw).pathname);
        } catch {
          /* ignore */
        }
      } else if (raw.startsWith('/')) {
        found.add(raw.split(/[?#]/)[0]);
      }
    }
    if (found.size > 200) break;
  }
  return [...found].filter((p) => p.length > 1 && !STATIC_ASSET_RE.test(p));
}

export interface DiscoveredEndpoint {
  path: string;
  method: string;
  status: number;
  contentType: string;
  source: 'js' | 'traffic' | 'wordlist';
  /** True for admin/debug/docs-like paths. */
  sensitive: boolean;
}

const SENSITIVE_PATH_RE =
  /\/(admin|administrator|phpmyadmin|debug|console|actuator|internal|private|test|staging|swagger|openapi|redoc|graphql|graphiql)\b/i;

export interface ApiDiscoveryResult {
  endpoints: DiscoveredEndpoint[];
  findings: Finding[];
  /** Paths worth handing to the GraphQL prober. */
  graphqlCandidates: string[];
}

/**
 * Discover endpoints. `scriptUrls` are same-origin script URLs to mine
 * (fetched through the rate-limited client); `trafficPaths` come from the
 * network analyzer.
 */
export async function discoverApiEndpoints(
  http: ActiveHttpClient,
  origin: string,
  scriptUrls: string[],
  trafficPaths: string[],
): Promise<ApiDiscoveryResult> {
  const candidates = new Map<string, 'js' | 'traffic' | 'wordlist'>();

  // 1. Mine JS bundles (same-origin only — enforced by caller filtering).
  const scripts = scriptUrls.slice(0, MAX_SCRIPTS);
  for (const src of scripts) {
    try {
      const res = await http.get(src);
      if (res.status === 200 && res.bodyText.length <= MAX_SCRIPT_BYTES) {
        for (const p of extractEndpointsFromCode(res.bodyText)) {
          if (!candidates.has(p)) candidates.set(p, 'js');
        }
      }
    } catch {
      /* skip unreachable scripts */
    }
    if (candidates.size >= MAX_CANDIDATES) break;
  }

  // 2. Traffic paths.
  for (const p of trafficPaths) {
    if (!candidates.has(p) && candidates.size < MAX_CANDIDATES) {
      candidates.set(p, 'traffic');
    }
  }

  // 3. Wordlist fill.
  for (const p of COMMON_API_PATHS) {
    if (candidates.size >= MAX_CANDIDATES) break;
    if (!candidates.has(p)) candidates.set(p, 'wordlist');
  }

  // Probe each candidate once.
  const endpoints: DiscoveredEndpoint[] = [];
  const before = http.limiter.getStats().requestsMade;
  for (const [path, source] of candidates) {
    const url = origin + path;
    try {
      const res = await http.get(url);
      if ([200, 201, 204, 301, 302, 401, 403, 405].includes(res.status)) {
        endpoints.push({
          path,
          method: 'GET',
          status: res.status,
          contentType: res.contentType,
          source,
          sensitive: SENSITIVE_PATH_RE.test(path),
        });
      }
    } catch {
      /* unreachable — not an endpoint */
    }
  }
  const requestsSpent = http.limiter.getStats().requestsMade - before;

  const findings = buildFindings(endpoints, requestsSpent);
  const graphqlCandidates = endpoints
    .filter((e) => /graphql|graphiql/i.test(e.path))
    .map((e) => e.path);

  return { endpoints, findings, graphqlCandidates };
}

function buildFindings(
  endpoints: DiscoveredEndpoint[],
  requestsSpent: number,
): Finding[] {
  const findings: Finding[] = [];
  if (endpoints.length === 0) return findings;

  const reachable = endpoints.filter((e) => e.status === 200);
  const protected_ = endpoints.filter((e) => [401, 403].includes(e.status));
  const methodHints = endpoints.filter((e) => e.status === 405);
  const sensitive = endpoints.filter((e) => e.sensitive);

  const summaryLines = endpoints
    .slice(0, 20)
    .map(
      (e) =>
        `GET ${e.path} → ${e.status}${e.contentType ? ` (${e.contentType})` : ''} [${e.source}]`,
    )
    .join('\n');

  findings.push({
    id: nextId(),
    category: 'api',
    mode: 'active',
    tags: ['api-endpoint'],
    title: `API surface mapped: ${endpoints.length} endpoint(s) respond`,
    description:
      `${endpoints.length} candidate paths responded (${reachable.length} × 200, ` +
      `${protected_.length} × 401/403, ${methodHints.length} × 405) across JS-bundle mining, traffic observation, and a small common-path wordlist. ` +
      `Each candidate cost one rate-limited GET (${requestsSpent} requests total).`,
    severity: 'info',
    confidence: 'high',
    confirmed: true,
    location: `${endpoints.length} endpoints`,
    evidence: redactedSnippet(summaryLines, 500),
    remediation:
      'Inventory these endpoints: confirm each is intentional, authenticated where needed, and covered by CORS and rate-limit policies.',
    ...cvssFields('api:endpoint-discovered'),
    reproSteps: [
      'Mine the page’s JavaScript bundles for fetch/XHR strings and route patterns.',
      'Combine with paths observed in network traffic.',
      'Request each candidate once (rate-limited) and record status codes.',
    ],
    requestCount: requestsSpent,
  });

  const docs = sensitive.filter((e) =>
    /swagger|openapi|redoc|\/docs/i.test(e.path),
  );
  for (const d of docs.slice(0, 3)) {
    findings.push({
      id: nextId(),
      category: 'api',
      mode: 'active',
      tags: ['api-endpoint', 'api-docs'],
      title: `API documentation publicly exposed: ${d.path}`,
      description:
        `GET ${d.path} returned ${d.status} with ${d.contentType || 'unknown content type'}. ` +
        'Machine-readable API docs disclose endpoints, parameters, and data models to unauthenticated users.',
      severity: 'low',
      confidence: 'high',
      confirmed: true,
      location: d.path,
      evidence: `GET ${d.path} → ${d.status} (${d.contentType || 'no content-type'})`,
      remediation:
        'Restrict API documentation to authenticated developers or internal networks; do not deploy Swagger UI to production.',
      ...cvssFields('api:docs-exposed'),
      requestCount: 1,
    });
  }

  const risky = sensitive.filter(
    (e) => !/swagger|openapi|redoc|\/docs/i.test(e.path),
  );
  for (const r of risky.slice(0, 5)) {
    findings.push({
      id: nextId(),
      category: 'api',
      mode: 'active',
      tags: ['api-endpoint', 'api-admin'],
      title: `Sensitive endpoint reachable: ${r.path} (${r.status})`,
      description:
        `GET ${r.path} returned ${r.status} — an admin, debug, or internal-looking endpoint is reachable. ` +
        'Its authorization checks were not bypassed during testing; verify it requires proper authentication.',
      severity: r.status === 200 ? 'medium' : 'low',
      confidence: 'medium',
      confirmed: r.status === 200,
      location: r.path,
      evidence: `GET ${r.path} → ${r.status}`,
      remediation:
        'Ensure admin/debug/internal endpoints require strong authentication, are IP-restricted, or are removed from production.',
      ...cvssFields('api:sensitive-endpoint'),
      requestCount: 1,
    });
  }

  return findings;
}
