/**
 * IDOR / predictable-resource-ID checks (active testing).
 *
 *  1. Find candidate object references: numeric path segments, numeric query
 *     params (id, user_id, order_id…), and UUIDs — from discovered endpoints
 *     and traffic.
 *  2. For SEQUENTIAL numeric IDs, request the immediate neighbors (id±1)
 *     through the rate-limited client, strictly inside the authorized scope.
 *  3. Compare responses: status, shape, and JSON FIELD NAMES (values are
 *     never recorded). Neighbor IDs returning record-shaped data with
 *     personal-data field names → access-control anomaly.
 *
 * This test is unauthenticated-by-design from the extension (the service
 * worker cannot and will not replay the user's session cookies). A neighbor
 * returning another record's shape is therefore a strong broken-access
 * signal, reported with field names only — never values.
 */
import { scoreFinding } from '../lib/cvss';
import type { Finding } from '../lib/types';
import type { ActiveHttpClient } from './httpClient';
import { redactedSnippet } from './httpClient';
import type { DiscoveredEndpoint } from './apiDiscovery';
import type { TrafficEntry } from './traffic';

let findingSeq = 0;
const MAX_TARGETS = 5;

function nextId(): string {
  findingSeq++;
  return `idor-${findingSeq}`;
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

/** Numeric path segment, e.g. /users/12345 */
const NUMERIC_SEGMENT_RE = /\/(\d{1,10})(?=\/|$)/;
/** UUID-looking segment — unguessable, a positive signal. */
const UUID_RE = /\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/i;
/** Query params that usually reference objects. */
const ID_PARAM_RE = /^(id|user_id|userid|account_id|order_id|customer_id|doc_id|file_id|record_id)$/i;
/** JSON field names suggesting personal data (names only are recorded). */
const PII_FIELD_RE =
  /^(email|e_mail|name|first_name|last_name|full_name|phone|mobile|address|street|city|zip|postal|ssn|social_security|dob|date_of_birth|birthdate|passport|national_id|credit_card|card_number|iban|salary|password_hash)$/i;

interface IdTarget {
  url: string;
  kind: 'path' | 'query';
  idValue: string;
}

function targetsFromEndpoints(
  endpoints: DiscoveredEndpoint[],
  origin: string,
): IdTarget[] {
  const out: IdTarget[] = [];
  for (const e of endpoints) {
    if (out.length >= MAX_TARGETS) break;
    const m = e.path.match(NUMERIC_SEGMENT_RE);
    if (m) {
      out.push({ url: origin + e.path, kind: 'path', idValue: m[1] });
    }
  }
  return out;
}

function targetsFromTraffic(entries: TrafficEntry[]): IdTarget[] {
  const out: IdTarget[] = [];
  const seen = new Set<string>();
  for (const e of entries) {
    if (out.length >= MAX_TARGETS) break;
    if (e.source !== 'tab' && e.source !== 'probe') continue;
    const key = `${e.method} ${e.host}${e.path}`;
    if (seen.has(key)) continue;
    const m = e.path.match(NUMERIC_SEGMENT_RE);
    if (m && !UUID_RE.test(e.path)) {
      seen.add(key);
      try {
        const u = new URL(e.url);
        out.push({ url: u.origin + u.pathname + u.search, kind: 'path', idValue: m[1] });
        continue;
      } catch {
        /* fall through to query check */
      }
    }
    // Numeric id-ish query params.
    try {
      const u = new URL(e.url);
      for (const [name, value] of u.searchParams) {
        if (ID_PARAM_RE.test(name) && /^\d{1,10}$/.test(value)) {
          seen.add(key);
          out.push({ url: u.origin + u.pathname + u.search, kind: 'query', idValue: value });
          break;
        }
      }
    } catch {
      /* ignore */
    }
  }
  return out;
}

/** Extract top-level JSON field names (values discarded). */
function jsonFieldNames(body: string): string[] {
  try {
    const j = JSON.parse(body);
    const obj = Array.isArray(j) ? j[0] : j?.data ?? j;
    if (obj && typeof obj === 'object') {
      return Object.keys(obj).slice(0, 40);
    }
  } catch {
    /* not JSON */
  }
  return [];
}

function neighborUrls(target: IdTarget, origin: string): string[] {
  const n = parseInt(target.idValue, 10);
  if (!Number.isSafeInteger(n)) return [];
  const out: string[] = [];
  for (const delta of [-1, 1]) {
    const neighbor = n + delta;
    if (neighbor < 0) continue;
    if (target.kind === 'path') {
      out.push(target.url.replace(`/${target.idValue}`, `/${neighbor}`));
    } else {
      try {
        const u = new URL(target.url, origin);
        for (const [name, value] of [...u.searchParams]) {
          if (value === target.idValue) u.searchParams.set(name, String(neighbor));
        }
        out.push(u.toString());
      } catch {
        /* skip */
      }
    }
  }
  return out;
}

export interface IdorResult {
  findings: Finding[];
}

export async function checkIdor(
  http: ActiveHttpClient,
  origin: string,
  endpoints: DiscoveredEndpoint[],
  traffic: TrafficEntry[],
): Promise<IdorResult> {
  const findings: Finding[] = [];
  const before = http.limiter.getStats().requestsMade;

  const targets = [
    ...targetsFromEndpoints(endpoints, origin),
    ...targetsFromTraffic(traffic),
  ].slice(0, MAX_TARGETS);

  // Positive signal: UUIDs in use.
  const uuidSeen = [...endpoints.map((e) => e.path), ...traffic.map((t) => t.path)].some((p) =>
    UUID_RE.test(p),
  );
  if (uuidSeen) {
    findings.push({
      id: nextId(),
      category: 'idor',
      mode: 'active',
      tags: ['idor-unguessable'],
      title: 'Unguessable resource identifiers (UUIDs) observed',
      description:
        'Some object references use UUIDs, which are not enumerable. Good practice — direct object references elsewhere should follow the same pattern.',
      severity: 'info',
      confidence: 'medium',
      confirmed: true,
      remediation: 'Prefer unguessable identifiers AND enforce server-side object-level authorization.',
      ...cvssFields('idor:review-hint'),
      requestCount: 0,
    });
  }

  for (const target of targets) {
    // Baseline: the original ID.
    let baseFields: string[] = [];
    let baseStatus = 0;
    try {
      const res = await http.get(target.url);
      baseStatus = res.status;
      if (res.status === 200 && res.contentType.includes('json')) {
        baseFields = jsonFieldNames(res.bodyText);
      }
    } catch {
      continue;
    }
    if (baseStatus !== 200) continue;

    // Neighbors.
    const neighborResults: Array<{ url: string; status: number; fields: string[] }> = [];
    for (const nUrl of neighborUrls(target, origin)) {
      try {
        const res = await http.get(nUrl);
        neighborResults.push({
          url: nUrl,
          status: res.status,
          fields:
            res.status === 200 && res.contentType.includes('json')
              ? jsonFieldNames(res.bodyText)
              : [],
        });
      } catch {
        /* neighbor unreachable */
      }
    }

    const served = neighborResults.filter((r) => r.status === 200 && r.fields.length > 0);
    if (served.length === 0) {
      const rejected = neighborResults.filter((r) => [401, 403, 404].includes(r.status));
      findings.push({
        id: nextId(),
        category: 'idor',
        mode: 'active',
        tags: ['idor'],
        title: `Predictable resource ID at ${new URL(target.url).pathname} — neighbors not enumerable`,
        description:
          `The resource uses a sequential numeric ID (${target.idValue}), but neighboring IDs were rejected ` +
          `(${rejected.map((r) => r.status).join(', ') || 'no response'}). Object-level authorization may be in place — verify manually in an authenticated session.`,
        severity: 'info',
        confidence: 'medium',
        confirmed: false,
        location: new URL(target.url).pathname,
        evidence: `id=${target.idValue} (sequential); neighbors → ${neighborResults.map((r) => r.status).join(', ') || 'unreachable'}`,
        remediation:
          'Confirm object-level authorization server-side: every ID lookup must verify the requester owns (or may access) the record.',
        ...cvssFields('idor:review-hint'),
      });
      continue;
    }

    // Neighbors served record-shaped data — check for PII field names.
    const piiFields = [...new Set(served.flatMap((r) => r.fields))].filter((f) =>
      PII_FIELD_RE.test(f),
    );
    const shapeMatch =
      baseFields.length > 0 &&
      served.some((r) => r.fields.length > 0 && r.fields[0] === baseFields[0]);

    if (piiFields.length > 0) {
      findings.push({
        id: nextId(),
        category: 'idor',
        mode: 'active',
        tags: ['idor-enumerable', 'idor-pii-fields'],
        title: `Sequential IDs expose records with personal-data fields — possible IDOR`,
        description:
          `Neighboring IDs of ${target.idValue} returned record-shaped JSON containing personal-data field names ` +
          `(${piiFields.slice(0, 8).join(', ')}). Field VALUES were not recorded. Unauthenticated enumeration of ` +
          `other records suggests missing object-level authorization — verify in an authenticated session whether these belong to other users.`,
        severity: 'high',
        confidence: 'medium',
        confirmed: true,
        location: new URL(target.url).pathname,
        evidence: redactedSnippet(
          `neighbor IDs served JSON with fields: ${[...new Set(served.flatMap((r) => r.fields))].slice(0, 12).join(', ')}`,
          400,
        ),
        remediation:
          'Enforce object-level authorization on every record lookup; use unguessable IDs; never rely on ID secrecy alone.',
        ...cvssFields('idor:predictable-ids'),
        reproSteps: [
          `GET ${target.url} and note the JSON structure.`,
          `GET the same path with the numeric ID ±1.`,
          'Compare: neighboring IDs return record-shaped data with personal-data field names.',
        ],
      });
    } else if (shapeMatch) {
      findings.push({
        id: nextId(),
        category: 'idor',
        mode: 'active',
        tags: ['idor-enumerable'],
        title: 'Sequential resource IDs are enumerable — verify access control',
        description:
          `Neighboring IDs of ${target.idValue} returned the same record shape, so the ID space is enumerable. ` +
          'No personal-data field names were seen in the unauthenticated responses, but object-level authorization should still be verified manually.',
        severity: 'medium',
        confidence: 'medium',
        confirmed: true,
        location: new URL(target.url).pathname,
        evidence: `id=${target.idValue} neighbors → 200 with matching record shape`,
        remediation:
          'Verify server-side that each ID lookup checks the requester’s permission for that specific record.',
        ...cvssFields('idor:predictable-ids'),
        reproSteps: [
          `GET ${target.url}.`,
          'GET the same path with the numeric ID ±1 and compare response shapes.',
        ],
      });
    }
  }

  const spent = http.limiter.getStats().requestsMade - before;
  const per = findings.length > 0 ? Math.max(1, Math.round(spent / findings.length)) : 0;
  for (const f of findings) {
    if (f.requestCount === undefined) f.requestCount = per;
  }
  return { findings };
}
