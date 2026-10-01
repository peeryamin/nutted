/**
 * GraphQL introspection probing (active testing).
 *
 *  1. Detect GraphQL endpoints (discovery candidates + common paths + hints
 *     in JS/traffic).
 *  2. Confirm with a minimal `{__typename}` query.
 *  3. Attempt introspection; enumerate query/mutation/subscription fields.
 *  4. Flag exposed dangerous mutations and batch-query support.
 *
 * Only introspection-shaped queries are sent — no destructive mutations are
 * ever executed.
 */
import { scoreFinding } from '../lib/cvss';
import type { Finding } from '../lib/types';
import type { ActiveHttpClient } from './httpClient';
import { redactedSnippet } from './httpClient';

let findingSeq = 0;
const MAX_MUTATIONS_LISTED = 25;

function nextId(): string {
  findingSeq++;
  return `gql-${findingSeq}`;
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

const COMMON_GRAPHQL_PATHS = [
  '/graphql',
  '/graphiql',
  '/api/graphql',
  '/v1/graphql',
  '/v2/graphql',
  '/graphql/console',
  '/api/graphiql',
];

const INTROSPECTION_QUERY = `{
  __schema {
    queryType { name fields { name } }
    mutationType { name fields { name } }
    subscriptionType { name fields { name } }
  }
}`;

const DANGEROUS_MUTATION_RE =
  /(delete|drop|remove|destroy|admin|createUser|updateUser|deleteUser|reset|impersonate|escalate|grant|revoke|disable|wipe|truncate)/i;

interface SchemaSummary {
  queries: string[];
  mutations: string[];
  subscriptions: string[];
}

function isGraphqlResponse(body: string): boolean {
  try {
    const j = JSON.parse(body);
    return (
      typeof j === 'object' &&
      j !== null &&
      ('data' in j || 'errors' in j)
    );
  } catch {
    return false;
  }
}

function summarizeSchema(body: string): SchemaSummary | null {
  try {
    const j = JSON.parse(body);
    const schema = j?.data?.__schema;
    if (!schema) return null;
    const names = (t: { fields?: Array<{ name?: string }> } | null): string[] =>
      (t?.fields ?? []).map((f) => f.name ?? '').filter(Boolean);
    return {
      queries: names(schema.queryType),
      mutations: names(schema.mutationType),
      subscriptions: names(schema.subscriptionType),
    };
  } catch {
    return null;
  }
}

export interface GraphqlResult {
  endpoints: string[];
  findings: Finding[];
}

export async function probeGraphql(
  http: ActiveHttpClient,
  origin: string,
  candidates: string[],
): Promise<GraphqlResult> {
  const findings: Finding[] = [];
  const endpoints: string[] = [];
  const before = http.limiter.getStats().requestsMade;

  const paths = [...new Set([...candidates, ...COMMON_GRAPHQL_PATHS])].slice(0, 8);

  for (const path of paths) {
    const url = origin + path;
    let confirmed = false;

    // Step 1: confirm it's GraphQL with a minimal query.
    try {
      const res = await http.postJson(url, { query: '{__typename}' });
      if (res.status === 200 && isGraphqlResponse(res.bodyText)) {
        confirmed = true;
      } else if (res.status === 400 && /graphql|syntax/i.test(res.bodyText)) {
        // A GraphQL-shaped error still confirms the endpoint.
        confirmed = true;
      }
    } catch {
      continue;
    }
    if (!confirmed) continue;
    endpoints.push(url);

    // Step 2: introspection.
    let schema: SchemaSummary | null = null;
    try {
      const res = await http.postJson(url, { query: INTROSPECTION_QUERY });
      if (res.status === 200) schema = summarizeSchema(res.bodyText);
    } catch {
      /* introspection failed — endpoint still confirmed */
    }

    if (schema) {
      const totalFields =
        schema.queries.length + schema.mutations.length + schema.subscriptions.length;
      const mutationsListed = schema.mutations.slice(0, MAX_MUTATIONS_LISTED);
      findings.push({
        id: nextId(),
        category: 'graphql',
        mode: 'active',
        tags: ['graphql-introspection'],
        title: `GraphQL introspection enabled at ${path}`,
        description:
          `Introspection is enabled: the full schema is disclosed (${schema.queries.length} queries, ` +
          `${schema.mutations.length} mutations, ${schema.subscriptions.length} subscriptions). ` +
          'Attackers can enumerate every operation and craft targeted queries/mutations.',
        severity: 'medium',
        confidence: 'high',
        confirmed: true,
        location: url,
        evidence: redactedSnippet(
          `queries(${schema.queries.length}): ${schema.queries.slice(0, 10).join(', ')}\n` +
            `mutations(${schema.mutations.length}): ${mutationsListed.join(', ')}` +
            (schema.mutations.length > MAX_MUTATIONS_LISTED ? ', …' : ''),
          500,
        ),
        remediation:
          'Disable introspection in production (and the GraphiQL explorer). If introspection must stay, gate it behind authentication.',
        ...cvssFields('graphql:introspection'),
        reproSteps: [
          `POST ${url} with JSON body {"query": "{ __schema { queryType { name } } }"}.`,
          'Observe the full schema in the response.',
        ],
      });

      // Step 3: dangerous mutations.
      const dangerous = schema.mutations.filter((m) => DANGEROUS_MUTATION_RE.test(m));
      if (dangerous.length > 0) {
        findings.push({
          id: nextId(),
          category: 'graphql',
          mode: 'active',
          tags: ['graphql-mutation-dangerous'],
          title: `Potentially dangerous GraphQL mutations exposed (${dangerous.length})`,
          description:
            `Mutations with destructive or privileged semantics are visible: ${dangerous.slice(0, 10).join(', ')}. ` +
            'Their authorization was not tested (no mutations are executed by this tool) — verify object-level access control manually.',
          severity: 'medium',
          confidence: 'medium',
          confirmed: false,
          location: url,
          evidence: redactedSnippet(dangerous.slice(0, 15).join(', '), 400),
          remediation:
            'Apply field-level authorization to every mutation; disable introspection so the operation list is not public.',
          ...cvssFields('graphql:dangerous-mutation'),
          reproSteps: [
            `POST ${url} with an introspection query and list mutationType fields.`,
            'Review each mutation for authorization checks.',
          ],
        });
      }
      void totalFields;
    } else {
      findings.push({
        id: nextId(),
        category: 'graphql',
        mode: 'active',
        tags: ['graphql-endpoint'],
        title: `GraphQL endpoint confirmed at ${path} (introspection disabled or blocked)`,
        description:
          'The endpoint answers GraphQL queries but introspection did not return a schema — good posture. ' +
          'Recorded for attack-surface mapping.',
        severity: 'info',
        confidence: 'high',
        confirmed: true,
        location: url,
        evidence: `POST ${url} {"query":"{__typename}"} → GraphQL-shaped response`,
        remediation: 'Keep introspection disabled in production.',
        ...cvssFields('api:endpoint-discovered'),
      });
    }

    // Step 4: batching support (force multiplier for brute force).
    try {
      const res = await http.postJson(url, [
        { query: '{__typename}' },
        { query: '{__typename}' },
      ]);
      if (res.status === 200) {
        try {
          const j = JSON.parse(res.bodyText);
          if (Array.isArray(j) && j.length === 2) {
            findings.push({
              id: nextId(),
              category: 'graphql',
              mode: 'active',
              tags: ['graphql-batching'],
              title: `GraphQL batching enabled at ${path}`,
              description:
                'The endpoint executes batched (array) queries. Batching amplifies brute-force, enumeration, and DoS attacks ' +
                'against login, token, and search fields.',
              severity: 'low',
              confidence: 'high',
              confirmed: true,
              location: url,
              evidence: 'POST array of 2 queries → array of 2 responses',
              remediation:
                'Disable query batching or enforce per-batch complexity/cost limits and rate limiting.',
              ...cvssFields('graphql:batching'),
              reproSteps: [
                `POST ${url} with a JSON array of two {"query":"{__typename}"} objects.`,
                'Observe an array of two responses.',
              ],
            });
          }
        } catch {
          /* not batch-capable */
        }
      }
    } catch {
      /* ignore */
    }

    // One confirmed endpoint is usually enough; keep probing cheap.
    if (endpoints.length >= 2) break;
  }

  const requestsMade = http.limiter.getStats().requestsMade - before;
  const perFinding = findings.length > 0 ? Math.max(1, Math.round(requestsMade / findings.length)) : 0;
  for (const f of findings) f.requestCount = perFinding;
  return { endpoints, findings };
}
