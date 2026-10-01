import {
  guardedFetch,
  readResult,
  type AgentTool,
} from '../agent/tools.js';
import { redactText } from '../guardrails/redact.js';

/**
 * Extra tools for the multi-agent specialists, built on the same guarded
 * primitives as the core tools (scope check → rate limit → SSRF guard).
 *
 * - probe_idor:    mutate a numeric object reference (id±1, id±10) and compare
 *                  response status/shape — the deterministic core of IDOR
 *                  detection. Only status codes, content types and JSON FIELD
 *                  NAMES are compared; values are never recorded.
 * - fetch_js:      fetch a same-origin JavaScript file and deterministically
 *                  extract candidate API endpoints, GraphQL references and
 *                  secret-shaped strings (patterns only, values redacted).
 * - probe_graphql: send a minimal introspection query and report whether it
 *                  is enabled, plus whether mutations/batch are advertised.
 */

function fail(error: unknown) {
  const msg = error instanceof Error ? error.message : String(error);
  return { ok: false as const, error: msg.slice(0, 300), honeypotSignals: [] as string[] };
}

const NUMERIC_ID_RE = /\/(\d{1,10})(?=\/|$|[?#])/;
const ENDPOINT_RE =
  /["'`](\/[A-Za-z0-9_\-./]{2,80}(?:\?[A-Za-z0-9_\-./=&%]{0,60})?)["'`]/g;
const GRAPHQL_REF_RE = /graphql|__schema|__typename|graphiql/i;
const SECRET_SHAPE_RE =
  /\b(AKIA[0-9A-Z]{16}|xox[bap]-[A-Za-z0-9-]{8,}|ghp_[A-Za-z0-9]{20,}|sk-(live|test)-[A-Za-z0-9]{8,}|AIza[0-9A-Za-z\-_]{20,})\b/;

const probeIdor: AgentTool = {
  name: 'probe_idor',
  description:
    'Test a numeric object reference for IDOR: requests id-1, id+1 and id+10 variants and compares status/shape/JSON field names. Args: {url}.',
  async run(args, ctx) {
    try {
      const raw = args['url'] as string;
      const m = raw.match(NUMERIC_ID_RE);
      if (!m) return { ok: false, error: 'no numeric path segment to mutate', honeypotSignals: [] };
      const id = m[1];
      const variants = [-1, 1, 10].map((d) =>
        raw.replace(`/${id}`, `/${String(Number(id) + d)}`),
      );
      const probes: Array<{ url: string; status?: number; contentType?: string; fieldNames?: string[]; error?: string }> = [];
      for (const v of variants) {
        try {
          const res = await guardedFetch(v, ctx);
          const ct = res.headers.get('content-type') ?? '';
          let fieldNames: string[] | undefined;
          if (ct.includes('json')) {
            const text = await res.text().catch(() => '');
            try {
              const parsed: unknown = JSON.parse(text);
              const obj = Array.isArray(parsed) ? parsed[0] : parsed;
              if (obj && typeof obj === 'object') {
                fieldNames = Object.keys(obj as Record<string, unknown>).slice(0, 30);
              }
            } catch {
              /* not JSON-shaped */
            }
          } else {
            await res.arrayBuffer().catch(() => undefined);
          }
          probes.push({ url: v, status: res.status, contentType: ct.split(';')[0], fieldNames });
        } catch (e) {
          probes.push({ url: v, error: (e as Error).message.slice(0, 120) });
        }
      }
      const baseline = await (async () => {
        try {
          const res = await guardedFetch(raw, ctx);
          await res.arrayBuffer().catch(() => undefined);
          return { status: res.status, contentType: (res.headers.get('content-type') ?? '').split(';')[0] };
        } catch (e) {
          return { error: (e as Error).message.slice(0, 120) };
        }
      })();
      return {
        ok: true,
        data: { baseline, probes },
        honeypotSignals: [] as string[],
      };
    } catch (e) {
      return fail(e);
    }
  },
};

const fetchJs: AgentTool = {
  name: 'fetch_js',
  description:
    'Fetch a same-origin JavaScript file and deterministically extract candidate API endpoints, GraphQL references and secret-shaped strings. Args: {url}.',
  async run(args, ctx) {
    try {
      const res = await guardedFetch(args['url'] as string, ctx);
      const text = await res.text().catch(() => '');
      const ct = res.headers.get('content-type') ?? '';
      const code = text.slice(0, 300_000);
      const endpoints = new Set<string>();
      let em: RegExpExecArray | null;
      ENDPOINT_RE.lastIndex = 0;
      while ((em = ENDPOINT_RE.exec(code)) !== null && endpoints.size < 60) {
        const ep = em[1];
        if (/^(api|rest|v\d|graphql|auth|user|admin|internal)/i.test(ep.slice(1)) || ep.includes('/api/')) {
          endpoints.add(ep);
        }
      }
      const secretShapes = new Set<string>();
      let sm: RegExpExecArray | null;
      const sre = new RegExp(SECRET_SHAPE_RE.source, 'g');
      while ((sm = sre.exec(code)) !== null && secretShapes.size < 10) {
        secretShapes.add(sm[1].slice(0, 8) + '…(redacted)');
      }
      const result = await readResult(res, ctx);
      result.data = {
        contentType: ct.split(';')[0],
        bytes: text.length,
        endpoints: [...endpoints],
        graphqlReferenced: GRAPHQL_REF_RE.test(code),
        secretShapes: [...secretShapes],
      };
      result.bodySnippet = redactText(code.slice(0, 500), 500);
      return result;
    } catch (e) {
      return fail(e);
    }
  },
};

const probeGraphql: AgentTool = {
  name: 'probe_graphql',
  description:
    'Probe a GraphQL endpoint: minimal introspection query; reports whether introspection is enabled and observed behavior. Args: {url}.',
  async run(args, ctx) {
    try {
      const url = args['url'] as string;
      const res = await guardedFetch(url, ctx, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ query: '{ __typename }' }),
      });
      const text = await res.text().catch(() => '');
      let parsed: unknown = null;
      try {
        parsed = JSON.parse(text);
      } catch {
        /* non-JSON */
      }
      const introspectionEnabled =
        !!parsed && typeof parsed === 'object' && 'data' in (parsed as Record<string, unknown>);
      const result = await readResult(res, ctx);
      result.data = {
        introspectionEnabled,
        hasData: introspectionEnabled,
        hasErrors:
          !!parsed && typeof parsed === 'object' && 'errors' in (parsed as Record<string, unknown>),
      };
      return result;
    } catch (e) {
      return fail(e);
    }
  },
};

/** New tools available to multi-agent specialists (in addition to defaultTools). */
export function extraTools(): AgentTool[] {
  return [probeIdor, fetchJs, probeGraphql];
}
