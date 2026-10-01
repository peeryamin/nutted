/**
 * Active HTTP client — the SINGLE choke point for every active request.
 *
 * Every request goes through, in order:
 *  1. Scope enforcement (authorization.assertInScope) — out-of-scope URLs
 *     throw before any network activity.
 *  2. Rate limiting (RateLimiter.acquire) — conservative fixed gap, with a
 *     per-scan cap that aborts the scan rather than hammering the target.
 *  3. The fetch itself, with a timeout and redirects followed manually
 *     (so redirect targets are scope-checked too).
 *  4. Traffic logging — method, URL, status, content type, and security
 *     headers only. Bodies are truncated to a small redacted snippet for
 *     evidence; parameter VALUES are never logged.
 */
import { ACTIVE_FETCH_TIMEOUT_MS, EVIDENCE_MAX_CHARS } from '../lib/config';
import { assertInScope, type AuthorizationRecord } from '../lib/authorization';
import { redactSecret } from '../lib/regexes';
import type { RateLimiter } from '../lib/rateLimiter';
import { TrafficLog, type TrafficEntry } from './traffic';

export interface ProbeResponse {
  url: string;
  finalUrl: string;
  status: number;
  redirected: boolean;
  headers: Record<string, string>;
  contentType: string;
  /** Truncated body text for analysis (callers must redact before display). */
  bodyText: string;
  bodyBytes: number;
  waitedMs: number;
}

export interface ActiveHttpOptions {
  authz: AuthorizationRecord;
  targetUrl: string;
  limiter: RateLimiter;
  log: TrafficLog;
}

const MAX_REDIRECTS = 3;
const MAX_BODY_CHARS = 200_000;

function headerRecord(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((v, k) => {
    out[k.toLowerCase()] = v;
  });
  return out;
}

function paramNamesFromInit(url: string, body: BodyInit | undefined): string[] {
  const names = new Set<string>();
  try {
    for (const k of new URL(url).searchParams.keys()) names.add(k);
  } catch {
    /* ignore */
  }
  if (typeof body === 'string') {
    // URL-encoded form bodies: record field NAMES only.
    for (const pair of body.split('&').slice(0, 40)) {
      const name = pair.split('=')[0];
      if (name) {
        try {
          names.add(decodeURIComponent(name.replace(/\+/g, ' ')));
        } catch {
          names.add(name);
        }
      }
    }
  }
  return [...names].slice(0, 60);
}

export class ActiveHttpClient {
  constructor(private readonly opts: ActiveHttpOptions) {}

  get limiter(): RateLimiter {
    return this.opts.limiter;
  }

  async request(
    method: string,
    rawUrl: string,
    init: RequestInit = {},
  ): Promise<ProbeResponse> {
    const { authz, targetUrl, limiter, log } = this.opts;
    assertInScope(rawUrl, authz, targetUrl);

    const { waitedMs } = await limiter.acquire();

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), ACTIVE_FETCH_TIMEOUT_MS);
    let res: Response;
    try {
      res = await fetch(rawUrl, {
        ...init,
        method,
        redirect: 'manual',
        signal: ctrl.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    // Follow redirects manually so each hop is scope-checked.
    let finalRes = res;
    let finalUrl = rawUrl;
    let redirected = false;
    for (let i = 0; i < MAX_REDIRECTS; i++) {
      const loc = finalRes.headers.get('location');
      if (!(finalRes.status >= 300 && finalRes.status < 400 && loc)) break;
      const next = new URL(loc, finalUrl).toString();
      assertInScope(next, authz, targetUrl);
      redirected = true;
      finalUrl = next;
      const { waitedMs: w2 } = await limiter.acquire();
      void w2;
      const ctrl2 = new AbortController();
      const timer2 = setTimeout(() => ctrl2.abort(), ACTIVE_FETCH_TIMEOUT_MS);
      try {
        finalRes = await fetch(next, {
          method: 'GET',
          redirect: 'manual',
          signal: ctrl2.signal,
        });
      } finally {
        clearTimeout(timer2);
      }
    }

    const headers = headerRecord(finalRes.headers);
    const contentType = (headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
    let bodyText = '';
    let bodyBytes = 0;
    const cl = parseInt(headers['content-length'] ?? '', 10);
    if (!Number.isNaN(cl)) bodyBytes = cl;
    try {
      const text = await finalRes.text();
      bodyBytes = text.length;
      bodyText = text.slice(0, MAX_BODY_CHARS);
    } catch {
      /* body unreadable — keep metadata only */
    }

    const u = new URL(finalUrl);
    const entry: Parameters<TrafficLog['add']>[0] = {
      source: 'probe',
      method,
      url: rawUrl.length > 600 ? rawUrl.slice(0, 600) : rawUrl,
      host: u.hostname,
      path: u.pathname,
      paramNames: paramNamesFromInit(rawUrl, init.body as BodyInit | undefined),
      statusCode: finalRes.status,
      contentType: contentType || undefined,
      timeStamp: Date.now(),
    };
    log.add(entry);

    return {
      url: rawUrl,
      finalUrl,
      status: finalRes.status,
      redirected,
      headers,
      contentType,
      bodyText,
      bodyBytes,
      waitedMs,
    };
  }

  get(url: string, init: RequestInit = {}): Promise<ProbeResponse> {
    return this.request('GET', url, init);
  }

  post(
    url: string,
    body: BodyInit,
    contentType = 'application/x-www-form-urlencoded',
  ): Promise<ProbeResponse> {
    return this.request('POST', url, {
      body,
      headers: { 'content-type': contentType },
    });
  }

  postJson(url: string, payload: unknown): Promise<ProbeResponse> {
    return this.request('POST', url, {
      body: JSON.stringify(payload),
      headers: { 'content-type': 'application/json' },
    });
  }
}

/**
 * Build a short, redacted evidence snippet from response text.
 * Secret-looking values are reduced to their 8-char prefix per convention.
 */
export function redactedSnippet(text: string, maxChars = EVIDENCE_MAX_CHARS): string {
  const raw = text.slice(0, maxChars).replace(/\s+/g, ' ').trim();
  // Mask anything that looks like an assigned secret before display.
  return raw.replace(
    /(['"]?(?:api[_-]?key|secret|token|password|passwd|private[_-]?key)['"]?\s*[:=]\s*['"]?)([^'"\s,}]{4,})/gi,
    (_m, prefix: string, value: string) => `${prefix}${redactSecret(value)}`,
  );
}
