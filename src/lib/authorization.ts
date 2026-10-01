/**
 * Authorization records for active testing (product plan §8 — legal guardrails).
 *
 * Active testing is LOCKED until the user completes the explicit confirmation
 * flow in the popup: they state their authorization basis (bug bounty program,
 * pentest contract, or ownership), define scope boundaries (included hosts,
 * excluded hosts/paths), and optionally gate login-form probing separately.
 *
 * Every active HTTP request passes through `assertInScope()` before it is
 * sent. The record is stored per target host in chrome.storage.local and a
 * snapshot is attached to each active ScanResult for accountability.
 */
import { STORAGE_KEYS } from './config';
import type { AuthorizationRecord, ScopePolicy } from './types';

export type { AuthorizationRecord, ScopePolicy };

let idSeq = 0;

export function newAuthorizationId(): string {
  idSeq++;
  return `authz-${Date.now().toString(36)}-${idSeq}`;
}

function keyForHost(host: string): string {
  return `${STORAGE_KEYS.authzPrefix}${host.toLowerCase()}`;
}

export async function getAuthorization(
  host: string,
): Promise<AuthorizationRecord | null> {
  const stored = await chrome.storage.local.get(keyForHost(host));
  const rec = stored[keyForHost(host)] as AuthorizationRecord | undefined;
  return rec ?? null;
}

export async function saveAuthorization(rec: AuthorizationRecord): Promise<void> {
  await chrome.storage.local.set({ [keyForHost(rec.targetHost)]: rec });
}

export async function revokeAuthorization(host: string): Promise<void> {
  await chrome.storage.local.remove(keyForHost(host));
}

/**
 * Normalize a hostname for comparison (lowercase, strip trailing dot and
 * any port the user may have pasted).
 */
export function normalizeHost(host: string): string {
  return host
    .trim()
    .toLowerCase()
    .replace(/:\d+$/, '')
    .replace(/\.$/, '');
}

/** True when `host` is the record's target host or an allowed subdomain. */
export function hostCoveredBy(host: string, rec: AuthorizationRecord): boolean {
  const h = normalizeHost(host);
  const target = normalizeHost(rec.targetHost);
  if (h === target) return true;
  if (
    (rec.scope.mode === 'full-domain' || rec.scope.includeSubdomains) &&
    h.endsWith(`.${target}`)
  ) {
    return true;
  }
  return false;
}

/**
 * Enforce scope on a candidate request URL. Returns null when allowed, or a
 * human-readable reason when the request must NOT be sent.
 */
export function scopeCheck(
  rawUrl: string,
  rec: AuthorizationRecord,
  targetUrl: string,
): string | null {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return `Refusing to request malformed URL: ${rawUrl}`;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return `Refusing non-HTTP(S) URL: ${url.protocol}//${url.host}`;
  }
  if (rec.scope.mode === 'page') {
    const target = new URL(targetUrl);
    if (
      url.origin !== target.origin ||
      url.pathname !== target.pathname
    ) {
      return `Scope is page-only (${targetUrl}); refusing ${rawUrl}`;
    }
    return null;
  }
  if (!hostCoveredBy(url.hostname, rec)) {
    return `Host ${url.hostname} is outside the authorized scope (${rec.targetHost})`;
  }
  const excludedHost = rec.scope.excludedHosts
    .map(normalizeHost)
    .some(
      (ex) => url.hostname === ex || url.hostname.endsWith(`.${ex}`),
    );
  if (excludedHost) {
    return `Host ${url.hostname} is explicitly excluded from scope`;
  }
  const excludedPath = rec.scope.excludedPaths.some((p) => {
    const prefix = p.startsWith('/') ? p : `/${p}`;
    return url.pathname === prefix || url.pathname.startsWith(`${prefix}/`);
  });
  if (excludedPath) {
    return `Path ${url.pathname} is explicitly excluded from scope`;
  }
  return null;
}

/** Throw when the URL is out of scope — the single choke point for probes. */
export function assertInScope(
  rawUrl: string,
  rec: AuthorizationRecord,
  targetUrl: string,
): void {
  const reason = scopeCheck(rawUrl, rec, targetUrl);
  if (reason) throw new Error(reason);
}

/** One-line human summary of the scope for the popup UI. */
export function summarizeScope(rec: AuthorizationRecord): string {
  const bits: string[] = [];
  bits.push(
    rec.scope.mode === 'page'
      ? 'this page only'
      : rec.scope.mode === 'subdomain'
        ? `host ${rec.targetHost}`
        : `*.${rec.targetHost} + host`,
  );
  if (rec.scope.excludedHosts.length > 0) {
    bits.push(`excluding hosts: ${rec.scope.excludedHosts.join(', ')}`);
  }
  if (rec.scope.excludedPaths.length > 0) {
    bits.push(`excluding paths: ${rec.scope.excludedPaths.join(', ')}`);
  }
  return bits.join('; ');
}

const BASIS_LABEL: Record<AuthorizationRecord['type'], string> = {
  'bug-bounty': 'Bug bounty program',
  'pentest-contract': 'Pentest contract',
  ownership: 'I own this target',
};

export function basisLabel(type: AuthorizationRecord['type']): string {
  return BASIS_LABEL[type];
}
