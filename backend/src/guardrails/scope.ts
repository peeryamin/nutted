import dns from 'node:dns/promises';
import net from 'node:net';
import type { ScopePolicy } from '../types.js';

/**
 * LEGAL GUARDRAIL — scope enforcement (product plan §8).
 *
 * The agent must respect defined scope boundaries. Every URL the agent (or any
 * active-testing tool) touches passes through `assertUrlAllowed` / `isUrlInScope`.
 * There is no code path for active requests that skips this check.
 */

export function normalizeTargetUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw Object.assign(new Error('Invalid target URL'), { statusCode: 400 });
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw Object.assign(new Error('Target URL must use http(s)'), { statusCode: 400 });
  }
  return url;
}

export interface ScopeCheck {
  allowed: boolean;
  reason?: string;
}

export function isUrlInScope(urlStr: string, target: URL, scope: ScopePolicy): ScopeCheck {
  let url: URL;
  try {
    url = new URL(urlStr);
  } catch {
    return { allowed: false, reason: 'malformed URL' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { allowed: false, reason: `protocol ${url.protocol} not allowed` };
  }

  const host = url.hostname.toLowerCase();
  const targetHost = target.hostname.toLowerCase();

  if (scope.excludedHosts.some((h) => host === h.toLowerCase() || host.endsWith(`.${h.toLowerCase()}`))) {
    return { allowed: false, reason: `host ${host} is excluded from scope` };
  }
  if (scope.excludedPaths.some((p) => url.pathname === p || url.pathname.startsWith(p.endsWith('/') ? p : `${p}/`))) {
    return { allowed: false, reason: `path ${url.pathname} is excluded from scope` };
  }

  switch (scope.mode) {
    case 'page':
      if (url.origin !== target.origin || url.pathname !== target.pathname) {
        return { allowed: false, reason: 'scope is limited to the single target page' };
      }
      return { allowed: true };
    case 'subdomain':
      if (host !== targetHost) {
        return { allowed: false, reason: `host ${host} is outside the target subdomain scope` };
      }
      return { allowed: true };
    case 'full-domain': {
      const inDomain = host === targetHost || (scope.includeSubdomains && host.endsWith(`.${targetHost}`));
      if (!inDomain) {
        return { allowed: false, reason: `host ${host} is outside the target domain scope` };
      }
      return { allowed: true };
    }
  }
}

function isPrivateIp(ip: string): boolean {
  if (!net.isIP(ip)) return false;
  const lower = ip.toLowerCase();
  // IPv4-mapped IPv6 literals (::ffff:127.0.0.1, ::ffff:7f00:1): the embedded
  // IPv4 address determines privateness. Unparseable mapped forms fail closed.
  const mapped = /^::ffff:(.+)$/.exec(lower);
  if (mapped) {
    const tail = mapped[1];
    if (net.isIPv4(tail)) return isPrivateIp(tail);
    const hex = tail.replace(/:/g, '');
    if (/^[0-9a-f]{1,8}$/.test(hex)) {
      const n = parseInt(hex, 16);
      return isPrivateIp([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'));
    }
    return true;
  }
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 172 && b !== undefined && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 127) return true; // loopback
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 169 && b === 254) return true; // link-local
    if (a >= 224) return true; // multicast + reserved
    return false;
  }
  // IPv6
  return (
    lower === '::1' ||
    lower === '::' ||
    lower.startsWith('fe80:') || // link-local
    lower.startsWith('fc') || // unique local fc00::/7
    lower.startsWith('fd')
  );
}

/**
 * SSRF guard: resolve the hostname and refuse private / internal addresses.
 * Bypassable ONLY via ALLOW_PRIVATE_TARGETS=true (for local test apps like
 * OWASP Juice Shop / DVWA) — which config.ts forbids in production.
 */
export async function assertPublicHost(hostname: string, allowPrivate: boolean): Promise<void> {
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname) && !allowPrivate) {
      throw Object.assign(
        new Error(`Refusing to scan private IP ${hostname} (SSRF guardrail)`),
        { statusCode: 400 }
      );
    }
    return;
  }
  let records: Array<{ address: string; family: number }>;
  try {
    records = await dns.lookup(hostname, { all: true });
  } catch {
    throw Object.assign(new Error(`Could not resolve host ${hostname}`), { statusCode: 400 });
  }
  for (const r of records) {
    if (isPrivateIp(r.address) && !allowPrivate) {
      throw Object.assign(
        new Error(`Refusing to scan ${hostname}: resolves to private IP ${r.address} (SSRF guardrail)`),
        { statusCode: 400 }
      );
    }
  }
}

export function assertUrlAllowed(urlStr: string, target: URL, scope: ScopePolicy): URL {
  const check = isUrlInScope(urlStr, target, scope);
  if (!check.allowed) {
    throw Object.assign(new Error(`Out of scope: ${check.reason}`), { statusCode: 403 });
  }
  return new URL(urlStr);
}
