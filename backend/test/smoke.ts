import { calculateCvss, scoreFinding } from '../../src/lib/cvss';
import { scoreTrapProbability } from '../../src/lib/honeypot';
import { buildAttackChains } from '../../src/lib/attackChains';
import { RateLimiter } from '../../src/lib/rateLimiter';
import { normalizeHost, hostCoveredBy, scopeCheck, type AuthorizationRecord } from '../../src/lib/authorization';
import { classifyReflection } from '../../src/active/xssTester';
import { extractEndpointsFromCode } from '../../src/active/apiDiscovery';
import type { Finding } from '../../src/lib/types';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

// --- CVSS v3.1 known vectors ---
// CVE-2020-1472 Netlogon: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0
const r1 = calculateCvss({AV:'N',AC:'H',PR:'N',UI:'N',S:'C',C:'H',I:'H',A:'H'});
check("CVSS AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H = 9.0", r1.score === 9.0, r1);
// Reflected XSS typical: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1
const r2 = calculateCvss({AV:'N',AC:'L',PR:'N',UI:'R',S:'C',C:'L',I:'L',A:'N'});
check('CVSS reflected-XSS = 6.1', r2.score === 6.1, r2);
// No impact = 0
const r3 = calculateCvss({AV:'N',AC:'L',PR:'N',UI:'N',S:'U',C:'N',I:'N',A:'N'});
check('CVSS no impact = 0', r3.score === 0, r3);
// Default creds preset should be critical 9.8
const dc = scoreFinding('auth:default-credentials');
check('default-creds preset critical 9.8', dc.score === 9.8 && dc.severity === 'critical', dc);
const corsP = scoreFinding('cors:wildcard-credentials');
check('cors wildcard+creds high', corsP.severity === 'high' && corsP.score >= 7, corsP);

// --- Honeypot scoring ---
const mkFinding = (over: Partial<Finding>): Finding => ({
  id: 'f1', category: 'auth', title: 't', description: 'd', severity: 'medium',
  confidence: 'high', remediation: 'r', ...over,
});
const ctx = { totalFindings: 3, headerPostureGood: true, cookiePostureGood: true, targetHost: 'example.com' };
const trap1 = scoreTrapProbability(mkFinding({
  title: 'Default credentials accepted: admin/admin', severity: 'critical',
  mode: 'active', tags: ['default-creds'], location: '/admin/login', evidence: 'accepted pair: admin/admin', requestCount: 1,
}), ctx);
check('trivial default creds scores trap', trap1.probability >= 0.6 && trap1.suspect, trap1);
const canary = scoreTrapProbability(mkFinding({
  title: 'AWS key exposed', severity: 'critical', location: 'https://x.canarytokens.com/abc',
  evidence: 'AKIA...', mode: 'passive',
}), ctx);
check('canary token scores trap', canary.suspect, canary);
const normal = scoreTrapProbability(mkFinding({ title: 'Missing CSP header', severity: 'medium' }), ctx);
check('normal finding low trap score', normal.probability < 0.3 && !normal.suspect, normal);

// --- Attack chains ---
const fCors = mkFinding({ id: 'c1', category: 'cors', title: 'CORS reflects arbitrary origins with credentials allowed', severity: 'high', mode: 'active', tags: ['cors-creds'], cvssScore: 8.2 });
const fApi = mkFinding({ id: 'a1', category: 'api', title: 'API surface mapped', severity: 'info', mode: 'active', tags: ['api-endpoint'] });
const fXss = mkFinding({ id: 'x1', category: 'xss', title: 'Confirmed reflected XSS', severity: 'high', mode: 'active', tags: ['xss-confirmed'], cvssScore: 6.1 });
const fCookie = mkFinding({ id: 'k1', category: 'cookies', title: 'Session cookie missing HttpOnly', severity: 'medium', description: 'cookie lacks HttpOnly flag' });
const chains = buildAttackChains([fCors, fApi, fXss, fCookie]);
check('builds 2 chains', chains.length === 2, chains.map(c => c.id));
check('cors chain links findings', chains.some(c => c.id.includes('cors-to-account-takeover') && c.findingIds.includes('c1') && c.findingIds.includes('a1')));
check('xss chain links findings', chains.some(c => c.id.includes('xss-to-session-hijack') && c.findingIds.includes('x1')));
check('findings annotated with chain ids', (fCors.attackChainIds?.length ?? 0) === 1);
// honeypot-suspect findings excluded from chains
const fTrap = mkFinding({ id: 't1', category: 'auth', title: 'trap', severity: 'critical', mode: 'active', tags: ['default-creds'], honeypotSuspect: true, trapProbability: 0.9 });
const chains2 = buildAttackChains([fTrap, fApi]);
check('trap findings excluded from chains', chains2.length === 0, chains2);

// --- Scope enforcement ---
const rec: AuthorizationRecord = {
  id: 'a1', targetHost: 'example.com', type: 'bug-bounty', statement: 's',
  scope: { mode: 'full-domain', includeSubdomains: true, excludedHosts: ['status.example.com'], excludedPaths: ['/logout'], maxRequestsPerSecond: 1 },
  allowAuthProbes: false, rateLimitMs: 1500, confirmedAt: new Date().toISOString(),
};
check('subdomain in scope', scopeCheck('https://app.example.com/api', rec, 'https://example.com/') === null);
check('excluded host blocked', scopeCheck('https://status.example.com/', rec, 'https://example.com/') !== null);
check('excluded path blocked', scopeCheck('https://example.com/logout', rec, 'https://example.com/') !== null);
check('external host blocked', scopeCheck('https://evil.com/', rec, 'https://example.com/') !== null);
check('non-http blocked', scopeCheck('file:///etc/passwd', rec, 'https://example.com/') !== null);
check('normalizeHost strips port', normalizeHost('Example.COM:8443') === 'example.com');
check('hostCoveredBy exact', hostCoveredBy('example.com', rec));

// --- Rate limiter ---
(async () => {
  const lim = new RateLimiter(300, 10);
  const t0 = Date.now();
  await lim.acquire(); await lim.acquire(); await lim.acquire();
  const elapsed = Date.now() - t0;
  check('rate limiter enforces gap (~600ms for 3)', elapsed >= 550 && elapsed < 2000, elapsed);
  check('stats requestsMade=3', lim.getStats().requestsMade === 3);
  const lim2 = new RateLimiter(100, 2);
  await lim2.acquire(); await lim2.acquire();
  let threw = false;
  try { await lim2.acquire(); } catch { threw = true; }
  check('rate limiter cap throws', threw);
})().then(() => {
  // --- XSS context classification ---
  check('classify html', classifyReflection('<p>hello BSXQ1 world</p>', 'BSXQ1') === 'html');
  check('classify attr-double', classifyReflection('<input value="BSXQ1">', 'BSXQ1') === 'attr-double');
  check('classify js-single', classifyReflection('<script>var x=\'BSXQ1\';</script>', 'BSXQ1') === 'js-single');
  check('classify comment', classifyReflection('<!-- BSXQ1 -->', 'BSXQ1') === 'comment');
  // --- endpoint extraction ---
  const eps = extractEndpointsFromCode(`fetch('/api/v1/users'); $.ajax({url: "/rest/orders"}); fetch("https://cdn.x/lib.js");`);
  check('extracts endpoints, skips CDN js', eps.includes('/api/v1/users') && eps.includes('/rest/orders'), eps);
  console.log(failures === 0 ? '\nALL SMOKE TESTS PASSED' : `\n${failures} FAILURES`);
  process.exit(failures === 0 ? 0 : 1);
});
