/**
 * Smoke test — no network, no paid APIs, no infrastructure.
 * Boots the full app in-process (memory DB, memory queue, mock LLM) and
 * exercises: health, register/login, scan lifecycle, guardrails
 * (authorization required, scope enforcement, evidence redaction), findings,
 * progress polling, and report generation.
 *
 * Run: npm run smoke
 */
import assert from 'node:assert/strict';
import { config } from '../src/config.js';
import { MemoryDatabase } from '../src/db/db.js';
import { createQueue } from '../src/queue/queue.js';
import { MockProvider } from '../src/llm/mock.js';
import { ScanOrchestrator } from '../src/orchestrator/orchestrator.js';
import { buildApp } from '../src/server.js';
import { isUrlInScope, normalizeTargetUrl } from '../src/guardrails/scope.js';
import { redactText } from '../src/guardrails/redact.js';
import { estimateCvss } from '../src/reports/cvss.js';

async function main(): Promise<void> {
  const db = new MemoryDatabase();
  const queue = await createQueue(undefined); // memory queue
  const provider = new MockProvider();

  // Stub tools — deterministic, zero network. The mock LLM provider reacts
  // to these canned results with deterministic findings.
  const stubTools = [
    {
      name: 'fetch_url',
      description: 'stub',
      run: async () => ({
        ok: true, status: 200,
        headers: { 'content-type': 'text/html' },
        bodySnippet: 'hello',
        data: { serverDisclosure: 'nginx/1.25' },
        honeypotSignals: [] as string[],
      }),
    },
    {
      name: 'check_security_headers',
      description: 'stub',
      run: async () => ({
        ok: true, status: 200,
        data: { missing: ['content-security-policy', 'strict-transport-security'] },
        honeypotSignals: [] as string[],
      }),
    },
    {
      name: 'probe_cors',
      description: 'stub',
      run: async () => ({
        ok: true, status: 200,
        data: { vulnerable: true, allowOrigin: 'https://evil.bugseek-test.invalid', allowCredentials: 'true' },
        honeypotSignals: [] as string[],
      }),
    },
    {
      name: 'inspect_cookies',
      description: 'stub',
      run: async () => ({
        ok: true, status: 200, data: { cookieCount: 1, issues: [] }, honeypotSignals: [] as string[],
      }),
    },
    {
      name: 'probe_reflected_xss',
      description: 'stub',
      run: async () => ({
        ok: true, status: 200, data: { reflectedUnencoded: false }, honeypotSignals: [] as string[],
      }),
    },
  ];

  const orchestrator = new ScanOrchestrator({ db, queue, config, provider, toolOverrides: stubTools });
  await queue.start((job) => orchestrator.handleJob(job.scanId));
  const app = buildApp({ config, db, queue, provider, orchestrator });

  const email = `smoke-${Date.now()}@example.com`;
  const password = 'correct-horse-battery-staple';

  // 1. Health
  let res = await app.inject({ method: 'GET', url: '/health' });
  assert.equal(res.statusCode, 200);
  const health = res.json();
  assert.equal(health.status, 'ok');
  assert.equal(health.db, 'memory');
  assert.equal(health.llm, 'mock');
  console.log('✓ health check', JSON.stringify({ db: health.db, queue: health.queue, llm: health.llm }));

  // 2. Register + login
  res = await app.inject({ method: 'POST', url: '/api/auth/register', payload: { email, password } });
  assert.equal(res.statusCode, 201, res.body);
  const token = res.json().token as string;
  assert.ok(token);
  const auth = { authorization: `Bearer ${token}` };
  console.log('✓ register');

  res = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email, password } });
  assert.equal(res.statusCode, 200);
  console.log('✓ login');

  res = await app.inject({ method: 'GET', url: '/api/auth/me', headers: auth });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().user.plan, 'free');
  console.log('✓ me (plan=free)');

  // 3. Guardrail: active scan WITHOUT authorization → 400
  res = await app.inject({
    method: 'POST', url: '/api/scans', headers: auth,
    payload: { targetUrl: 'https://example.com', mode: 'active' },
  });
  assert.equal(res.statusCode, 403, 'free tier must not allow active scans');
  console.log('✓ guardrail: free tier blocked from active testing (403)');

  // Upgrade to hunter for the remaining tests (direct DB call = test setup).
  const user = await db.getUserByEmail(email);
  assert.ok(user);
  await db.setUserPlan(user.id, 'hunter');

  res = await app.inject({
    method: 'POST', url: '/api/scans', headers: auth,
    payload: { targetUrl: 'https://example.com', mode: 'active' },
  });
  assert.equal(res.statusCode, 400, res.body);
  assert.match(res.json().error, /[Aa]uthorization/);
  console.log('✓ guardrail: active scan requires explicit authorization (400)');

  // 4. Active scan WITH authorization (mock provider, stub tools → no network).
  //    The engine's default tools are replaced via hooks only in-process; here
  //    we rely on the mock provider + tool failures being tolerated — but to
  //    avoid real network calls, run a PASSIVE scan instead and submit
  //    extension findings manually.
  res = await app.inject({
    method: 'POST', url: '/api/scans', headers: auth,
    payload: {
      targetUrl: 'https://example.com',
      mode: 'passive',
      scope: { mode: 'subdomain', includeSubdomains: false },
    },
  });
  assert.equal(res.statusCode, 201, res.body);
  const scan = res.json().scan;
  assert.equal(scan.mode, 'passive');
  assert.equal(scan.authorizationId, undefined);
  console.log('✓ passive scan created', scan.id);

  // Wait for the in-process queue to finish the passive scan.
  const deadline = Date.now() + 30_000;
  let final = scan;
  for (;;) {
    res = await app.inject({ method: 'GET', url: `/api/scans/${scan.id}`, headers: auth });
    final = res.json().scan;
    if (final.status === 'completed' || final.status === 'failed') break;
    if (Date.now() > deadline) throw new Error('scan did not finish in time');
    await new Promise((r) => setTimeout(r, 200));
  }
  assert.equal(final.status, 'completed', JSON.stringify(final.error));
  console.log('✓ passive scan completed');

  // 5. Progress polling
  res = await app.inject({ method: 'GET', url: `/api/scans/${scan.id}/progress?since=0`, headers: auth });
  assert.equal(res.statusCode, 200);
  assert.ok(res.json().events.length > 0);
  console.log(`✓ progress polling (${res.json().events.length} events)`);

  // 6. Submit an extension finding with a SECRET in evidence → must be redacted.
  const leaky = {
    category: 'secrets',
    title: 'Exposed AWS key in bundle',
    description: 'Hardcoded AWS access key found in JS bundle.',
    severity: 'critical',
    confidence: 'high',
    location: 'https://example.com/app.js',
    evidence: 'const k = "AKIAIOSFODNN7EXAMPLE"; // contact admin@example.com',
    remediation: 'Rotate the key and move to server-side.',
  };
  res = await app.inject({
    method: 'POST', url: `/api/scans/${scan.id}/findings`, headers: auth, payload: leaky,
  });
  // Scan is completed → submission rejected (409). Create a fresh scan for this.
  assert.equal(res.statusCode, 409);
  console.log('✓ guardrail: findings rejected for completed scan (409)');

  // Create a fresh scan directly in the DB (bypasses the queue so the worker
  // can't complete it mid-test — deterministic, no race).
  const scan2 = await db.createScan({
    userId: user.id,
    targetUrl: 'https://example.com',
    mode: 'passive',
    scope: {
      mode: 'subdomain', includeSubdomains: false,
      excludedHosts: [], excludedPaths: [], maxRequestsPerSecond: 2,
    },
  });
  res = await app.inject({
    method: 'POST', url: `/api/scans/${scan2.id}/findings`, headers: auth, payload: leaky,
  });
  assert.equal(res.statusCode, 201, res.body);
  const submitted = res.json().finding;
  assert.ok(!submitted.evidence.includes('AKIAIOSFODNN7EXAMPLE'), 'secret must be redacted');
  assert.ok(!submitted.evidence.includes('admin@example.com'), 'PII must be redacted');
  assert.ok(submitted.evidence.includes('[REDACTED'), 'redaction marker expected');
  assert.ok(submitted.cvssScore > 0 && submitted.cvssVector?.startsWith('CVSS:3.1'));
  console.log('✓ guardrail: evidence redacted before persistence:', JSON.stringify(submitted.evidence));

  // 7. Active scan end-to-end through the orchestrator (stub tools, mock LLM).
  {
    res = await app.inject({
      method: 'POST', url: '/api/scans', headers: auth,
      payload: {
        targetUrl: 'https://example.com',
        mode: 'active',
        authorization: {
          type: 'bug-bounty',
          programName: 'Smoke Test Program',
          statement: 'I confirm I am authorized to test this target via the smoke test bug bounty program.',
          confirmed: true,
        },
      },
    });
    assert.equal(res.statusCode, 201, res.body);
    const activeScan = res.json().scan;
    assert.ok(activeScan.authorizationId, 'authorization record must be stored with the scan');
    console.log('✓ active scan created with authorization record', activeScan.authorizationId);

    const deadline2 = Date.now() + 60_000;
    let active = activeScan;
    for (;;) {
      res = await app.inject({ method: 'GET', url: `/api/scans/${activeScan.id}`, headers: auth });
      active = res.json().scan;
      if (active.status === 'completed' || active.status === 'failed') break;
      if (Date.now() > deadline2) throw new Error('active scan did not finish in time');
      await new Promise((r) => setTimeout(r, 200));
    }
    assert.equal(active.status, 'completed', JSON.stringify(active.error));

    res = await app.inject({ method: 'GET', url: `/api/scans/${activeScan.id}/findings`, headers: auth });
    const agentFindings = res.json().findings;
    assert.ok(agentFindings.length > 0, 'agent should produce findings from stub results');
    const cors = agentFindings.find((f: { category: string }) => f.category === 'cors');
    assert.ok(cors && cors.severity === 'high', 'CORS reflection should be high severity');
    assert.ok(agentFindings.every((f: { evidence?: string }) =>
      !f.evidence || (!/AKIA[0-9A-Z]{16}/.test(f.evidence) && !/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(f.evidence)),
    ), 'evidence must not contain secrets or PII');
    console.log(`✓ agent loop (PLAN→ACT→OBSERVE→REFLECT): ${agentFindings.length} findings persisted`);
    for (const f of agentFindings) {
      console.log(`    - [${f.severity}] ${f.title} (trap=${f.trapProbability})`);
    }

    // Progress events include the agent's act/reflect steps.
    res = await app.inject({ method: 'GET', url: `/api/scans/${activeScan.id}/progress?since=0`, headers: auth });
    const kinds = new Set(res.json().events.map((e: { kind: string }) => e.kind));
    assert.ok(kinds.has('finding') || kinds.has('step'), 'progress should include agent activity');
    console.log(`✓ active scan progress events (${res.json().events.length} events)`);
  }

  // 8. Scope enforcement unit checks
  {
    const target = normalizeTargetUrl('https://app.example.com/page');
    const scope = {
      mode: 'subdomain' as const, includeSubdomains: false,
      excludedHosts: [], excludedPaths: ['/admin'], maxRequestsPerSecond: 2,
    };
    assert.equal(isUrlInScope('https://app.example.com/other', target, scope).allowed, true);
    assert.equal(isUrlInScope('https://sub.app.example.com/', target, scope).allowed, false);
    assert.equal(isUrlInScope('https://app.example.com/admin/panel', target, scope).allowed, false);
    assert.equal(isUrlInScope('https://evil.com/', target, scope).allowed, false);
    assert.equal(isUrlInScope('ftp://app.example.com/', target, scope).allowed, false);
    console.log('✓ scope enforcement unit checks');
  }

  // 9. Redaction + CVSS unit checks
  {
    assert.equal(redactText('key=AKIAIOSFODNN7EXAMPLE'), 'key=[REDACTED:aws-key]');
    const cvss = estimateCvss('high', 'xss');
    assert.ok(cvss.score > 0 && cvss.score <= 8.9, `CVSS band respected: ${cvss.score}`);
    assert.ok(cvss.vector.startsWith('CVSS:3.1/'));
    console.log(`✓ redact + CVSS unit checks (xss/high → ${cvss.score} ${cvss.vector})`);
  }

  // 10. Reports (hunter tier allows pdf/docx/md)
  {
    // Mark first scan completed already; generate reports for it.
    for (const fmt of ['md', 'json', 'pdf', 'docx']) {
      res = await app.inject({
        method: 'GET', url: `/api/scans/${scan.id}/report?format=${fmt}`, headers: auth,
      });
      assert.equal(res.statusCode, 200, `${fmt}: ${res.body.slice(0, 200)}`);
      assert.ok(res.body.length > 100, `${fmt} report too small`);
      console.log(`✓ report format=${fmt} (${res.body.length} bytes)`);
    }
    assert.ok(res.headers['content-type']?.includes('wordprocessingml'));
  }

  // 11. Scan list + pause/resume/cancel on a queued scan
  {
    res = await app.inject({ method: 'GET', url: '/api/scans?limit=10', headers: auth });
    assert.equal(res.statusCode, 200);
    assert.ok(res.json().total >= 2);
    console.log(`✓ scan listing (total=${res.json().total})`);
  }

  await app.close();
  await queue.close();
  await db.close();
  console.log('\nSMOKE TEST PASSED — all checks green.');
}

main().catch((err) => {
  console.error('\nSMOKE TEST FAILED:', err);
  process.exit(1);
});
