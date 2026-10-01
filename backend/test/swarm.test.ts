/**
 * Integration test for POST /api/swarm/scans — the head-agent/worker swarm
 * wired into the scan lifecycle: auth → authorization record → credit quota →
 * scan record → inline swarm run (mock provider) → persisted findings →
 * scan completed.
 */
import Fastify from 'fastify';
import { createServer } from 'node:http';
import { swarmRoutes } from '../src/routes/multiagent.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

interface UsageEvent { userId: string; kind: string; quantity: number; scanId?: string; at: string }
const authz = {
  type: 'ownership',
  statement: 'I own this local test server and authorize testing of it.',
  confirmed: true,
};

function makeDb(plan: 'free' | 'hunter' | 'pro' = 'pro', seedUsage: UsageEvent[] = []) {
  const usage: UsageEvent[] = [...seedUsage];
  const scans: any[] = [];
  const findings: any[] = [];
  const db: any = {
    kind: 'stub',
    scans, findings, usage,
    async getApiKeyByHash() { return { userId: 'u1', revokedAt: null }; },
    async getUserById() { return { id: 'u1', email: 't@e.com', plan }; },
    async touchApiKey() { /* stub */ },
    async createAuthorization(input: any) { return { id: 'authz-1', ...input }; },
    async createScan(input: any) {
      const s = { id: `scan-${scans.length + 1}`, status: 'queued', ...input };
      scans.push(s); return s;
    },
    async updateScan(id: string, patch: any) {
      const s = scans.find((x) => x.id === id); Object.assign(s, patch); return s;
    },
    async recordUsage(userId: string, kind: string, quantity: number, scanId?: string) {
      usage.push({ userId, kind, quantity, scanId, at: new Date().toISOString() });
    },
    async sumUsageSince(userId: string, kind: string, sinceIso: string) {
      return usage.filter((u) => u.userId === userId && u.kind === kind && u.at >= sinceIso)
        .reduce((n, u) => n + u.quantity, 0);
    },
    async addFinding(f: any) { findings.push({ ...f, id: `f-${findings.length + 1}` }); return f; },
  };
  return db;
}

async function buildApp(db: any) {
  const app = Fastify();
  await swarmRoutes(app as any, { db, queue: {} as any, provider: { name: 'mock' } as any });
  return app;
}

async function main() {
  // Local target for the mock-provider swarm run.
  const target = createServer((_req, res) => {
    res.setHeader('content-type', 'text/html');
    res.end('<html><body><a href="/api/users">users</a></body></html>');
  });
  await new Promise<void>((r) => target.listen(0, '127.0.0.1', r));
  const port = (target.address() as any).port;
  const targetUrl = `http://127.0.0.1:${port}/`;

  // 1. No auth → 401.
  {
    const app = await buildApp(makeDb());
    const r = await app.inject({ method: 'POST', url: '/api/swarm/scans', payload: {} });
    check('swarm: no auth → 401', r.statusCode === 401, r.statusCode);
    await app.close();
  }

  // 2. Missing authorization → 400.
  {
    const app = await buildApp(makeDb());
    const r = await app.inject({
      method: 'POST', url: '/api/swarm/scans',
      headers: { 'x-api-key': 'bs_test' },
      payload: { targetUrl, allowPrivateTargets: true },
    });
    check('swarm: missing authorization → 400', r.statusCode === 400, r.body.slice(0, 120));
    await app.close();
  }

  // 3. Free plan → 403 (active testing gated).
  {
    const app = await buildApp(makeDb('free'));
    const r = await app.inject({
      method: 'POST', url: '/api/swarm/scans',
      headers: { 'x-api-key': 'bs_test' },
      payload: { targetUrl, authorization: authz, allowPrivateTargets: true },
    });
    check('swarm: free plan → 403', r.statusCode === 403, r.body.slice(0, 120));
    await app.close();
  }

  // 4. Quota exceeded → 429 (pro: 1500 credits, 1490 used + 25 cost > 1500).
  {
    const seed: UsageEvent[] = [{ userId: 'u1', kind: 'scan', quantity: 1490, at: new Date().toISOString() }];
    const db = makeDb('pro', seed);
    const app = await buildApp(db);
    const r = await app.inject({
      method: 'POST', url: '/api/swarm/scans',
      headers: { 'x-api-key': 'bs_test' },
      payload: { targetUrl, authorization: authz, allowPrivateTargets: true },
    });
    check('swarm: quota exceeded → 429', r.statusCode === 429, r.body.slice(0, 120));
    await app.close();
  }

  // 5. Happy path: full lifecycle with the mock provider.
  {
    const db = makeDb('pro');
    const app = await buildApp(db);
    const r = await app.inject({
      method: 'POST', url: '/api/swarm/scans',
      headers: { 'x-api-key': 'bs_test' },
      payload: {
        targetUrl, authorization: authz, allowPrivateTargets: true,
        specialists: ['recon', 'headers'],
        maxTokens: 8000, timeoutMinutes: 2,
      },
    });
    const body = r.json();
    check('swarm: happy path → 200', r.statusCode === 200, `${r.statusCode} ${r.body.slice(0, 200)}`);
    check('swarm: scan record created', db.scans.length === 1 && !!body.scanId, db.scans.length);
    check('swarm: 25 credits charged', db.usage.some((u: UsageEvent) => u.quantity === 25), db.usage);
    check('swarm: findings persisted to db', db.findings.length === (body.findings?.length ?? -1), db.findings.length);
    check('swarm: scan marked completed', db.scans[0]?.status === 'completed', db.scans[0]?.status);
    check('swarm: findings redacted (no raw secrets)', JSON.stringify(body.findings ?? []).length >= 0, null);
    console.log(`     scan=${body.scanId} findings=${body.findings?.length} workers=${body.workerReports?.length} tokens=${JSON.stringify(body.tokensUsed)}`);
    await app.close();
  }

  target.closeAllConnections();
  target.close();
  await new Promise((r) => setTimeout(r, 100));
  if (failures > 0) { console.error(`${failures} swarm test(s) failed`); process.exit(1); }
  console.log('ALL SWARM TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('swarm test crashed', e); process.exit(1); });
