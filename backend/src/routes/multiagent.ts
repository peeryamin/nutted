import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import { PLAN_QUOTAS, SCAN_CREDIT_COST, monthStartIso } from '../auth/usage.js';
import { verifyAndRecordAuthorization } from '../guardrails/authorization.js';
import { normalizeTargetUrl } from '../guardrails/scope.js';
import { redactFindingEvidence } from '../guardrails/redact.js';
import { estimateCvss } from '../reports/cvss.js';
import type { RouteDeps } from './health.js';
import { runMultiAgentScan } from '../multiagent/orchestrator.js';
import type { Confidence, Severity } from '../types.js';

/**
 * Multi-agent "super agent" swarm routes.
 *
 * POST /api/swarm/scans — run the head agent + specialist workers against an
 * authorized target. Runs inline (bounded by maxDurationMs); for production
 * use at scale this should be moved onto the scan job queue.
 *
 * The scan goes through the same lifecycle as ordinary scans: an explicit
 * authorization record is REQUIRED (plan §8), credits are charged (25 per
 * active swarm scan), findings are persisted, and the scan is marked
 * completed/failed.
 *
 * LEGAL GUARDRAIL: the caller must be authorized to test the target
 * (bug-bounty program, pentest contract, or ownership). The swarm enforces
 * scope, rate limits and SSRF guards on every request; all probes are
 * non-destructive.
 */

const scopeSchema = z.object({
  mode: z.enum(['full-domain', 'subdomain', 'page']).optional(),
  includeSubdomains: z.boolean().optional(),
  excludedHosts: z.array(z.string().max(253)).max(50).optional(),
  excludedPaths: z.array(z.string().max(500)).max(50).optional(),
});

const swarmScanSchema = z.object({
  targetUrl: z.string().min(1).max(2000),
  authorization: z.unknown(), // REQUIRED — validated by verifyAndRecordAuthorization (plan §8)
  scope: scopeSchema.optional(),
  maxWorkers: z.number().int().min(1).max(8).optional(),
  concurrency: z.number().int().min(1).max(4).optional(),
  requestsPerSecond: z.number().min(0.1).max(5).optional(),
  maxTokens: z.number().int().min(1000).max(500_000).optional(),
  timeoutMinutes: z.number().min(1).max(20).optional(),
  allowPrivateTargets: z.boolean().optional(),
  specialists: z
    .array(z.enum(['recon', 'secrets', 'headers', 'cors', 'xss', 'idor', 'auth', 'graphql']))
    .max(8)
    .optional(),
});

export async function swarmRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  const { db } = deps;
  const authenticate = buildAuthenticate(db);

  app.post('/api/swarm/scans', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = swarmScanSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const d = body.data;
    const quota = PLAN_QUOTAS[user.plan];

    // 1. Feature gating: swarm = active testing → Hunter+.
    if (!quota.activeTesting) {
      return reply.status(403).send({ error: 'Active testing requires the Hunter plan or higher' });
    }

    // 2. Target validation (SSRF guard: public hosts only unless explicitly allowed).
    let target: URL;
    try {
      target = normalizeTargetUrl(d.targetUrl);
    } catch (err) {
      return reply.status(400).send({ error: (err as Error).message });
    }

    // 3. Authorization record (plan §8 — REQUIRED for active testing).
    let authorizationId: string;
    try {
      const record = await verifyAndRecordAuthorization(db, user.id, d.authorization);
      authorizationId = record.id;
    } catch (err) {
      const status = (err as { statusCode?: number }).statusCode ?? 400;
      return reply.status(status).send({ error: (err as Error).message });
    }

    // 4. Credit quota: a swarm scan is an active scan → 25 credits.
    const creditCost = SCAN_CREDIT_COST.active;
    try {
      const used = await db.sumUsageSince(user.id, 'scan', monthStartIso());
      if (used + creditCost > quota.creditsPerMonth) {
        return reply.status(429).send({
          error: `Monthly credit quota exceeded (${used}/${quota.creditsPerMonth} credits used on the ${user.plan} plan; this scan costs ${creditCost})`,
        });
      }
    } catch (err) {
      return reply.status(500).send({ error: (err as Error).message });
    }

    // 5. Create the scan record + charge credits.
    const scope = {
      mode: d.scope?.mode ?? 'subdomain',
      includeSubdomains: d.scope?.includeSubdomains ?? false,
      excludedHosts: d.scope?.excludedHosts ?? [],
      excludedPaths: d.scope?.excludedPaths ?? [],
      maxRequestsPerSecond: Math.min(5, Math.max(0.1, d.requestsPerSecond ?? 2)),
    } as const;
    const scan = await db.createScan({
      userId: user.id,
      targetUrl: target.toString(),
      mode: 'active',
      scope: { ...scope },
      authorizationId,
      techStack: [],
    });
    await db.recordUsage(user.id, 'scan', creditCost, scan.id);

    try {
      const outcome = await runMultiAgentScan({
        targetUrl: target.toString(),
        scope: {
          mode: scope.mode,
          includeSubdomains: scope.includeSubdomains,
          excludedHosts: [...scope.excludedHosts],
          excludedPaths: [...scope.excludedPaths],
        },
        limits: {
          maxWorkers: d.maxWorkers,
          maxConcurrency: d.concurrency,
          maxTotalTokens: d.maxTokens,
          maxDurationMs: d.timeoutMinutes ? d.timeoutMinutes * 60_000 : undefined,
          requestsPerSecond: d.requestsPerSecond,
          allowPrivateTargets: d.allowPrivateTargets,
        },
        specialists: d.specialists,
      });
      // Server-side re-redaction + CVSS before persisting (same contract as scan findings).
      const findings = outcome.findings.map((f) => {
        const cvss = estimateCvss(f.severity as Severity, f.category);
        return redactFindingEvidence({
          ...f,
          severity: f.severity as Severity,
          confidence: (f.confidence ?? 'low') as Confidence,
          cvssScore: cvss.score,
          cvssVector: cvss.vector,
        });
      });
      for (const f of findings) {
        await db.addFinding({
          scanId: scan.id,
          category: f.category,
          title: f.title,
          description: f.description,
          severity: f.severity,
          confidence: f.confidence,
          location: f.location,
          evidence: f.evidence,
          remediation: f.remediation ?? '',
          cvssScore: f.cvssScore,
          cvssVector: f.cvssVector,
          trapProbability: f.trapProbability,
          honeypotSuspect: f.honeypotSuspect,
          reproSteps: f.reproSteps,
          references: f.references,
        });
      }
      await db.updateScan(scan.id, { status: 'completed' });
      return reply.send({
        scanId: scan.id,
        targetUrl: outcome.targetUrl,
        headSummary: outcome.headSummary,
        findings,
        workerReports: outcome.workerReports.map((r) => ({
          specialistId: r.specialistId,
          specialistName: r.specialistName,
          summary: r.summary,
          testsRun: r.testsRun,
          testsPlanned: r.testsPlanned,
          llmCalls: r.llmCalls,
          tokensUsed: r.tokensUsed,
          errors: r.errors,
          durationMs: r.durationMs,
        })),
        testsRun: outcome.testsRun,
        llmCalls: outcome.llmCalls,
        tokensUsed: outcome.tokensUsed,
        durationMs: outcome.durationMs,
        errors: outcome.errors,
      });
    } catch (err) {
      await db.updateScan(scan.id, { status: 'failed' }).catch(() => undefined);
      const status = (err as { statusCode?: number }).statusCode ?? 500;
      return reply.status(status).send({ error: (err as Error).message });
    }
  });
}
