import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import type { ScanOrchestrator } from '../orchestrator/orchestrator.js';
import { redactFindingEvidence } from '../guardrails/redact.js';
import { estimateCvss } from '../reports/cvss.js';
import type { RouteDeps } from './health.js';
import type { Confidence, Severity } from '../types.js';

const scopeSchema = z.object({
  mode: z.enum(['full-domain', 'subdomain', 'page']).optional(),
  includeSubdomains: z.boolean().optional(),
  excludedHosts: z.array(z.string().max(253)).max(50).optional(),
  excludedPaths: z.array(z.string().max(500)).max(50).optional(),
  maxRequestsPerSecond: z.number().min(0.1).max(10).optional(),
});

const createScanSchema = z.object({
  targetUrl: z.string().min(1).max(2000),
  mode: z.enum(['passive', 'active']),
  scope: scopeSchema.optional(),
  authorization: z.unknown().optional(),
  techStack: z
    .array(z.object({ name: z.string().max(100), version: z.string().max(50).optional() }))
    .max(50)
    .optional(),
});

const listQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  offset: z.coerce.number().int().min(0).default(0),
});

const progressQuerySchema = z.object({
  since: z.coerce.number().int().min(0).default(0),
});

// Findings submitted by the extension (Phase 1 passive results).
// LEGAL GUARDRAIL: evidence is re-redacted server-side before persistence.
const submitFindingSchema = z.object({
  category: z.string().min(1).max(50),
  title: z.string().min(1).max(300),
  description: z.string().min(1).max(5000),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  confidence: z.enum(['high', 'medium', 'low']),
  location: z.string().max(500).optional(),
  evidence: z.string().max(5000).optional(),
  remediation: z.string().max(5000).default(''),
  reproSteps: z.array(z.string().max(1000)).max(20).default([]),
  references: z.array(z.string().url().max(500)).max(20).default([]),
  trapProbability: z.number().min(0).max(1).default(0),
});

export interface ScanRouteDeps extends RouteDeps {
  orchestrator: ScanOrchestrator;
}

export async function scanRoutes(app: FastifyInstance, deps: ScanRouteDeps): Promise<void> {
  const { db, orchestrator } = deps;
  const authenticate = buildAuthenticate(db);

  app.post('/api/scans', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = createScanSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    try {
      const scan = await orchestrator.createScan(user, body.data);
      return reply.status(201).send({ scan });
    } catch (err) {
      const status = (err as { statusCode?: number }).statusCode ?? 500;
      return reply.status(status).send({ error: (err as Error).message });
    }
  });

  app.get('/api/scans', { preHandler: authenticate }, async (request) => {
    const user = requireUser(request);
    const q = listQuerySchema.parse(request.query);
    return db.listScans(user.id, q.limit, q.offset);
  });

  app.get('/api/scans/:id', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const scan = await db.getScan(id);
    if (!scan || scan.userId !== user.id) {
      return reply.status(404).send({ error: 'Scan not found' });
    }
    return { scan };
  });

  app.get('/api/scans/:id/progress', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const scan = await db.getScan(id);
    if (!scan || scan.userId !== user.id) {
      return reply.status(404).send({ error: 'Scan not found' });
    }
    const q = progressQuerySchema.parse(request.query);
    const { events, latestSeq } = orchestrator.getProgress(id, q.since);
    return { scanId: id, status: scan.status, progress: scan.progress, events, latestSeq };
  });

  for (const action of ['pause', 'resume', 'cancel', 'retry'] as const) {
    app.post(`/api/scans/:id/${action}`, { preHandler: authenticate }, async (request, reply) => {
      const user = requireUser(request);
      const { id } = request.params as { id: string };
      try {
        const scan = await orchestrator[`${action}Scan`](id, user.id);
        return reply.send({ scan });
      } catch (err) {
        const status = (err as { statusCode?: number }).statusCode ?? 500;
        return reply.status(status).send({ error: (err as Error).message });
      }
    });
  }

  app.get('/api/scans/:id/findings', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const scan = await db.getScan(id);
    if (!scan || scan.userId !== user.id) {
      return reply.status(404).send({ error: 'Scan not found' });
    }
    const findings = await db.listFindings(id);
    return { scanId: id, findings };
  });

  app.post('/api/scans/:id/findings', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const scan = await db.getScan(id);
    if (!scan || scan.userId !== user.id) {
      return reply.status(404).send({ error: 'Scan not found' });
    }
    // The extension streams its Phase 1 findings while the backend scan may
    // still be queued (worker not picked up yet), running, or paused.
    if (scan.status !== 'queued' && scan.status !== 'running' && scan.status !== 'paused') {
      return reply.status(409).send({ error: `Cannot submit findings to a ${scan.status} scan` });
    }
    const body = submitFindingSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const d = body.data;
    const cvss = estimateCvss(d.severity as Severity, d.category);
    const finding = await db.addFinding(
      redactFindingEvidence({
        scanId: id,
        category: d.category,
        title: d.title,
        description: d.description,
        severity: d.severity as Severity,
        cvssScore: cvss.score,
        cvssVector: cvss.vector,
        confidence: d.confidence as Confidence,
        trapProbability: d.trapProbability,
        honeypotSuspect: d.trapProbability >= 0.6,
        location: d.location,
        evidence: d.evidence,
        reproSteps: d.reproSteps,
        remediation: d.remediation,
        references: d.references,
      })
    );
    return reply.status(201).send({ finding });
  });
}
