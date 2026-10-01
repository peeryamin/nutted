import type { AppConfig } from '../config.js';
import type { Database } from '../db/db.js';
import type { JobQueue } from '../queue/queue.js';
import type { LLMProvider } from '../llm/provider.js';
import { PLAN_QUOTAS, SCAN_CREDIT_COST, monthStartIso } from '../auth/usage.js';
import { verifyAndRecordAuthorization } from '../guardrails/authorization.js';
import { normalizeTargetUrl } from '../guardrails/scope.js';
import { createToolContext, defaultTools, type AgentTool } from '../agent/tools.js';
import { runAgentScan } from '../agent/engine.js';
import { redactFindingEvidence } from '../guardrails/redact.js';
import { estimateCvss } from '../reports/cvss.js';
import type {
  Finding,
  PlanTier,
  Scan,
  ScanProgressEvent,
  ScanStatus,
  ScopePolicy,
} from '../types.js';

export interface CreateScanRequest {
  targetUrl: string;
  mode: 'passive' | 'active';
  scope?: Partial<ScopePolicy>;
  authorization?: unknown;
  techStack?: Array<{ name: string; version?: string }>;
}

export interface OrchestratorDeps {
  db: Database;
  queue: JobQueue;
  config: AppConfig;
  provider: LLMProvider;
  /**
   * Override the agent's toolset (used by tests/smoke to avoid real network
   * calls). When set, BOTH passive checks and the active agent loop use
   * these tools instead of the default network tools.
   */
  toolOverrides?: AgentTool[];
}

const VALID_TRANSITIONS: Record<ScanStatus, ScanStatus[]> = {
  queued: ['running', 'cancelled'],
  running: ['paused', 'completed', 'failed', 'cancelled'],
  paused: ['running', 'cancelled'],
  completed: [],
  failed: ['queued'], // allow retry by re-queueing
  cancelled: ['queued'], // allow re-run
};

/**
 * Scan lifecycle state machine: queued → running → paused → completed/failed.
 * All transitions go through `transition()` so invalid jumps are rejected.
 * Progress events are kept per scan (in-memory ring buffer) for the extension
 * to poll via GET /api/scans/:id/progress.
 */
export class ScanOrchestrator {
  private events = new Map<string, ScanProgressEvent[]>();
  private seq = new Map<string, number>();
  private pausedScans = new Set<string>();
  private cancelledScans = new Set<string>();

  constructor(private deps: OrchestratorDeps) {}

  // ── Creation (validation + guardrails) ──────────────────────────────────

  async createScan(
    user: { id: string; email: string; plan: PlanTier },
    req: CreateScanRequest
  ): Promise<Scan> {
    const quota = PLAN_QUOTAS[user.plan];

    // 1. Feature gating: active testing requires Hunter+ (plan §6.1).
    if (req.mode === 'active' && !quota.activeTesting) {
      throw Object.assign(
        new Error('Active testing requires the Hunter plan or higher'),
        { statusCode: 403 }
      );
    }

    // 2. Target validation.
    if (!req.targetUrl || typeof req.targetUrl !== 'string') {
      throw Object.assign(new Error('targetUrl is required'), { statusCode: 400 });
    }
    const target = normalizeTargetUrl(req.targetUrl);

    // 3. Authorization verification for active testing (plan §8 — REQUIRED).
    let authorizationId: string | undefined;
    if (req.mode === 'active') {
      const record = await verifyAndRecordAuthorization(this.deps.db, user.id, req.authorization);
      authorizationId = record.id;
    }

    // 4. Usage quota — credit-metered (business plan §3): 1 credit = one
    // passive scan, 25 credits = one active agent scan.
    const creditCost = SCAN_CREDIT_COST[req.mode];
    const used = await this.deps.db.sumUsageSince(user.id, 'scan', monthStartIso());
    if (used + creditCost > quota.creditsPerMonth) {
      throw Object.assign(
        new Error(
          `Monthly credit quota exceeded (${used}/${quota.creditsPerMonth} credits used on the ${user.plan} plan; this scan costs ${creditCost})`
        ),
        { statusCode: 429 }
      );
    }

    // 5. Scope policy (sane defaults; the extension confirms these with the user).
    const scope: ScopePolicy = {
      mode: req.scope?.mode ?? 'full-domain',
      includeSubdomains: req.scope?.includeSubdomains ?? true,
      excludedHosts: req.scope?.excludedHosts ?? [],
      excludedPaths: req.scope?.excludedPaths ?? [],
      maxRequestsPerSecond: Math.min(
        req.scope?.maxRequestsPerSecond ?? this.deps.config.agentRequestsPerSecond,
        10 // hard ceiling — never DoS-like (plan §8)
      ),
    };

    const scan = await this.deps.db.createScan({
      userId: user.id,
      targetUrl: target.toString(),
      mode: req.mode,
      scope,
      authorizationId,
      techStack: req.techStack ?? [],
    });
    await this.deps.db.recordUsage(user.id, 'scan', SCAN_CREDIT_COST[req.mode], scan.id);
    this.emit(scan.id, 'status', `Scan queued (${scan.mode})`, { status: scan.status });
    await this.deps.queue.enqueue({ scanId: scan.id });
    return scan;
  }

  // ── Lifecycle control ───────────────────────────────────────────────────

  async pauseScan(scanId: string, userId: string): Promise<Scan> {
    const scan = await this.ownedScan(scanId, userId);
    this.transition(scan.status, 'paused');
    this.pausedScans.add(scanId);
    const updated = await this.deps.db.updateScan(scanId, { status: 'paused' });
    this.emit(scanId, 'status', 'Scan paused by user', { status: 'paused' });
    return updated as Scan;
  }

  async resumeScan(scanId: string, userId: string): Promise<Scan> {
    const scan = await this.ownedScan(scanId, userId);
    this.transition(scan.status, 'running');
    this.pausedScans.delete(scanId);
    const updated = await this.deps.db.updateScan(scanId, { status: 'running' });
    this.emit(scanId, 'status', 'Scan resumed', { status: 'running' });
    return updated as Scan;
  }

  async cancelScan(scanId: string, userId: string): Promise<Scan> {
    const scan = await this.ownedScan(scanId, userId);
    this.transition(scan.status, 'cancelled');
    this.pausedScans.delete(scanId);
    this.cancelledScans.add(scanId);
    const updated = await this.deps.db.updateScan(scanId, {
      status: 'cancelled',
      finishedAt: new Date().toISOString(),
    });
    this.emit(scanId, 'status', 'Scan cancelled by user', { status: 'cancelled' });
    return updated as Scan;
  }

  /** Retry a failed/cancelled scan by re-queueing it. */
  async retryScan(scanId: string, userId: string): Promise<Scan> {
    const scan = await this.ownedScan(scanId, userId);
    this.transition(scan.status, 'queued');
    this.cancelledScans.delete(scanId);
    const updated = await this.deps.db.updateScan(scanId, {
      status: 'queued',
      error: undefined,
      progress: { completedSteps: 0, totalSteps: 0 },
    });
    this.emit(scanId, 'status', 'Scan re-queued', { status: 'queued' });
    await this.deps.queue.enqueue({ scanId });
    return updated as Scan;
  }

  private async ownedScan(scanId: string, userId: string): Promise<Scan> {
    const scan = await this.deps.db.getScan(scanId);
    if (!scan || scan.userId !== userId) {
      throw Object.assign(new Error('Scan not found'), { statusCode: 404 });
    }
    return scan;
  }

  private transition(from: ScanStatus, to: ScanStatus): void {
    if (!VALID_TRANSITIONS[from].includes(to)) {
      throw Object.assign(new Error(`Invalid scan transition: ${from} → ${to}`), {
        statusCode: 409,
      });
    }
  }

  // ── Progress events (polled by the extension) ────────────────────────────

  getProgress(scanId: string, since = 0): { events: ScanProgressEvent[]; latestSeq: number } {
    const all = this.events.get(scanId) ?? [];
    return {
      events: all.filter((e) => e.seq > since),
      latestSeq: this.seq.get(scanId) ?? 0,
    };
  }

  private emit(scanId: string, kind: ScanProgressEvent['kind'], message: string, data?: unknown): void {
    const seq = (this.seq.get(scanId) ?? 0) + 1;
    this.seq.set(scanId, seq);
    const list = this.events.get(scanId) ?? [];
    list.push({ seq, at: new Date().toISOString(), kind, message, data });
    // Ring buffer: keep the last 500 events per scan.
    if (list.length > 500) list.splice(0, list.length - 500);
    this.events.set(scanId, list);
  }

  // ── Job execution ───────────────────────────────────────────────────────

  /** Queue worker entrypoint. */
  async handleJob(scanId: string): Promise<void> {
    const scan = await this.deps.db.getScan(scanId);
    if (!scan) return;
    if (scan.status !== 'queued') return; // already handled / cancelled

    await this.deps.db.updateScan(scanId, { status: 'running', startedAt: new Date().toISOString() });
    this.emit(scanId, 'status', 'Scan started', { status: 'running' });

    try {
      if (scan.mode === 'active') {
        await this.runActive(scan);
      } else {
        await this.runPassive(scan);
      }
      const current = await this.deps.db.getScan(scanId);
      if (current && current.status === 'running') {
        await this.deps.db.updateScan(scanId, {
          status: 'completed',
          finishedAt: new Date().toISOString(),
        });
        this.emit(scanId, 'status', 'Scan completed', { status: 'completed' });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await this.deps.db.updateScan(scanId, {
        status: 'failed',
        error: message.slice(0, 500),
        finishedAt: new Date().toISOString(),
      });
      this.emit(scanId, 'status', `Scan failed: ${message}`, { status: 'failed' });
    } finally {
      this.pausedScans.delete(scanId);
      this.cancelledScans.delete(scanId);
    }
  }

  /**
   * Active scan: full agent loop. Guardrails (scope, rate limit, SSRF,
   * authorization) are enforced inside the tools and at creation.
   */
  private async runActive(scan: Scan): Promise<void> {
    if (!scan.authorizationId) {
      // Defense in depth: creation requires this, but never run active
      // testing without a stored authorization record.
      throw new Error('Active scan blocked: no authorization record (plan §8)');
    }
    const target = new URL(scan.targetUrl);
    const outcome = await runAgentScan({
      scan,
      provider: this.deps.provider,
      scope: scan.scope,
      techStack: scan.techStack,
      limits: {
        maxActions: this.deps.config.agentMaxActions,
        maxDurationMs: this.deps.config.agentMaxDurationMs,
        requestsPerSecond: scan.scope.maxRequestsPerSecond,
      },
      allowPrivateTargets: this.deps.config.allowPrivateTargets,
      hooks: {
        tools: this.deps.toolOverrides,
        onEvent: (e) => {
          this.emit(scan.id, e.kind === 'finding' ? 'finding' : e.kind === 'done' ? 'status' : 'step', e.message, e.data);
          if (e.kind === 'act' || e.kind === 'done') {
            void this.deps.db
              .getScan(scan.id)
              .then((s) =>
                s && s.status === 'running'
                  ? this.deps.db.updateScan(scan.id, {
                      progress: {
                        completedSteps: outcome.testsRun,
                        totalSteps: outcome.testsPlanned,
                        currentStep: e.kind === 'act' ? e.message : undefined,
                      },
                    })
                  : undefined
              )
              .catch(() => undefined);
          }
        },
        shouldContinue: () => {
          if (this.cancelledScans.has(scan.id)) return 'cancelled';
          if (this.pausedScans.has(scan.id)) return 'paused';
          return 'run';
        },
        recordUsage: async (_kind, inputTokens, outputTokens) => {
          await this.deps.db.recordUsage(scan.userId, 'llm_call', inputTokens + outputTokens, scan.id);
        },
      },
    });

    for (const f of outcome.findings) {
      const cvss = estimateCvss(f.severity, f.category);
      const stored = await this.deps.db.addFinding({
        ...redactFindingEvidence(f),
        scanId: scan.id,
        cvssScore: cvss.score,
        cvssVector: cvss.vector,
      });
      void stored;
    }
    await this.deps.db.updateScan(scan.id, {
      progress: {
        completedSteps: outcome.testsRun,
        totalSteps: outcome.testsPlanned,
        currentStep: undefined,
      },
    });
    this.emit(scan.id, 'status', outcome.summary, { summary: outcome.summary });
  }

  /**
   * Passive scan: server-side safe checks (no payloads). The extension can
   * also POST its own Phase 1 findings to /api/scans/:id/findings.
   */
  private async runPassive(scan: Scan): Promise<void> {
    const target = new URL(scan.targetUrl);
    const ctx = createToolContext(target, scan.scope, this.deps.config.allowPrivateTargets);
    const tools = this.deps.toolOverrides ?? defaultTools();
    const headerTool = tools.find((t) => t.name === 'check_security_headers');
    const fetchTool = tools.find((t) => t.name === 'fetch_url');
    const total = 2;
    let done = 0;

    const findings: Array<Omit<Finding, 'id' | 'scanId' | 'createdAt'>> = [];

    if (headerTool) {
      this.emit(scan.id, 'step', 'Checking security headers…');
      const r = await headerTool.run({ url: scan.targetUrl }, ctx);
      done += 1;
      await this.deps.db.updateScan(scan.id, {
        progress: { completedSteps: done, totalSteps: total, currentStep: 'Security headers' },
      });
      const missing = (r.data?.['missing'] as string[]) ?? [];
      if (r.ok && missing.length > 0) {
        const cvss = estimateCvss('low', 'headers');
        findings.push({
          category: 'headers',
          title: `Missing security headers: ${missing.join(', ')}`,
          description:
            'One or more OWASP-recommended security headers are absent (observed passively).',
          severity: 'low',
          confidence: 'high',
          trapProbability: 0,
          honeypotSuspect: false,
          location: scan.targetUrl,
          evidence: `missing: ${missing.join(', ')}`,
          reproSteps: ['Fetch the target URL and inspect response headers.'],
          remediation:
            'Set Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.',
          references: ['https://owasp.org/www-project-secure-headers/'],
          cvssScore: cvss.score,
          cvssVector: cvss.vector,
        });
      }
    }

    if (fetchTool) {
      this.emit(scan.id, 'step', 'Fingerprinting technology stack…');
      const r = await fetchTool.run({ url: scan.targetUrl }, ctx);
      done += 1;
      const tech: Scan['techStack'] = [];
      const server = r.data?.['serverDisclosure'];
      if (typeof server === 'string' && server) tech.push({ name: server });
      await this.deps.db.updateScan(scan.id, {
        techStack: tech,
        progress: { completedSteps: done, totalSteps: total, currentStep: undefined },
      });
    }

    for (const f of findings) {
      await this.deps.db.addFinding({ ...redactFindingEvidence(f), scanId: scan.id });
      this.emit(scan.id, 'finding', `Finding: ${f.title} [${f.severity}]`);
    }
    this.emit(scan.id, 'status', `Passive scan finished: ${findings.length} finding(s)`);
  }
}
