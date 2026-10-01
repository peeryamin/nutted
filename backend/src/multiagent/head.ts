import type { TechEntry } from '../types.js';
import { defaultTools, createToolContext } from '../agent/tools.js';
import { extraTools } from './extraTools.js';
import { getSpecialist, allSpecialists, ALWAYS_SPAWN, CONDITIONAL_SPAWN } from './specialists.js';
import { runWorker } from './worker.js';
import type {
  MultiAgentEvent,
  MultiAgentLimits,
  MultiAgentOptions,
  MultiAgentOutcome,
  SpecialistId,
  WorkerContext,
  WorkerFinding,
  WorkerReport,
} from './types.js';

const DEFAULT_LIMITS: MultiAgentLimits = {
  maxWorkers: 7,
  maxConcurrency: 3,
  maxTotalTokens: 120_000,
  maxDurationMs: 10 * 60_000,
  requestsPerSecond: 2,
  allowPrivateTargets: false,
};

const SEVERITY_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const HEAD_SYSTEM = `You are the HEAD AGENT of a multi-agent web-security testing swarm ("BugSeek swarm").
You coordinate specialist worker agents, each an expert in one vulnerability class.
Your jobs: (1) decide which specialists to deploy based on recon, (2) review their reports for duplicates and honeypot traps, (3) chain related findings into attack scenarios, (4) write the final executive summary.

HARD RULES:
- All testing is authorized, in-scope, rate-limited, non-destructive. Never ask a worker to go outside scope.
- Be skeptical: duplicates across workers must be merged, not multiplied. Trap-like findings must be flagged, not celebrated.
- Return ONLY valid JSON — no prose, no markdown fences.`;

async function runPool<T>(items: T[], concurrency: number, fn: (t: T) => Promise<void>): Promise<void> {
  const queue = [...items];
  const runners = Array.from(
    { length: Math.max(1, Math.min(concurrency, queue.length)) },
    async () => {
      while (queue.length > 0) {
        const item = queue.shift() as T;
        await fn(item);
      }
    },
  );
  await Promise.all(runners);
}

function dedupeFindings(reports: WorkerReport[]): WorkerFinding[] {
  const byKey = new Map<string, WorkerFinding>();
  for (const r of reports) {
    for (const f of r.findings) {
      const key = `${f.category}|${f.title.toLowerCase().trim()}|${f.location.toLowerCase().trim()}`;
      const existing = byKey.get(key);
      if (!existing) {
        byKey.set(key, { ...f, chainWith: [...f.chainWith] });
      } else {
        // Keep the higher severity / confidence; merge chain hints.
        if ((SEVERITY_RANK[f.severity] ?? 0) > (SEVERITY_RANK[existing.severity] ?? 0)) {
          byKey.set(key, {
            ...f,
            chainWith: [...new Set([...existing.chainWith, ...f.chainWith])],
            description: existing.description.length > f.description.length ? existing.description : f.description,
          });
        } else {
          existing.chainWith = [...new Set([...existing.chainWith, ...f.chainWith])];
        }
      }
    }
  }
  return [...byKey.values()].sort(
    (a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0),
  );
}

/**
 * Head agent run: recon → plan specialists → spawn workers (bounded
 * concurrency, shared rate limiter) → dedupe → trap review → chaining →
 * executive synthesis.
 */
export async function runHeadAgent(opts: MultiAgentOptions): Promise<MultiAgentOutcome> {
  const started = Date.now();
  // Merge caller limits over defaults, ignoring undefined values: spreading
  // { requestsPerSecond: undefined } would otherwise clobber the default
  // and poison the token-bucket rate limiter (NaN refill → busy loop).
  const limits: MultiAgentLimits = { ...DEFAULT_LIMITS };
  for (const [k, v] of Object.entries(opts.limits ?? {})) {
    if (v !== undefined) {
      (limits as unknown as Record<string, unknown>)[k] = v;
    }
  }
  const emit = (e: MultiAgentEvent) => opts.onEvent?.(e);
  const event = (kind: MultiAgentEvent['kind'], message: string, data?: unknown) =>
    emit({ kind, message, data });

  const target = new URL(opts.targetUrl);
  const scope = {
    mode: opts.scope.mode,
    includeSubdomains: opts.scope.includeSubdomains,
    excludedHosts: opts.scope.excludedHosts ?? [],
    excludedPaths: opts.scope.excludedPaths ?? [],
    maxRequestsPerSecond: limits.requestsPerSecond,
  };
  const registry = [...defaultTools(), ...extraTools()];
  const toolCtx = createToolContext(target, scope, limits.allowPrivateTargets);
  const tokenBudget = { input: 0, output: 0, max: limits.maxTotalTokens };
  const deadline = Date.now() + limits.maxDurationMs;

  const spend = (input: number, output: number): boolean => {
    tokenBudget.input += input;
    tokenBudget.output += output;
    return tokenBudget.input + tokenBudget.output <= tokenBudget.max;
  };

  const errors: string[] = [];
  const workerReports: WorkerReport[] = [];
  const techStack: TechEntry[] = [...(opts.techStack ?? [])];

  const makeWorkerCtx = (prior: string[]): WorkerContext => ({
    provider: opts.provider,
    tools: registry,
    toolCtx,
    targetUrl: opts.targetUrl,
    scope,
    techStack,
    priorFindings: prior,
    deadline,
    tokenBudget,
    shouldContinue: opts.shouldContinue,
    onEvent: (e) => emit(e),
  });

  // ── Phase 0: recon worker first (fast, informs everything else) ──
  event('head_plan', `Head agent starting multi-agent scan of ${opts.targetUrl}`);
  const reconDef = getSpecialist('recon');
  event('worker_start', `Spawning ${reconDef.name} (phase 0)`);
  const reconReport = await runWorker(reconDef, makeWorkerCtx([]));
  workerReports.push(reconReport);
  event('worker_done', reconReport.summary, { specialist: reconDef.id });

  // Pull tech-stack hints from recon findings (category 'tech').
  for (const f of reconReport.findings) {
    if (f.category === 'tech' && f.title && !techStack.some((t) => t.name === f.title)) {
      techStack.push({ name: f.title.slice(0, 80) });
    }
  }
  const reconNotes = [
    reconReport.summary,
    ...reconReport.findings.map((f) => `${f.title} (${f.severity})`),
    ...reconReport.notes,
  ].join(' | ').slice(0, 2000);

  // ── Phase 1: head plans which specialists to deploy ──
  let specialistIds: SpecialistId[];
  if (opts.specialists && opts.specialists.length > 0) {
    specialistIds = [...new Set(opts.specialists)].filter((id) => id !== 'recon');
    event('head_plan', `Using caller-specified specialists: ${specialistIds.join(', ')}`);
  } else {
    const catalog = allSpecialists()
      .filter((d) => d.id !== 'recon')
      .map((d) => `- ${d.id}: ${d.expertise}`)
      .join('\n');
    try {
      const planCompletion = await opts.provider.complete({
        messages: [
          { role: 'system', content: HEAD_SYSTEM },
          {
            role: 'user',
            content:
              `TARGET: ${opts.targetUrl}\n` +
              `TECH STACK: ${techStack.map((t) => t.name).join(', ') || 'unknown'}\n` +
              `RECON RESULTS: ${reconNotes}\n\n` +
              `Always spawn: ${ALWAYS_SPAWN.join(', ')} (already decided).\n` +
              `Decide which of these CONDITIONAL specialists to spawn, based on recon:\n${catalog}\n\n` +
              `Rules: max ${limits.maxWorkers} total workers. Spawn 'graphql' only if GraphQL was referenced. ` +
              `Spawn 'auth' only if login/session behavior was observed. Spawn 'xss' if user-input reflections or forms exist. ` +
              `Spawn 'idor' if numeric object IDs were seen.\n` +
              `Return JSON: {"specialists":["xss","idor"],"rationale":"..."}`,
          },
        ],
        maxTokens: 600,
        temperature: 0.2,
        tier: 'routine',
      });
      if (!spend(planCompletion.usage.inputTokens, planCompletion.usage.outputTokens)) {
        throw new Error('token budget exhausted during head planning');
      }
      const parsed = planCompletion.parseJson<{ specialists: string[]; rationale: string }>();
      const conditional = (parsed.specialists ?? []).filter((id): id is SpecialistId =>
        (CONDITIONAL_SPAWN as string[]).includes(id),
      );
      specialistIds = [...new Set([...ALWAYS_SPAWN, ...conditional])].slice(0, limits.maxWorkers);
      event('head_plan', `Deploying specialists: ${specialistIds.join(', ')}`, {
        rationale: parsed.rationale,
      });
    } catch (err) {
      errors.push(`head planning failed: ${(err as Error).message} — falling back to always-spawn set`);
      specialistIds = [...ALWAYS_SPAWN];
      event('guardrail', 'Head planning failed; using default specialist set');
    }
  }

  // ── Phase 2: spawn workers with bounded concurrency ──
  const priorTitles: string[] = workerReports.flatMap((r) => r.findings.map((f) => f.title));
  await runPool(specialistIds, limits.maxConcurrency, async (id) => {
    const def = getSpecialist(id);
    event('worker_start', `Spawning ${def.name}`);
    try {
      const rep = await runWorker(def, makeWorkerCtx([...priorTitles]));
      workerReports.push(rep);
      for (const f of rep.findings) priorTitles.push(f.title);
      event('worker_done', rep.summary, { specialist: id });
    } catch (err) {
      const msg = `${def.name} crashed: ${(err as Error).message}`;
      errors.push(msg);
      event('guardrail', msg);
    }
  });

  // ── Phase 3: dedupe ──
  const deduped = dedupeFindings(workerReports);
  event('head_review', `Deduped to ${deduped.length} unique findings`, {
    before: workerReports.reduce((n, r) => n + r.findings.length, 0),
  });

  // ── Phase 4: head-level trap review (reasoning tier, capped) ──
  const reviewCandidates = deduped.filter(
    (f) => f.trapProbability >= 0.3 || (SEVERITY_RANK[f.severity] ?? 0) >= 4,
  ).slice(0, 10);
  if (reviewCandidates.length > 0 && tokenBudget.input + tokenBudget.output < tokenBudget.max) {
    event('head_review', `Reviewing ${reviewCandidates.length} findings for traps/chains`);
    try {
      const reviewCompletion = await opts.provider.complete({
        messages: [
          { role: 'system', content: HEAD_SYSTEM },
          {
            role: 'user',
            content:
              `Review these findings from specialist workers. For each: confirm or adjust trapProbability ` +
              `(raise it if it smells like a honeypot/canary/too-easy trap), and suggest attack chains ` +
              `(which findings combine into a bigger impact).\n\n` +
              `${JSON.stringify(reviewCandidates.map((f, i) => ({ i, title: f.title, severity: f.severity, category: f.category, description: f.description.slice(0, 400), evidence: f.evidence.slice(0, 200), trapProbability: f.trapProbability, chainWith: f.chainWith })), null, 1)}\n\n` +
              `Return JSON: {"reviews":[{"i":0,"trapProbability":0.0-1.0,"trapReason":"...","chains":["..."]}],"chains":[{"name":"...","members":[0,2],"impact":"..."}]}`,
          },
        ],
        maxTokens: 2000,
        temperature: 0.1,
        tier: 'reasoning',
      });
      if (spend(reviewCompletion.usage.inputTokens, reviewCompletion.usage.outputTokens)) {
        const reviewed = reviewCompletion.parseJson<{
          reviews: Array<{ i: number; trapProbability: number; trapReason?: string; chains?: string[] }>;
          chains: Array<{ name: string; members: number[]; impact: string }>;
        }>();
        for (const r of reviewed.reviews ?? []) {
          const f = reviewCandidates[r.i];
          if (!f) continue;
          if (typeof r.trapProbability === 'number') {
            f.trapProbability = Math.min(1, Math.max(0, r.trapProbability));
            if (r.trapReason) f.description += `\n\nHead-agent trap review: ${r.trapReason}`;
          }
          if (r.chains) f.chainWith = [...new Set([...f.chainWith, ...r.chains])];
        }
        for (const c of reviewed.chains ?? []) {
          const memberTitles = (c.members ?? [])
            .map((i) => reviewCandidates[i]?.title)
            .filter(Boolean);
          if (memberTitles.length >= 2) {
            for (const t of memberTitles) {
              const f = deduped.find((x) => x.title === t);
              if (f) f.chainWith = [...new Set([...f.chainWith, `chain:${c.name}`])];
            }
          }
        }
      }
    } catch (err) {
      errors.push(`head trap review failed: ${(err as Error).message}`);
      event('guardrail', 'Head trap review failed — keeping worker verdicts');
    }
  }

  // ── Phase 5: executive synthesis (reasoning tier) ──
  let headSummary = '';
  const sevCounts = deduped.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});
  if (tokenBudget.input + tokenBudget.output < tokenBudget.max) {
    event('head_synthesis', 'Writing executive summary');
    try {
      const synth = await opts.provider.complete({
        messages: [
          { role: 'system', content: HEAD_SYSTEM },
          {
            role: 'user',
            content:
              `TARGET: ${opts.targetUrl}\n` +
              `WORKERS: ${workerReports.map((r) => r.specialistName).join(', ')}\n` +
              `FINDINGS (${deduped.length}): ${deduped.map((f) => `[${f.severity}/${f.confidence}] ${f.title} @ ${f.location} (trap=${f.trapProbability.toFixed(2)})`).join(' | ') || 'none'}\n` +
              `Write a concise executive summary for a bug-bounty hunter: overall risk rating, the 3 most important findings and why, any attack chains, and what to test next manually. 150-250 words. Plain text, no JSON.`,
          },
        ],
        maxTokens: 600,
        temperature: 0.3,
        tier: 'reasoning',
      });
      spend(synth.usage.inputTokens, synth.usage.outputTokens);
      headSummary = synth.text.trim();
    } catch (err) {
      errors.push(`synthesis failed: ${(err as Error).message}`);
    }
  }
  if (!headSummary) {
    const parts = Object.entries(sevCounts).map(([s, n]) => `${n} ${s}`);
    headSummary = `Multi-agent scan of ${opts.targetUrl} completed with ${deduped.length} unique findings (${parts.join(', ') || 'none'}).`;
  }

  const testsRun = workerReports.reduce((n, r) => n + r.testsRun, 0);
  const llmCalls = workerReports.reduce((n, r) => n + r.llmCalls, 0);

  event('done', `Multi-agent scan complete: ${deduped.length} findings, ${testsRun} tests`);

  return {
    targetUrl: opts.targetUrl,
    findings: deduped.map((f) => ({
      category: f.category,
      title: f.title,
      description: f.description,
      severity: f.severity,
      confidence: f.confidence,
      trapProbability: f.trapProbability,
      honeypotSuspect: f.trapProbability >= 0.6,
      location: f.location,
      evidence: f.evidence,
      reproSteps: f.reproSteps,
      remediation: f.remediation,
      references: f.references,
    })),
    workerReports,
    headSummary,
    testsRun,
    llmCalls,
    tokensUsed: { input: tokenBudget.input, output: tokenBudget.output },
    durationMs: Date.now() - started,
    errors,
  };
}
