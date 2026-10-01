import type {
  Confidence,
  Finding,
  ScopePolicy,
  Severity,
  TechEntry,
} from '../types.js';
import type { LLMProvider } from '../llm/provider.js';
import type { AgentTool, ToolExecutionContext } from '../agent/tools.js';

/**
 * Multi-agent system ("super agent") — shared types.
 *
 * Architecture:
 *   HeadAgent (head.ts)
 *     1. Runs the recon specialist first (fast, deterministic-heavy).
 *     2. PLANS which specialist workers to spawn, adapted to the tech stack
 *        and recon findings (e.g. GraphQL endpoint seen → graphql worker).
 *     3. Spawns workers with bounded concurrency; workers share ONE
 *        ToolExecutionContext (single rate limiter + scope guardrail), so N
 *        workers can never DDoS the target.
 *     4. Collects WorkerReports → dedupes → head-level trap review →
 *        attack chaining → final synthesis.
 *   Specialist workers (worker.ts + specialists.ts): each runs its own
 *   PLAN → ACT → OBSERVE → REFLECT loop with a specialist system prompt, a
 *   restricted tool subset, and its own budgets, then reports home.
 *
 * Cost control (the user is a cost-sensitive student): planning and triage
 * reflection use the cheap 'routine' tier; the expensive 'reasoning' tier is
 * reserved for escalated reflection (triage says "candidate finding") and the
 * head's final synthesis.
 */

export type SpecialistId =
  | 'recon'
  | 'secrets'
  | 'headers'
  | 'cors'
  | 'xss'
  | 'idor'
  | 'auth'
  | 'graphql';

export interface SpecialistDef {
  id: SpecialistId;
  name: string;
  /** What this worker is an expert in (1-2 lines, used in prompts). */
  expertise: string;
  /** Specialist system prompt for PLAN + REFLECT. */
  systemPrompt: string;
  /** Tool names this worker may use (subset of the registry). */
  tools: string[];
  /** Max LLM-planned actions for this worker. */
  maxActions: number;
  /** Max reasoning-tier escalations per worker (cost cap). */
  maxEscalations: number;
}

export interface WorkerFinding {
  severity: Severity;
  confidence: Confidence;
  category: string;
  title: string;
  description: string;
  location: string;
  evidence: string;
  reproSteps: string[];
  remediation: string;
  references: string[];
  trapProbability: number;
  chainWith: string[];
}

export interface WorkerReport {
  specialistId: SpecialistId;
  specialistName: string;
  summary: string;
  findings: WorkerFinding[];
  testsRun: number;
  testsPlanned: number;
  escalations: number;
  llmCalls: number;
  tokensUsed: { input: number; output: number };
  errors: string[];
  durationMs: number;
  notes: string[];
}

export interface MultiAgentLimits {
  /** Max specialists to spawn (after recon). */
  maxWorkers: number;
  /** How many workers run at the same time. */
  maxConcurrency: number;
  /** Hard cap on total LLM tokens for the whole run (input+output). */
  maxTotalTokens: number;
  /** Hard wall-clock cap for the whole run. */
  maxDurationMs: number;
  /** Requests/sec across ALL workers (shared limiter). */
  requestsPerSecond: number;
  /** Skip private-target refusal (self-hosted labs like Juice Shop). */
  allowPrivateTargets: boolean;
}

export interface MultiAgentOptions {
  targetUrl: string;
  scope: ScopePolicy;
  provider: LLMProvider;
  techStack?: TechEntry[];
  limits?: Partial<MultiAgentLimits>;
  /** Force a specific specialist set (skips head planning). */
  specialists?: SpecialistId[];
  onEvent?: (e: MultiAgentEvent) => void;
  shouldContinue?: () => 'run' | 'paused' | 'cancelled';
}

export type MultiAgentEventKind =
  | 'head_plan'
  | 'worker_start'
  | 'worker_progress'
  | 'worker_done'
  | 'head_review'
  | 'head_synthesis'
  | 'guardrail'
  | 'done';

export interface MultiAgentEvent {
  kind: MultiAgentEventKind;
  message: string;
  data?: unknown;
}

export interface MultiAgentOutcome {
  targetUrl: string;
  findings: Array<Omit<Finding, 'id' | 'scanId' | 'createdAt'>>;
  workerReports: WorkerReport[];
  headSummary: string;
  testsRun: number;
  llmCalls: number;
  tokensUsed: { input: number; output: number };
  durationMs: number;
  errors: string[];
}

export interface WorkerContext {
  provider: LLMProvider;
  tools: AgentTool[];
  toolCtx: ToolExecutionContext;
  targetUrl: string;
  scope: ScopePolicy;
  techStack: TechEntry[];
  priorFindings: string[];
  deadline: number;
  tokenBudget: { input: number; output: number; max: number };
  shouldContinue?: () => 'run' | 'paused' | 'cancelled';
  onEvent?: (e: MultiAgentEvent) => void;
}
