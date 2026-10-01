/**
 * Shared backend types for BugSeek AI Phase 2.
 *
 * NOTE on backward compatibility with the Phase 1 extension
 * (bugseek/src/lib/types.ts): the backend `Finding` type keeps every Phase 1
 * field name and meaning. New fields are additive only (cvssScore,
 * cvssVector, trapProbability, honeypotSuspect, reproSteps, references), so
 * old clients keep working. The extension sibling may add fields but MUST NOT
 * rename or change the meaning of existing ones — see docs/schemas.md.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export type Confidence = 'high' | 'medium' | 'low';

export type ScanMode = 'passive' | 'active';

export type ScanStatus =
  | 'queued'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type PlanTier = 'free' | 'hunter' | 'pro' | 'enterprise';

export type AuthzType = 'bug-bounty' | 'pentest-contract' | 'ownership';

/**
 * Scope boundaries the agent MUST NOT cross (plan §8: scope enforcement).
 * `mode` mirrors the extension's scope confirmation step:
 * - 'full-domain': the target host + subdomains (if includeSubdomains)
 * - 'subdomain': only the exact target host
 * - 'page': only the exact target URL (no crawling)
 */
export interface ScopePolicy {
  mode: 'full-domain' | 'subdomain' | 'page';
  includeSubdomains: boolean;
  excludedHosts: string[];
  excludedPaths: string[];
  maxRequestsPerSecond: number;
}

export interface AuthorizationRecord {
  id: string;
  userId: string;
  type: AuthzType;
  programName?: string;
  referenceUrl?: string;
  /** User's explicit statement of authorization, stored verbatim. */
  statement: string;
  confirmedAt: string; // ISO
}

export interface TechEntry {
  name: string;
  version?: string;
}

export interface ScanProgress {
  completedSteps: number;
  totalSteps: number;
  currentStep?: string;
}

export interface Scan {
  id: string;
  userId: string;
  targetUrl: string;
  mode: ScanMode;
  status: ScanStatus;
  scope: ScopePolicy;
  /** Authorization record id — REQUIRED for active scans (plan §8). */
  authorizationId?: string;
  techStack: TechEntry[];
  progress: ScanProgress;
  error?: string;
  createdAt: string; // ISO
  startedAt?: string; // ISO
  finishedAt?: string; // ISO
}

/**
 * Canonical server-side finding.
 *
 * LEGAL GUARDRAIL (plan §8 — data handling): `evidence` MUST be redacted
 * before persistence. The backend runs every finding through
 * `redactEvidence()` (guardrails/redact.ts) which masks secrets, tokens,
 * credentials and PII. Findings reference the vulnerability; they never
 * reproduce sensitive data itself.
 */
export interface Finding {
  id: string;
  scanId: string;
  /**
   * Superset of the Phase 1 FindingCategory. Phase 1 values
   * ('secrets' | 'cookies' | 'headers' | 'tech' | 'dom' | 'sinks') remain
   * valid; active-testing categories are additive.
   */
  category: string;
  title: string;
  description: string;
  severity: Severity;
  /** CVSS v3.1 base-score estimate (see reports/cvss.ts). */
  cvssScore?: number;
  cvssVector?: string;
  confidence: Confidence;
  /**
   * Honeypot/trap suspicion, 0..1 (plan §4.5). Findings with
   * trapProbability >= 0.6 are flagged via `honeypotSuspect` and presented
   * as "possible trap — verify manually", not as confirmed vulnerabilities.
   */
  trapProbability: number;
  honeypotSuspect: boolean;
  /** Where the finding was observed. Never contains raw secrets. */
  location?: string;
  /** Truncated, REDACTED evidence snippet. */
  evidence?: string;
  reproSteps: string[];
  remediation: string;
  references: string[];
  createdAt: string; // ISO
}

export interface ScanProgressEvent {
  seq: number;
  at: string; // ISO
  kind: 'status' | 'step' | 'finding' | 'log' | 'guardrail';
  message: string;
  data?: unknown;
}

export interface UserRecord {
  id: string;
  email: string;
  passwordHash: string;
  plan: PlanTier;
  createdAt: string; // ISO
}

export interface ApiKeyRecord {
  id: string;
  userId: string;
  name: string;
  keyHash: string;
  /** e.g. "bs_a1b2" — safe to display, used for key identification. */
  keyPrefix: string;
  createdAt: string; // ISO
  lastUsedAt?: string; // ISO
  revokedAt?: string; // ISO
}
