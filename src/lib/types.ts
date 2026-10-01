/**
 * Shared types for BugSeek AI (passive reconnaissance + active testing).
 *
 * Phase 1 fields are unchanged; Phase 2 additions are additive only so they
 * stay compatible with the backend contract in
 * ~/workspace/bugseek/backend/src/types.ts (see docs/schemas.md).
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

export type ScanMode = 'passive' | 'active';

export type FindingCategory =
  | 'secrets'
  | 'cookies'
  | 'headers'
  | 'tech'
  | 'dom'
  | 'sinks'
  // Active-testing categories (Phase 2+)
  | 'network'
  | 'cors'
  | 'api'
  | 'xss'
  | 'idor'
  | 'auth'
  | 'graphql'
  | 'chain';

export interface Finding {
  id: string;
  category: FindingCategory;
  title: string;
  description: string;
  severity: Severity;
  confidence: 'high' | 'medium' | 'low';
  /** Where the finding was observed (script src, cookie name, header name, DOM context). */
  location?: string;
  /** Truncated, redacted evidence snippet. Never contains full secrets. */
  evidence?: string;
  remediation: string;

  // ---- Phase 2 additions (all optional, additive) ----
  /** Which scan mode produced this finding. Defaults to 'passive'. */
  mode?: ScanMode;
  /** Machine-readable tags used for attack-chain matching, e.g. 'xss-confirmed'. */
  tags?: string[];
  /** CVSS v3.1 base score, 0.0–10.0 (set for active findings). */
  cvssScore?: number;
  /** CVSS v3.1 vector string, e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'. */
  cvssVector?: string;
  /** Human-readable justification for the CVSS metrics chosen. */
  cvssJustification?: string;
  /** Honeypot/trap suspicion probability, 0..1 (product plan §4.5). */
  trapProbability?: number;
  /** Signals that contributed to trapProbability. */
  trapSignals?: string[];
  /**
   * True when trapProbability >= TRAP_FLAG_THRESHOLD (0.6, matches backend).
   * Flagged findings are presented as "possible trap — verify manually",
   * NOT reported as vulnerabilities.
   */
  honeypotSuspect?: boolean;
  /** True when confirmed by observation (e.g. payload execution), not mere presence. */
  confirmed?: boolean;
  /** Step-by-step reproduction instructions (active findings). */
  reproSteps?: string[];
  /** Reference URLs (CWE / OWASP). */
  references?: string[];
  /** IDs of attack chains this finding participates in. */
  attackChainIds?: string[];
  /** Active HTTP requests spent to produce this finding (accountability). */
  requestCount?: number;
}

export interface TechFingerprint {
  name: string;
  version?: string;
  source: 'header' | 'meta' | 'script' | 'dom' | 'global';
}

/** Raw data collected by the content script from the target page. */
export interface DomScanData {
  url: string;
  title: string;
  forms: Array<{
    action: string;
    method: string;
    inputCount: number;
    hasPassword: boolean;
  }>;
  inputs: Array<{ type: string; name: string; id: string; hidden: boolean }>;
  hiddenInputCount: number;
  iframes: Array<{ src: string; sameOrigin: boolean }>;
  /** Trimmed HTML comment bodies found in the page. */
  comments: string[];
  /** Inline <script> bodies (truncated by collector). */
  inlineScripts: string[];
  /** Absolute URLs of external scripts. */
  externalScripts: string[];
  metaTags: Array<{ name: string; content: string }>;
  /** Potential DOM-based XSS sinks found in inline scripts. */
  sinks: Array<{ sink: string; count: number; sample: string }>;
  /** Page JS globals detected via MAIN-world probe (e.g. "jQuery 3.7.1"). */
  globals: string[];
  inlineHandlerCount: number;
}

/**
 * Scope boundaries the active scanner MUST NOT cross (product plan §8).
 * Stored with the authorization record and enforced on every active request.
 */
export interface ScopePolicy {
  /** 'full-domain': target host + subdomains · 'subdomain': exact host · 'page': target URL only */
  mode: 'full-domain' | 'subdomain' | 'page';
  includeSubdomains: boolean;
  excludedHosts: string[];
  /** Path prefixes (e.g. '/logout', '/billing') that must never be requested. */
  excludedPaths: string[];
  maxRequestsPerSecond: number;
}

/**
 * Explicit user authorization for active testing (product plan §8).
 * No active request is sent before a record exists for the target host.
 */
export interface AuthorizationRecord {
  id: string;
  /** Host this authorization applies to (subdomains per scope.includeSubdomains). */
  targetHost: string;
  type: 'bug-bounty' | 'pentest-contract' | 'ownership';
  programName?: string;
  /** The user's explicit confirmation statement, stored verbatim. */
  statement: string;
  scope: ScopePolicy;
  /**
   * Separately-gated permission for login-form testing (default-credential
   * probes, brute-force protection checks). Never implied by the base grant.
   */
  allowAuthProbes: boolean;
  /** Minimum gap between active requests, ms (default 1500, min 250). */
  rateLimitMs: number;
  confirmedAt: string; // ISO timestamp
}

/** An attack chain links findings into a higher-impact narrative (plan §4.4). */
export interface AttackChain {
  id: string;
  title: string;
  description: string;
  /** Ordered finding IDs that compose the chain. */
  findingIds: string[];
  severity: Severity;
  confidence: 'high' | 'medium' | 'low';
  /** Highest CVSS among member findings, if any. */
  cvssScore?: number;
  impact: string;
  /** True when the backend AI agent deepened/verified this chain. */
  aiDeepened?: boolean;
}

export interface ActiveScanStats {
  requestsMade: number;
  throttledMs: number;
  maxRequests: number;
  rateLimitMs: number;
  backendReachable: boolean;
  backendDeepened: boolean;
}

export interface ScanResult {
  targetUrl: string;
  scannedAt: string; // ISO timestamp
  durationMs: number;
  tech: TechFingerprint[];
  findings: Finding[];
  /** Defaults to 'passive'. */
  mode?: ScanMode;
  /** Attack chains (active scans). */
  chains?: AttackChain[];
  /** Snapshot of the authorization record used (active scans). */
  authorization?: AuthorizationRecord;
  /** Request/throttle accounting (active scans). */
  activeStats?: ActiveScanStats;
}

export type ScanMessage =
  | { type: 'RUN_SCAN'; tabId: number }
  | { type: 'COLLECT_DOM' }
  | { type: 'SCAN_PROGRESS'; step: string }
  | { type: 'SCAN_DONE'; result: ScanResult }
  | { type: 'SCAN_ERROR'; error: string }
  // Active testing (Phase 2)
  | { type: 'RUN_ACTIVE_SCAN'; tabId: number; deepInspect?: boolean }
  | {
      type: 'ACTIVE_PROGRESS';
      step: string;
      requestsMade: number;
      rateLimitMs: number;
      nextRequestInMs: number;
    }
  | { type: 'ACTIVE_DONE'; result: ScanResult }
  | { type: 'ACTIVE_ERROR'; error: string }
  // Background -> content script: confirm reflected XSS via DOM observation.
  | { type: 'XSS_PROBE'; url: string; marker: string };

/** Response from the content script to an XSS_PROBE message. */
export interface XssProbeResponse {
  ok: boolean;
  executed?: boolean;
  error?: string;
}
