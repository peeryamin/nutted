/**
 * Backend API client — the SINGLE module that talks to the BugSeek backend.
 *
 * The backend (~/workspace/bugseek/backend, Fastify, default
 * http://localhost:3000) is built by a sibling worker in parallel, so every
 * endpoint here is provisional: each call has a short timeout and degrades to
 * null when the backend is unreachable. The extension is fully functional
 * standalone — backend calls only add AI deepening, scan history, and richer
 * reports on top of local results.
 */
import {
  BACKEND_BASE_URL,
  BACKEND_REQUEST_TIMEOUT_MS,
} from './config';
import type { AttackChain, Finding, ScanResult } from './types';
import { buildChainDeepeningRequest } from './attackChains';

export interface BackendStatus {
  reachable: boolean;
  baseUrl: string;
  version?: string;
}

/** Backend API key (bs_…), stored by the user in extension settings. Sent as x-api-key. */
const API_KEY_STORAGE_KEY = 'bugseek:apiKey';

export async function getBackendApiKey(): Promise<string | null> {
  try {
    const stored = await chrome.storage.local.get(API_KEY_STORAGE_KEY);
    const key = stored[API_KEY_STORAGE_KEY];
    return typeof key === 'string' && key.startsWith('bs_') ? key : null;
  } catch {
    return null;
  }
}

export async function setBackendApiKey(key: string | null): Promise<void> {
  try {
    if (key) await chrome.storage.local.set({ [API_KEY_STORAGE_KEY]: key });
    else await chrome.storage.local.remove(API_KEY_STORAGE_KEY);
  } catch {
    /* storage unavailable — backend calls simply stay unauthenticated */
  }
}

async function fetchJson<T>(
  path: string,
  init: RequestInit,
  timeoutMs = BACKEND_REQUEST_TIMEOUT_MS,
): Promise<T | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const apiKey = await getBackendApiKey();
    const res = await fetch(`${BACKEND_BASE_URL}${path}`, {
      ...init,
      signal: ctrl.signal,
      headers: {
        'content-type': 'application/json',
        ...(apiKey ? { 'x-api-key': apiKey } : {}),
        ...(init.headers ?? {}),
      },
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    clearTimeout(timer);
    return null;
  }
}

/** Cheap liveness probe used for the popup's backend status badge. */
export async function checkBackendStatus(): Promise<BackendStatus> {
  const health = await fetchJson<{ version?: string }>(
    '/api/v1/health',
    { method: 'GET' },
    2500,
  );
  return {
    reachable: health !== null,
    baseUrl: BACKEND_BASE_URL,
    version: health?.version,
  };
}

/**
 * Ask the backend AI agent to deepen/verify locally-built attack chains
 * (plan → act → observe → reflect loop, plan §4.4). Returns the chains with
 * aiDeepened flags/verdicts merged in, or null when offline.
 */
export async function deepenAttackChains(
  targetUrl: string,
  chains: AttackChain[],
  findings: Finding[],
): Promise<AttackChain[] | null> {
  if (chains.length === 0) return chains;
  const req = buildChainDeepeningRequest(targetUrl, chains, findings);
  const res = await fetchJson<{
    chains: Array<{ id: string; verdict: string; confidence?: string; note?: string }>;
  }>('/api/v1/chains/analyze', {
    method: 'POST',
    body: JSON.stringify(req),
  });
  if (!res) return null;
  const verdicts = new Map(res.chains.map((c) => [c.id, c]));
  return chains.map((c) => {
    const v = verdicts.get(c.id);
    if (!v) return c;
    return {
      ...c,
      aiDeepened: true,
      description: v.note ? `${c.description}\n\nAI verdict (${v.verdict}): ${v.note}` : c.description,
    };
  });
}

/**
 * Run the backend multi-agent swarm (head agent + specialist workers) against
 * an authorized target. POST /api/swarm/scans (Hunter+, 25 credits).
 * Returns the swarm outcome (head summary + persisted findings), or null when
 * offline. The caller must pass the user's explicit authorization — the
 * backend re-validates it (plan §8).
 */
export interface SwarmAuthorizationInput {
  type: 'bug-bounty' | 'pentest-contract' | 'ownership';
  programName?: string;
  referenceUrl?: string;
  statement: string;
  confirmed: true;
}

export interface SwarmScopeInput {
  mode?: 'full-domain' | 'subdomain' | 'page';
  includeSubdomains?: boolean;
  excludedHosts?: string[];
  excludedPaths?: string[];
}

export interface SwarmOutcome {
  scanId: string;
  targetUrl: string;
  headSummary: string;
  findings: Array<{
    id: string;
    category: string;
    title: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    confidence: 'high' | 'medium' | 'low';
    location?: string;
    evidence?: string;
    remediation: string;
    cvssScore?: number;
    cvssVector?: string;
    trapProbability?: number;
    honeypotSuspect?: boolean;
  }>;
  workerReports: Array<{
    specialistId: string;
    specialistName: string;
    summary: string;
    testsRun: number;
    findings: number;
    tokensUsed: number;
    durationMs: number;
  }>;
  testsRun: number;
  tokensUsed: number;
  durationMs: number;
}

export async function runSwarmScan(
  targetUrl: string,
  authorization: SwarmAuthorizationInput,
  scope?: SwarmScopeInput,
): Promise<SwarmOutcome | null> {
  return fetchJson<SwarmOutcome>('/api/swarm/scans', {
    method: 'POST',
    body: JSON.stringify({ targetUrl, authorization, scope }),
  });
}

/**
 * Submit a finished scan for server-side history/reporting. Best-effort:
 * returns the server scan id, or null when offline. Findings are already
 * redacted client-side (8-char prefix convention); the backend re-redacts
 * before persistence per its own guardrails.
 */
export async function submitScanResult(
  result: ScanResult,
): Promise<string | null> {
  const res = await fetchJson<{ id: string }>('/api/v1/scans', {
    method: 'POST',
    body: JSON.stringify({
      targetUrl: result.targetUrl,
      mode: result.mode ?? 'passive',
      scannedAt: result.scannedAt,
      durationMs: result.durationMs,
      tech: result.tech,
      findings: result.findings,
      chains: result.chains ?? [],
      authorizationId: result.authorization?.id,
      stats: result.activeStats,
    }),
  });
  return res?.id ?? null;
}
