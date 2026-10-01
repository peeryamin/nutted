/**
 * Active scan orchestrator (Phase 2).
 *
 * Pipeline:
 *   authorization check → scope check → DOM collection → tab traffic capture
 *   → baseline GET → API discovery → network analysis → CORS tests
 *   → GraphQL probing → XSS tests → IDOR checks → auth checks
 *   → trap scoring → attack-chain building → (best-effort) backend AI
 *     deepening → report assembly
 *
 * Invariants:
 *  - No active request is sent before a valid authorization record exists.
 *  - Every request passes through ActiveHttpClient (scope + rate limit).
 *  - Failures in one module never abort the others.
 *  - The extension works fully offline; backend calls are best-effort.
 */
import { MAX_ACTIVE_REQUESTS_PER_SCAN } from '../lib/config';
import { getAuthorization, normalizeHost } from '../lib/authorization';
import { RateLimiter } from '../lib/rateLimiter';
import { scoreTrapProbability, type TrapContext } from '../lib/honeypot';
import { buildAttackChains } from '../lib/attackChains';
import {
  checkBackendStatus,
  deepenAttackChains,
  submitScanResult,
} from '../lib/apiClient';
import { checkHeaders } from '../scanners/headerChecker';
import { auditCookies } from '../scanners/cookieAuditor';
import { SEVERITY_ORDER, type Finding, type ScanMessage, type ScanResult } from '../lib/types';
import { TrafficLog, getMainFrameHeaders, mergeTabEntries, startTabCapture, stopTabCapture } from './traffic';
import { ActiveHttpClient } from './httpClient';
import { analyzeTraffic } from './networkAnalyzer';
import { discoverApiEndpoints } from './apiDiscovery';
import { testCors } from './corsTester';
import { probeGraphql } from './graphqlProbe';
import { testXss } from './xssTester';
import { checkIdor } from './idorChecker';
import { checkAuthentication } from './authChecker';
import {
  DeepInspectSession,
  analyzeDeepBodies,
  type CapturedBody,
} from './deepInspect';
import type { DomScanData } from '../lib/types';

export type ProgressFn = (step: string, limiter: RateLimiter) => void;

async function collectDom(tabId: number): Promise<DomScanData> {
  let res: { ok: boolean; data?: DomScanData; error?: string };
  try {
    res = (await chrome.tabs.sendMessage(tabId, {
      type: 'COLLECT_DOM',
    } satisfies ScanMessage)) as typeof res;
  } catch {
    throw new Error(
      'Could not reach the page. Reload the tab and run the active scan again.',
    );
  }
  if (!res?.ok || !res.data) {
    throw new Error(res?.error ?? 'The page did not return scan data.');
  }
  return res.data;
}

function sameOriginScripts(externalScripts: string[], pageUrl: string): string[] {
  const pageOrigin = new URL(pageUrl).origin;
  return externalScripts.filter((s) => {
    try {
      return new URL(s).origin === pageOrigin;
    } catch {
      return false;
    }
  });
}

export async function runActiveScan(
  tabId: number,
  onProgress: ProgressFn,
  opts?: { deepInspect?: boolean },
): Promise<ScanResult> {
  const started = Date.now();

  const tab = await chrome.tabs.get(tabId);
  const targetUrl = tab.url ?? '';
  if (!/^https?:\/\//i.test(targetUrl)) {
    throw new Error('BugSeek can only actively test regular web pages (http/https).');
  }
  const targetHost = normalizeHost(new URL(targetUrl).hostname);
  const origin = new URL(targetUrl).origin;

  // ---- Gate 1: explicit authorization required. ----
  const authz = await getAuthorization(targetHost);
  if (!authz) {
    throw new Error(
      `Active testing is locked: no authorization record exists for ${targetHost}. ` +
        'Complete the authorization confirmation in the "Active testing" tab first.',
    );
  }

  const limiter = new RateLimiter(authz.rateLimitMs, MAX_ACTIVE_REQUESTS_PER_SCAN);
  const log = new TrafficLog();
  const http = new ActiveHttpClient({
    authz,
    targetUrl,
    limiter,
    log,
  });

  const step = (s: string): void => onProgress(s, limiter);
  const isHttps = targetUrl.toLowerCase().startsWith('https://');

  const findings: Finding[] = [];
  const errors: string[] = [];

  // ---- Deep inspect (opt-in): devtools-level body capture via CDP. ----
  // Attached only after the authorization gate above, on the target tab only.
  let deep: DeepInspectSession | null = null;
  let deepBodies: CapturedBody[] = [];
  if (opts?.deepInspect) {
    step('Attaching devtools-level inspection…');
    try {
      deep = await DeepInspectSession.start(tabId, authz, targetUrl);
    } catch (err) {
      errors.push(
        `Deep inspect unavailable: ${err instanceof Error ? err.message : String(err)} — continuing with standard capture.`,
      );
      deep = null;
    }
  }

  step('Collecting page structure…');
  let dom: DomScanData;
  try {
    dom = await collectDom(tabId);
  } catch (err) {
    // collectDom runs BEFORE the main try/finally below. If it throws, the
    // debugger would otherwise stay attached — detach it here so a DOM
    // failure can never leak a debugging session onto the target tab.
    if (deep) {
      await deep.stop().catch(() => undefined);
      deep = null;
    }
    throw err;
  }

  step('Starting traffic capture…');
  startTabCapture(tabId);

  try {
    // Baseline GET: feeds traffic analysis + gives us the raw HTML.
    step('Establishing baseline…');
    try {
      await http.get(targetUrl);
    } catch (err) {
      errors.push(`baseline request failed: ${err instanceof Error ? err.message : String(err)}`);
    }

    // API discovery (mines JS, traffic, wordlist).
    step('Discovering API endpoints…');
    let apiEndpoints: Awaited<ReturnType<typeof discoverApiEndpoints>>['endpoints'] = [];
    let graphqlCandidates: string[] = [];
    try {
      const scripts = sameOriginScripts(dom.externalScripts, targetUrl);
      const discovered = await discoverApiEndpoints(http, origin, scripts, []);
      apiEndpoints = discovered.endpoints;
      graphqlCandidates = discovered.graphqlCandidates;
      findings.push(...discovered.findings);
    } catch (err) {
      errors.push(`API discovery: ${err instanceof Error ? err.message : String(err)}`);
    }

    // Network traffic analysis (tab traffic so far + probe traffic).
    step('Analyzing network traffic…');
    try {
      const analysis = analyzeTraffic(log.all());
      findings.push(...analysis.findings);
    } catch (err) {
      errors.push(`traffic analysis: ${err instanceof Error ? err.message : String(err)}`);
    }

    // CORS tests.
    step('Testing CORS configuration…');
    try {
      const firstApi = apiEndpoints.find((e) => e.status === 200);
      const extra = firstApi ? [origin + firstApi.path] : [];
      const { findings: corsFindings } = await testCors(http, targetUrl, extra);
      findings.push(...corsFindings);
    } catch (err) {
      errors.push(`CORS tests: ${err instanceof Error ? err.message : String(err)}`);
    }

    // GraphQL probing.
    step('Probing for GraphQL…');
    try {
      const { findings: gqlFindings } = await probeGraphql(http, origin, graphqlCandidates);
      findings.push(...gqlFindings);
    } catch (err) {
      errors.push(`GraphQL probing: ${err instanceof Error ? err.message : String(err)}`);
    }

    // XSS tests (context-aware, DOM-observed confirmation).
    step('Testing for reflected XSS (context-aware)…');
    try {
      const { findings: xssFindings } = await testXss(http, tabId, targetUrl, dom);
      findings.push(...xssFindings);
    } catch (err) {
      errors.push(`XSS tests: ${err instanceof Error ? err.message : String(err)}`);
    }

    // IDOR checks.
    step('Checking for predictable resource IDs…');
    try {
      const { findings: idorFindings } = await checkIdor(
        http,
        origin,
        apiEndpoints,
        log.all(),
      );
      findings.push(...idorFindings);
    } catch (err) {
      errors.push(`IDOR checks: ${err instanceof Error ? err.message : String(err)}`);
    }

    // Auth checks (probing tier gated inside the module).
    step('Checking authentication posture…');
    try {
      const { findings: authFindings } = await checkAuthentication(
        http,
        authz,
        targetUrl,
        dom,
      );
      findings.push(...authFindings);
    } catch (err) {
      errors.push(`auth checks: ${err instanceof Error ? err.message : String(err)}`);
    }
  } finally {
    const tabEntries = stopTabCapture(tabId);
    mergeTabEntries(log, tabEntries);
    if (deep) {
      try {
        const res = await deep.stop();
        deepBodies = res.bodies;
        if (deep.detachNote) {
          errors.push(
            `Deep inspect note: the debugger detached mid-scan (${deep.detachNote}); body capture may be partial.`,
          );
        }
      } catch (err) {
        errors.push(
          `Deep inspect stop failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
  }

  // ---- Deep body analysis: secrets, debug output, IDOR follow-up. ----
  if (deepBodies.length > 0) {
    step('Analyzing captured response bodies…');
    try {
      const deepAnalysis = analyzeDeepBodies(deepBodies);
      findings.push(...deepAnalysis.findings);
      if (deepAnalysis.idorEntries.length > 0) {
        const { findings: deepIdor } = await checkIdor(
          http,
          origin,
          [],
          deepAnalysis.idorEntries,
        );
        findings.push(...deepIdor);
      }
    } catch (err) {
      errors.push(
        `deep body analysis: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  // ---- Post-processing: trap scoring (plan §4.5). ----
  // Compute real posture signals from passive observations (header snapshot
  // captured by the background listener + a cookie audit read). These are
  // observational reads, not active probes, and they feed only the trap
  // scorer — they are not added as findings here.
  step('Scoring honeypot/trap probability…');
  let headerPostureGood = true;
  let cookiePostureGood = true;
  try {
    const hdrs = getMainFrameHeaders(tabId);
    if (hdrs) {
      headerPostureGood = !checkHeaders(hdrs, isHttps).some(
        (f) => f.severity === 'high' || f.severity === 'critical',
      );
    }
  } catch {
    /* posture unknown — leave true; inconsistency signal stays quiet */
  }
  try {
    cookiePostureGood = !(await auditCookies(targetUrl)).some(
      (f) => f.severity === 'high' || f.severity === 'critical',
    );
  } catch {
    /* posture unknown */
  }
  const trapCtx: TrapContext = {
    totalFindings: findings.length,
    headerPostureGood,
    cookiePostureGood,
    targetHost,
  };
  for (const f of findings) {
    // Modules already set CVSS; ensure every finding carries a trap score.
    if (f.trapProbability === undefined) {
      const s = scoreTrapProbability(f, trapCtx);
      f.trapProbability = s.probability;
      f.trapSignals = s.signals;
      f.honeypotSuspect = s.suspect;
    }
  }
  // ---- Attack-chain reasoning hooks (plan §4.4). ----
  step('Linking findings into attack chains…');
  const chains = buildAttackChains(findings);

  // ---- Best-effort backend AI deepening (offline-capable). ----
  step('Checking backend for AI deepening…');
  const stats = limiter.getStats();
  let backendReachable = false;
  let backendDeepened = false;
  let deepenedChains = chains;
  try {
    const status = await checkBackendStatus();
    backendReachable = status.reachable;
    if (backendReachable && chains.length > 0) {
      const deepened = await deepenAttackChains(targetUrl, chains, findings);
      if (deepened) {
        deepenedChains = deepened;
        backendDeepened = true;
      }
    }
  } catch {
    /* offline — local results stand alone */
  }

  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );

  const result: ScanResult = {
    targetUrl,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    tech: [],
    findings: sorted,
    mode: 'active',
    chains: deepenedChains,
    authorization: authz,
    activeStats: {
      requestsMade: stats.requestsMade,
      throttledMs: stats.throttledMsTotal,
      maxRequests: stats.maxRequests,
      rateLimitMs: stats.gapMs,
      backendReachable,
      backendDeepened,
    },
  };

  // Best-effort history submission (never fails the scan).
  if (backendReachable) {
    try {
      await submitScanResult(result);
    } catch {
      /* ignore */
    }
  }

  if (errors.length > 0) {
    // Surface module errors as info findings so the user sees partial coverage.
    result.findings.push({
      id: 'active-partial-coverage',
      category: 'network',
      mode: 'active',
      title: `Partial coverage: ${errors.length} module(s) reported errors`,
      description: errors.slice(0, 5).join(' | '),
      severity: 'info',
      confidence: 'high',
      confirmed: true,
      remediation: 'Re-run the active scan; transient network errors usually clear.',
      requestCount: 0,
    });
  }

  return result;
}
