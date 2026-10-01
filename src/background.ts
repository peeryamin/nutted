/**
 * BugSeek AI background service worker (Manifest V3).
 *
 * Responsibilities:
 *  - Capture main-frame response headers via webRequest (passive).
 *  - Orchestrate a scan when the popup requests one:
 *      content script DOM data -> cookie audit -> secret scan of
 *      inline + same-origin external JS -> header checks -> tech
 *      fingerprinting -> aggregated, severity-sorted findings.
 *
 * Phase 1 performs NO active testing: no payload injection, no fuzzing,
 * no authentication attempts. The only network reads are the page's own
 * public resources.
 */
import type { DomScanData, Finding, ScanMessage, ScanResult } from './lib/types';
import { SEVERITY_ORDER } from './lib/types';
import { scanSecrets, type ScriptSource } from './scanners/secretScanner';
import { auditCookies } from './scanners/cookieAuditor';
import { checkHeaders } from './scanners/headerChecker';
import { analyzeDom } from './scanners/domAnalyzer';
import { fingerprintTech } from './lib/fingerprint';
import { STORAGE_KEYS } from './lib/config';
import { runActiveScan } from './active/activeRunner';
import type { RateLimiter } from './lib/rateLimiter';
import { getMainFrameHeaders, recordMainFrameHeaders } from './active/traffic';

const MAX_EXTERNAL_SCRIPTS = 12;
const MAX_SCRIPT_BYTES = 1_500_000;
const FETCH_TIMEOUT_MS = 8000;

/** Latest observed main-frame response headers per tab (passive). */
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const headers: Record<string, string> = {};
    for (const h of details.responseHeaders ?? []) {
      if (h.name) headers[h.name.toLowerCase()] = h.value ?? '';
    }
    recordMainFrameHeaders(details.tabId, headers);
    return undefined;
  },
  { urls: ['<all_urls>'], types: ['main_frame'] },
  ['responseHeaders'],
);

chrome.tabs.onRemoved.addListener((tabId) => {
  // Tab-scoped traffic state is cleaned up inside traffic.ts.
});

chrome.runtime.onMessage.addListener((msg: ScanMessage) => {
  if (msg.type === 'RUN_SCAN') {
    // Fire-and-forget: progress + result are pushed back as messages.
    void runScan(msg.tabId);
  } else if (msg.type === 'RUN_ACTIVE_SCAN') {
    // Active testing: gated on the authorization record (checked in the runner).
    void runActive(msg.tabId, msg.deepInspect ?? false);
  }
  return false;
});

function sendProgress(step: string): void {
  chrome.runtime
    .sendMessage({ type: 'SCAN_PROGRESS', step } satisfies ScanMessage)
    .catch(() => {
      /* popup may be closed; ignore */
    });
}

async function runScan(tabId: number): Promise<void> {
  const started = Date.now();
  try {
    const tab = await chrome.tabs.get(tabId);
    const url = tab.url ?? '';
    if (!/^https?:\/\//i.test(url)) {
      throw new Error(
        'BugSeek can only scan regular web pages (http/https). Open a website and try again.',
      );
    }

    sendProgress('Collecting page structure…');
    const dom = await collectDom(tabId);

    sendProgress('Auditing cookies…');
    const cookieFindings = await auditCookies(url);

    sendProgress('Scanning JavaScript for exposed secrets…');
    const externalCode = await fetchSameOriginScripts(dom.externalScripts, url);
    const scriptSources: ScriptSource[] = [
      ...dom.inlineScripts.map((code, i) => ({
        label: `inline <script> #${i + 1} on ${shortHost(url)}`,
        code,
      })),
      ...externalCode,
    ];
    const secretFindings: Finding[] = scanSecrets(scriptSources);

    sendProgress('Checking security headers…');
    const headers = getMainFrameHeaders(tabId) ?? (await fetchHeadersFallback(url));
    const headerFindings = checkHeaders(headers, url.startsWith('https://'));

    sendProgress('Fingerprinting technology…');
    const tech = fingerprintTech(headers, dom);

    sendProgress('Analyzing page structure…');
    const domFindings = analyzeDom(dom);

    const findings = [
      ...secretFindings,
      ...cookieFindings,
      ...headerFindings,
      ...domFindings,
    ].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

    const result: ScanResult = {
      targetUrl: url,
      scannedAt: new Date().toISOString(),
      durationMs: Date.now() - started,
      tech,
      findings,
    };

    await chrome.storage.local.set({ [`scan:${tabId}`]: result, lastResult: result });
    await chrome.runtime
      .sendMessage({ type: 'SCAN_DONE', result } satisfies ScanMessage)
      .catch(() => {
        /* popup may be closed; result is in storage */
      });
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    await chrome.runtime
      .sendMessage({ type: 'SCAN_ERROR', error } satisfies ScanMessage)
      .catch(() => {
        /* popup may be closed */
      });
  }
}

async function collectDom(tabId: number): Promise<DomScanData> {
  let res: { ok: boolean; data?: DomScanData; error?: string };
  try {
    res = (await chrome.tabs.sendMessage(tabId, {
      type: 'COLLECT_DOM',
    } satisfies ScanMessage)) as typeof res;
  } catch {
    throw new Error(
      'Could not reach the page. Reload the tab (the extension must be installed before the page loads) and scan again.',
    );
  }
  if (!res?.ok || !res.data) {
    throw new Error(res?.error ?? 'The page did not return scan data.');
  }
  return res.data;
}

/**
 * Fetch first-party (same-origin) external scripts for secret scanning.
 * Third-party CDN bundles are skipped in Phase 1 to keep scans fast and
 * focused on code the site owner controls.
 */
async function fetchSameOriginScripts(
  srcs: string[],
  pageUrl: string,
): Promise<ScriptSource[]> {
  const pageOrigin = new URL(pageUrl).origin;
  const targets = srcs
    .filter((s) => {
      try {
        return new URL(s).origin === pageOrigin;
      } catch {
        return false;
      }
    })
    .slice(0, MAX_EXTERNAL_SCRIPTS);

  const results: ScriptSource[] = [];
  await Promise.all(
    targets.map(async (src) => {
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
        const res = await fetch(src, { signal: ctrl.signal });
        clearTimeout(timer);
        if (!res.ok) return;
        const text = await res.text();
        if (!text || text.length > MAX_SCRIPT_BYTES) return;
        results.push({ label: src, code: text });
      } catch {
        /* skip unreachable scripts */
      }
    }),
  );
  return results;
}

/** Fallback: read headers with a HEAD request if the navigation predates the extension. */
async function fetchHeadersFallback(url: string): Promise<Record<string, string>> {
  const headers: Record<string, string> = {};
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    const res = await fetch(url, { method: 'HEAD', signal: ctrl.signal });
    clearTimeout(timer);
    res.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
  } catch {
    /* leave empty; checkHeaders() reports the gap */
  }
  return headers;
}

function shortHost(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

/**
 * Active testing scan (Phase 2). Authorization + scope are enforced inside
 * runActiveScan; every request is rate-limited via ActiveHttpClient.
 */
async function runActive(tabId: number, deepInspect: boolean): Promise<void> {
  try {
    const result = await runActiveScan(
      tabId,
      (step, limiter: RateLimiter) => {
      const stats = limiter.getStats();
      chrome.runtime
        .sendMessage({
          type: 'ACTIVE_PROGRESS',
          step,
          requestsMade: stats.requestsMade,
          rateLimitMs: stats.gapMs,
          nextRequestInMs: stats.nextRequestInMs,
        } satisfies ScanMessage)
        .catch(() => {
          /* popup may be closed; ignore */
        });
      },
      { deepInspect },
    );

    await chrome.storage.local.set({
      [`${STORAGE_KEYS.activeScanPrefix}${tabId}`]: result,
      [STORAGE_KEYS.lastActiveResult]: result,
    });
    await chrome.runtime
      .sendMessage({ type: 'ACTIVE_DONE', result } satisfies ScanMessage)
      .catch(() => {
        /* popup may be closed; result is in storage */
      });
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    await chrome.runtime
      .sendMessage({ type: 'ACTIVE_ERROR', error } satisfies ScanMessage)
      .catch(() => {
        /* popup may be closed */
      });
  }
}
