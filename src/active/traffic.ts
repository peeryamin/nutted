/**
 * Network traffic capture for the target tab (active testing).
 *
 * Two sources feed the TrafficLog:
 *  1. The page's own requests, observed passively via webRequest while a
 *     capture session is open for the tab (headers, methods, status codes,
 *     content types — never bodies).
 *  2. The active probe requests sent by ActiveHttpClient, logged manually
 *     (service-worker fetch has no tabId, so webRequest can't attribute it).
 *
 * Privacy: request/response BODIES are never stored. Query/form parameter
 * VALUES are never stored — only parameter names. Response headers are
 * filtered to a small security-relevant allowlist.
 */

export interface TrafficEntry {
  id: number;
  /** 'tab' = page's own traffic, 'probe' = our active requests. */
  source: 'tab' | 'probe';
  method: string;
  url: string;
  host: string;
  path: string;
  /** Query/form parameter NAMES only — values are never recorded. */
  paramNames: string[];
  statusCode?: number;
  contentType?: string;
  /** Security-relevant response headers only (CORS, CSP, auth challenges…). */
  responseHeaders?: Record<string, string>;
  error?: string;
  timeStamp: number;
}

let entrySeq = 0;

/** Response headers worth keeping for analysis (lowercased names). */
const KEPT_RESPONSE_HEADERS = new Set([
  'access-control-allow-origin',
  'access-control-allow-credentials',
  'access-control-allow-methods',
  'access-control-allow-headers',
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'server',
  'x-powered-by',
  'www-authenticate',
  'location',
  'retry-after',
  'x-ratelimit-limit',
  'x-ratelimit-remaining',
  'ratelimit-limit',
  'ratelimit-remaining',
  'allow',
  'set-cookie', // presence only — value replaced with '(present)'
]);

/** Query parameter names that suggest sensitive material (values redacted). */
export const SENSITIVE_PARAM_RE =
  /^(token|access_token|id_token|auth|authorization|session|sessionid|sid|api_key|apikey|secret|password|passwd|pwd|private_key)$/i;

function paramNamesFromUrl(url: string): string[] {
  try {
    return [...new URL(url).searchParams.keys()];
  } catch {
    return [];
  }
}

function splitUrl(url: string): { host: string; path: string } {
  try {
    const u = new URL(url);
    return { host: u.hostname, path: u.pathname };
  } catch {
    return { host: '', path: url };
  }
}

export class TrafficLog {
  private entries: TrafficEntry[] = [];
  private readonly maxEntries: number;

  constructor(maxEntries = 2000) {
    this.maxEntries = maxEntries;
  }

  add(entry: Omit<TrafficEntry, 'id' | 'timeStamp'> & { timeStamp?: number }): TrafficEntry {
    entrySeq++;
    const full: TrafficEntry = {
      id: entrySeq,
      timeStamp: entry.timeStamp ?? Date.now(),
      ...entry,
    } as TrafficEntry;
    // Re-apply id/timeStamp after spread to keep types honest.
    full.id = entrySeq;
    if (!entry.timeStamp) full.timeStamp = Date.now();
    this.entries.push(full);
    if (this.entries.length > this.maxEntries) {
      this.entries.splice(0, this.entries.length - this.maxEntries);
    }
    return full;
  }

  all(): TrafficEntry[] {
    return [...this.entries];
  }

  probes(): TrafficEntry[] {
    return this.entries.filter((e) => e.source === 'probe');
  }

  tabTraffic(): TrafficEntry[] {
    return this.entries.filter((e) => e.source === 'tab');
  }

  clear(): void {
    this.entries = [];
  }
}

/**
 * Tab capture sessions. Listeners are registered once per service-worker
 * lifetime and filter on the open session set, so start/stop is cheap.
 */
const captureTabs = new Set<number>();
const tabLogs = new Map<number, TrafficEntry[]>();
const MAX_TAB_ENTRIES = 800;

function pendingBodyParamNames(
  details: chrome.webRequest.OnBeforeRequestDetails,
): string[] {
  const names = new Set<string>();
  const body = details.requestBody;
  if (!body) return [];
  if (body.formData) {
    for (const k of Object.keys(body.formData)) names.add(k);
  }
  // raw bodies are never inspected — values could be credentials.
  return [...names];
}

function keepResponseHeaders(
  headers: chrome.webRequest.HttpHeader[] | undefined,
): Record<string, string> | undefined {
  if (!headers) return undefined;
  const out: Record<string, string> = {};
  for (const h of headers) {
    const name = (h.name ?? '').toLowerCase();
    if (!name || !KEPT_RESPONSE_HEADERS.has(name)) continue;
    out[name] = name === 'set-cookie' ? '(present)' : (h.value ?? '');
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function recordTabRequest(
  details: chrome.webRequest.OnBeforeRequestDetails,
): undefined {
  if (!captureTabs.has(details.tabId)) return;
  const { host, path } = splitUrl(details.url);
  const paramNames = [
    ...new Set([...paramNamesFromUrl(details.url), ...pendingBodyParamNames(details)]),
  ];
  const list = tabLogs.get(details.tabId) ?? [];
  list.push({
    id: ++entrySeq,
    source: 'tab',
    method: details.method,
    url: details.url.length > 600 ? details.url.slice(0, 600) : details.url,
    host,
    path,
    paramNames,
    timeStamp: details.timeStamp,
  });
  if (list.length > MAX_TAB_ENTRIES) list.splice(0, list.length - MAX_TAB_ENTRIES);
  tabLogs.set(details.tabId, list);
}

function recordTabResponse(
  details: chrome.webRequest.OnHeadersReceivedDetails,
): undefined {
  if (!captureTabs.has(details.tabId)) return;
  const list = tabLogs.get(details.tabId);
  if (!list) return;
  // Attach to the most recent matching request.
  for (let i = list.length - 1; i >= 0; i--) {
    const e = list[i];
    if (e.url === details.url && e.method === details.method && e.statusCode === undefined && !e.error) {
      e.statusCode = details.statusCode;
      e.responseHeaders = keepResponseHeaders(details.responseHeaders);
      const ct = (details.responseHeaders ?? []).find(
        (h) => h.name?.toLowerCase() === 'content-type',
      )?.value;
      if (ct) e.contentType = ct.split(';')[0].trim().toLowerCase();
      break;
    }
  }
}

function recordTabError(
  details: chrome.webRequest.OnErrorOccurredDetails,
): undefined {
  if (!captureTabs.has(details.tabId)) return;
  const list = tabLogs.get(details.tabId);
  if (!list) return;
  for (let i = list.length - 1; i >= 0; i--) {
    const e = list[i];
    if (e.url === details.url && e.method === details.method && e.statusCode === undefined && !e.error) {
      e.error = details.error;
      break;
    }
  }
}

/** Latest observed main-frame response headers per tab (passive). */
const mainFrameHeaders = new Map<number, Record<string, string>>();

export function recordMainFrameHeaders(
  tabId: number,
  headers: Record<string, string>,
): void {
  mainFrameHeaders.set(tabId, headers);
}

export function getMainFrameHeaders(tabId: number): Record<string, string> | undefined {
  return mainFrameHeaders.get(tabId);
}

let listenersRegistered = false;

/** Idempotent: safe to call from background startup. */
export function ensureTrafficListeners(): void {
  if (listenersRegistered) return;
  listenersRegistered = true;
  chrome.webRequest.onBeforeRequest.addListener(
    recordTabRequest,
    { urls: ['<all_urls>'] },
    ['requestBody'],
  );
  chrome.webRequest.onHeadersReceived.addListener(
    recordTabResponse,
    { urls: ['<all_urls>'] },
    ['responseHeaders'],
  );
  chrome.webRequest.onErrorOccurred.addListener(recordTabError, {
    urls: ['<all_urls>'],
  });
  chrome.tabs.onRemoved.addListener((tabId) => {
    captureTabs.delete(tabId);
    tabLogs.delete(tabId);
    mainFrameHeaders.delete(tabId);
  });
}

export function startTabCapture(tabId: number): void {
  ensureTrafficListeners();
  captureTabs.add(tabId);
  tabLogs.set(tabId, []);
}

export function stopTabCapture(tabId: number): TrafficEntry[] {
  captureTabs.delete(tabId);
  const entries = tabLogs.get(tabId) ?? [];
  tabLogs.delete(tabId);
  return entries;
}

/** Merge a finished tab capture into the scan's log. */
export function mergeTabEntries(log: TrafficLog, entries: TrafficEntry[]): void {
  for (const e of entries) log.add(e);
}
