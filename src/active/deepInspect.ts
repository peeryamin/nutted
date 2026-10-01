/**
 * Deep inspect mode — devtools-level traffic visibility for active scans.
 *
 * DevTools itself is only a UI over the Chrome DevTools Protocol (CDP).
 * This module speaks that same protocol via chrome.debugger, giving an
 * active scan everything a human would see with DevTools open: full
 * request/response BODIES for the tab's own traffic (chrome.webRequest
 * only exposes metadata — never bodies), POST payloads, and per-response
 * MIME types.
 *
 * Safety contract:
 *  - Opt-in only. The `debugger` permission is OPTIONAL in the manifest and
 *    is requested at runtime when the user ticks "Deep inspect" — it is
 *    never an install-time permission.
 *  - Attach happens only after a valid authorization record exists, and
 *    only on the single target tab.
 *  - Bodies are captured ONLY for in-scope URLs (scopeCheck), only for
 *    text-ish content types, and capped in count and bytes.
 *  - Captured bodies live in memory for the duration of the scan and are
 *    dropped on detach. Only redacted snippets ever reach findings; raw
 *    bodies are never written to storage or the report.
 *  - The session always detaches: on scan end (finally), on tab close, on
 *    navigation-triggered detach, or when the user opens DevTools.
 *
 * UX notes (surfaced, not hidden): Chrome shows a "…is debugging this
 * browser" infobar while attached, and attach fails while DevTools is
 * already open on the same tab — both produce user-facing messages.
 */
import {
  DEEP_INSPECT_BODY_CONTENT_RE,
  DEEP_INSPECT_MAX_BODIES,
  DEEP_INSPECT_MAX_BODY_BYTES,
  EVIDENCE_MAX_CHARS,
} from '../lib/config';
import { scopeCheck, type AuthorizationRecord } from '../lib/authorization';
import { SECRET_PATTERNS, isPlaceholder, redactSecret } from '../lib/regexes';
import type { Finding } from '../lib/types';
import type { TrafficEntry } from './traffic';

const CDP_VERSION = '1.3';

/** True when the user has granted the optional debugger permission. */
export async function hasDebuggerPermission(): Promise<boolean> {
  try {
    return await chrome.permissions.contains({ permissions: ['debugger'] });
  } catch {
    return false;
  }
}

/**
 * Request the optional debugger permission.
 * MUST be called synchronously inside a user gesture (popup click).
 */
export async function requestDebuggerPermission(): Promise<boolean> {
  try {
    return await chrome.permissions.request({ permissions: ['debugger'] });
  } catch {
    return false;
  }
}

export interface CapturedBody {
  url: string;
  method: string;
  status: number;
  mimeType: string;
  /** Truncated body text (in-memory only, dropped on detach). */
  text: string;
  truncated: boolean;
}

interface ResponseMeta {
  url: string;
  method: string;
  status: number;
  mimeType: string;
}

/** Numeric path segment, e.g. /users/12345 — candidate object reference. */
const NUMERIC_SEGMENT_RE = /\/(\d{1,10})(?=\/|$)/;
/** Query params that usually reference objects. */
const ID_PARAM_RE = /[?&](id|user_id|userid|account_id|order_id|customer_id|doc_id|file_id|record_id)=/i;
/** Verbose error / debug output worth flagging as information disclosure. */
const DEBUG_INFO_RE =
  /(stack trace|traceback \(most recent call|at [A-Za-z0-9_$]+\s*\([^)]*:\d+:\d+\)|SQL syntax[^;]{0,80}MySQL|ORA-\d{5}|Exception in thread|Warning:[^\n]{0,80}\.php on line \d+|DEBUG\s*=\s*True)/i;

let findingSeq = 0;
let entrySeq = 1000000; // private namespace; deep entries never enter the TrafficLog

function decodeBase64(b64: string): string {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function toTrafficEntry(
  url: string,
  method: string,
  status?: number,
  contentType?: string,
): TrafficEntry | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  entrySeq++;
  return {
    id: entrySeq,
    source: 'tab',
    method,
    url,
    host: u.hostname,
    path: u.pathname,
    paramNames: [...u.searchParams.keys()],
    statusCode: status,
    contentType,
    timeStamp: Date.now(),
  };
}

export class DeepInspectSession {
  private readonly tabId: number;
  private readonly authz: AuthorizationRecord;
  private readonly targetUrl: string;
  private readonly pendingMethods = new Map<string, string>();
  private readonly responseMeta = new Map<string, ResponseMeta>();
  private readonly bodies: CapturedBody[] = [];
  private attached = false;
  private detachReason: string | null = null;

  private constructor(
    tabId: number,
    authz: AuthorizationRecord,
    targetUrl: string,
  ) {
    this.tabId = tabId;
    this.authz = authz;
    this.targetUrl = targetUrl;
  }

  /** Attach to the tab and enable CDP Network capture. Throws on failure. */
  static async start(
    tabId: number,
    authz: AuthorizationRecord,
    targetUrl: string,
  ): Promise<DeepInspectSession> {
    if (!(await hasDebuggerPermission())) {
      throw new Error(
        'Deep inspect needs the debugger permission. Grant it when prompted and run the scan again.',
      );
    }
    const session = new DeepInspectSession(tabId, authz, targetUrl);
    try {
      await session.attach();
    } catch (err) {
      // Never leak a half-attached debugger (stuck infobar); clean up first.
      await session.stop();
      throw err;
    }
    return session;
  }

  /** Why the debugger detached mid-scan, if it did (e.g. user opened DevTools). */
  get detachNote(): string | null {
    return this.detachReason;
  }

  private get debuggee(): chrome.debugger.Debuggee {
    return { tabId: this.tabId };
  }

  private async attach(): Promise<void> {
    try {
      await chrome.debugger.attach(this.debuggee, CDP_VERSION);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (/another debugger/i.test(msg)) {
        throw new Error(
          'Could not attach: Chrome DevTools is already open on this tab. Close DevTools and run the scan again.',
        );
      }
      throw new Error(`Could not attach the debugger: ${msg}`);
    }
    this.attached = true;
    chrome.debugger.onEvent.addListener(this.onEvent);
    chrome.debugger.onDetach.addListener(this.onDetach);
    chrome.tabs.onRemoved.addListener(this.onTabRemoved);
    await chrome.debugger.sendCommand(this.debuggee, 'Network.enable');
  }

  /**
   * Detach and hand back what was captured. Safe to call multiple times and
   * after the tab is gone.
   */
  async stop(): Promise<{ bodies: CapturedBody[] }> {
    chrome.debugger.onEvent.removeListener(this.onEvent);
    chrome.debugger.onDetach.removeListener(this.onDetach);
    chrome.tabs.onRemoved.removeListener(this.onTabRemoved);
    if (this.attached) {
      this.attached = false;
      try {
        await chrome.debugger.sendCommand(this.debuggee, 'Network.disable');
      } catch {
        /* tab may be gone; ignore */
      }
      try {
        await chrome.debugger.detach(this.debuggee);
      } catch {
        /* already detached; ignore */
      }
    }
    const bodies = this.bodies.splice(0, this.bodies.length);
    this.pendingMethods.clear();
    this.responseMeta.clear();
    return { bodies };
  }

  private onEvent = (
    source: chrome.debugger.Debuggee,
    method: string,
    params?: object,
  ): void => {
    if (source.tabId !== this.tabId || !this.attached) return;
    try {
      if (method === 'Network.requestWillBeSent') {
        const p = params as {
          requestId: string;
          request: { url: string; method: string };
        };
        this.pendingMethods.set(p.requestId, p.request.method);
      } else if (method === 'Network.responseReceived') {
        const p = params as {
          requestId: string;
          response: { url: string; status: number; mimeType: string };
        };
        const method = this.pendingMethods.get(p.requestId) ?? 'GET';
        this.pendingMethods.delete(p.requestId);
        this.responseMeta.set(p.requestId, {
          url: p.response.url,
          method,
          status: p.response.status,
          mimeType: p.response.mimeType,
        });
      } else if (method === 'Network.loadingFinished') {
        const p = params as { requestId: string };
        void this.captureBody(p.requestId);
      }
    } catch {
      /* Capture must never break the scan. */
    }
  };

  private onDetach = (
    source: chrome.debugger.Debuggee,
    reason: string,
  ): void => {
    if (source.tabId !== this.tabId) return;
    this.attached = false;
    this.detachReason = reason;
  };

  private onTabRemoved = (tabId: number): void => {
    if (tabId === this.tabId) this.attached = false; // Chrome detaches for us
  };

  private async captureBody(requestId: string): Promise<void> {
    const meta = this.responseMeta.get(requestId);
    this.responseMeta.delete(requestId);
    if (!meta || this.bodies.length >= DEEP_INSPECT_MAX_BODIES) return;
    if (!/^https?:/i.test(meta.url)) return;
    // Out-of-scope traffic is not even looked at.
    if (scopeCheck(meta.url, this.authz, this.targetUrl) !== null) return;
    if (!DEEP_INSPECT_BODY_CONTENT_RE.test(meta.mimeType)) return;

    let text: string;
    try {
      const res = (await chrome.debugger.sendCommand(
        this.debuggee,
        'Network.getResponseBody',
        { requestId },
      )) as { body: string; base64Encoded: boolean };
      text = res.base64Encoded ? decodeBase64(res.body) : res.body;
    } catch {
      return; // e.g. no body, already evicted
    }

    let truncated = false;
    if (text.length > DEEP_INSPECT_MAX_BODY_BYTES) {
      text = text.slice(0, DEEP_INSPECT_MAX_BODY_BYTES);
      truncated = true;
    }
    this.bodies.push({ ...meta, text, truncated });
  }
}

export interface DeepAnalysis {
  findings: Finding[];
  /** In-scope URLs with ID-like references, as traffic entries for IDOR re-check. */
  idorEntries: TrafficEntry[];
  bodiesExamined: number;
}

/**
 * Analyze captured bodies: secret patterns, verbose debug/error output,
 * and ID-like references for a follow-up IDOR pass. All evidence is
 * redacted; raw bodies are never returned.
 */
export function analyzeDeepBodies(bodies: CapturedBody[]): DeepAnalysis {
  const findings: Finding[] = [];
  const idorEntries: TrafficEntry[] = [];
  const seenUrls = new Set<string>();
  const seenSecrets = new Set<string>();

  for (const body of bodies) {
    const location = `${body.method} ${body.url}`;

    // 1. Secrets exposed in response bodies.
    for (const pattern of SECRET_PATTERNS) {
      const flags = pattern.regex.flags.includes('g')
        ? pattern.regex.flags
        : pattern.regex.flags + 'g';
      const re = new RegExp(pattern.regex.source, flags);
      let match: RegExpExecArray | null;
      let reported = 0;
      while (
        (match = re.exec(body.text)) !== null &&
        reported < 3
      ) {
        if (match.index === re.lastIndex) re.lastIndex++;
        const matched = match[0];
        if (isPlaceholder(matched)) continue;
        const dedupeKey = `${pattern.id}:${redactSecret(matched)}`;
        if (seenSecrets.has(dedupeKey)) continue;
        seenSecrets.add(dedupeKey);
        reported++;
        findings.push({
          id: `deepsecret-${pattern.id}-${findingSeq++}`,
          category: 'secrets',
          title: `${pattern.name} exposed in HTTP response body`,
          description: `${pattern.description} Found in a live response body via Deep inspect (not in static scripts).`,
          severity: pattern.severity,
          confidence:
            pattern.severity === 'critical' || pattern.severity === 'high'
              ? 'high'
              : 'medium',
          location,
          evidence: redactSecret(matched).slice(0, EVIDENCE_MAX_CHARS),
          remediation: pattern.remediation,
          mode: 'active',
          tags: ['deep-inspect'],
        });
      }
    }

    // 2. Verbose debug / error output (information disclosure).
    const debugHit = DEBUG_INFO_RE.exec(body.text);
    if (debugHit) {
      findings.push({
        id: `deepdebug-${findingSeq++}`,
        category: 'network',
        title: 'Verbose debug/error output in response body',
        description:
          'A response body contains stack traces, SQL errors, or debug output that discloses internals (paths, queries, framework details).',
        severity: 'medium',
        confidence: 'high',
        location,
        evidence: redactSecret(debugHit[0]).slice(0, EVIDENCE_MAX_CHARS),
        remediation:
          'Disable debug output in production; return generic error pages and log details server-side.',
        mode: 'active',
        tags: ['deep-inspect', 'info-disclosure'],
      });
    }

    // 3. ID-like references for a follow-up IDOR pass.
    if (
      !seenUrls.has(body.url) &&
      (NUMERIC_SEGMENT_RE.test(body.url) || ID_PARAM_RE.test(body.url))
    ) {
      seenUrls.add(body.url);
      const entry = toTrafficEntry(body.url, body.method, body.status, body.mimeType);
      if (entry) idorEntries.push(entry);
    }
  }

  return { findings, idorEntries, bodiesExamined: bodies.length };
}
