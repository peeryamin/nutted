/**
 * Context-aware XSS testing (active testing).
 *
 * Method (NOT blind fuzzing):
 *  1. Take reflection points: the tab URL's query parameters and GET forms
 *     from the DOM collection.
 *  2. Send a unique canary per parameter; find where it lands in the raw
 *     HTML and classify the sink context (HTML text, double/single-quoted
 *     attribute, JS string, HTML comment).
 *  3. Send ONE context-adapted payload carrying a marker, then confirm via
 *     DOM observation: the content script loads the probe URL in a hidden
 *     same-origin iframe and reports whether the marker reached
 *     document.title (i.e. the payload executed).
 *  4. Reflected-but-not-executed inputs become low-severity REVIEW HINTS,
 *     never vulnerabilities.
 *
 * Payloads are non-destructive marker assignments (document.title) — no
 * alert(), no exfiltration, no persistence.
 */
import { scoreFinding } from '../lib/cvss';
import type { DomScanData, Finding, XssProbeResponse } from '../lib/types';
import type { ActiveHttpClient } from './httpClient';
import { redactedSnippet } from './httpClient';

let findingSeq = 0;
const MAX_PARAMS = 6;

function nextId(): string {
  findingSeq++;
  return `xss-${findingSeq}`;
}

function cvssFields(presetKey: string): Pick<
  Finding, 'cvssScore' | 'cvssVector' | 'cvssJustification' | 'references'
> {
  const s = scoreFinding(presetKey);
  return {
    cvssScore: s.score,
    cvssVector: s.vector,
    cvssJustification: s.justification,
    references: s.references,
  };
}

type SinkContext = 'html' | 'attr-double' | 'attr-single' | 'js-double' | 'js-single' | 'comment' | 'unknown';

const CONTEXT_LABEL: Record<SinkContext, string> = {
  html: 'HTML text node',
  'attr-double': 'double-quoted attribute value',
  'attr-single': 'single-quoted attribute value',
  'js-double': 'double-quoted JavaScript string',
  'js-single': 'single-quoted JavaScript string',
  comment: 'HTML comment',
  unknown: 'unclassified location',
};

function randToken(prefix: string): string {
  return `${prefix}${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * Classify where a canary string lands in raw HTML. Checks each occurrence
 * and returns the most specific context found.
 */
export function classifyReflection(html: string, canary: string): SinkContext {
  let idx = html.indexOf(canary);
  if (idx === -1) return 'unknown';
  let best: SinkContext = 'unknown';

  while (idx !== -1) {
    const before = html.slice(Math.max(0, idx - 4000), idx);
    const ctx = classifySingle(before, idx);
    // Prefer the most specific classification.
    const rank: Record<SinkContext, number> = {
      unknown: 0, html: 1, comment: 2, 'attr-single': 3, 'attr-double': 3,
      'js-single': 4, 'js-double': 4,
    };
    if (rank[ctx] > rank[best]) best = ctx;
    idx = html.indexOf(canary, idx + canary.length);
    if (best === 'js-double' || best === 'js-single') break;
  }
  return best;
}

function classifySingle(before: string, _idx: number): SinkContext {
  // Inside <script> (not src)? Look at the nearest open tag before the canary.
  const lastScriptOpen = before.lastIndexOf('<script');
  const lastScriptClose = before.lastIndexOf('</script>');
  if (lastScriptOpen > lastScriptClose) {
    const tagChunk = before.slice(lastScriptOpen, lastScriptOpen + 300);
    if (!/\bsrc\s*=/.test(tagChunk)) {
      // Inside script body: which quote are we in?
      const code = before.slice(lastScriptOpen);
      const dbl = (code.match(/"/g) ?? []).length;
      const sgl = (code.match(/'/g) ?? []).length;
      if (dbl % 2 === 1) return 'js-double';
      if (sgl % 2 === 1) return 'js-single';
      return 'html'; // script body but not in a string (rare)
    }
  }

  // Inside an HTML comment?
  const lastCommentOpen = before.lastIndexOf('<!--');
  const lastCommentClose = before.lastIndexOf('-->');
  if (lastCommentOpen > lastCommentClose) return 'comment';

  // Inside a tag's attribute? Find the nearest '<' not closed by '>'.
  const lastLt = before.lastIndexOf('<');
  const lastGt = before.lastIndexOf('>');
  if (lastLt > lastGt) {
    const tagSoFar = before.slice(lastLt);
    // Count unescaped quotes since the tag opened.
    const dbl = (tagSoFar.match(/"/g) ?? []).length;
    const sgl = (tagSoFar.match(/'/g) ?? []).length;
    if (dbl % 2 === 1) return 'attr-double';
    if (sgl % 2 === 1) return 'attr-single';
    return 'html';
  }

  return 'html';
}

/** One context-adapted, non-destructive marker payload per sink context. */
function payloadFor(context: SinkContext, marker: string): string {
  const set = `document.title='${marker}'`;
  switch (context) {
    case 'html':
      return `<svg/onload=${set}>`;
    case 'attr-double':
      return `"autofocus/onfocus=${set} x="`;
    case 'attr-single':
      return `'autofocus/onfocus=${set} x='`;
    case 'js-double':
      return `";${set};//`;
    case 'js-single':
      return `';${set};//`;
    case 'comment':
      return `--><svg/onload=${set}>`;
    default:
      return `<svg/onload=${set}>`;
  }
}

export interface XssTestResult {
  findings: Finding[];
}

/**
 * Ask the content script to load `url` in a hidden iframe and report
 * whether `marker` reached document.title (payload executed).
 */
async function confirmViaDom(tabId: number, url: string, marker: string): Promise<boolean> {
  try {
    const res = (await chrome.tabs.sendMessage(tabId, {
      type: 'XSS_PROBE',
      url,
      marker,
    })) as XssProbeResponse | undefined;
    return !!res?.ok && !!res.executed;
  } catch {
    return false;
  }
}

interface ReflectionPoint {
  /** URL with the canary injected. */
  probeUrl: string;
  param: string;
  source: string; // 'query-param' | 'get-form'
}

function reflectionPoints(tabUrl: string, dom: DomScanData): ReflectionPoint[] {
  const points: ReflectionPoint[] = [];
  try {
    const u = new URL(tabUrl);
    for (const [name] of u.searchParams) {
      if (points.length >= MAX_PARAMS) break;
      const canary = randToken('bsxq');
      const probe = new URL(u.toString());
      probe.searchParams.set(name, canary);
      points.push({ probeUrl: probe.toString(), param: name, source: 'query-param' });
    }
  } catch {
    /* ignore malformed URL */
  }
  // GET forms: reflect through their action URL.
  for (const form of dom.forms) {
    if (points.length >= MAX_PARAMS) break;
    if (form.method !== 'get' || form.inputCount === 0 || form.hasPassword) continue;
    try {
      const action = new URL(form.action || tabUrl, tabUrl);
      const canary = randToken('bsxq');
      action.searchParams.set('bugseek_probe', canary);
      points.push({
        probeUrl: action.toString(),
        param: 'bugseek_probe',
        source: `get-form → ${action.pathname}`,
      });
    } catch {
      /* ignore */
    }
  }
  return points;
}

export async function testXss(
  http: ActiveHttpClient,
  tabId: number,
  tabUrl: string,
  dom: DomScanData,
): Promise<XssTestResult> {
  const findings: Finding[] = [];
  const before = http.limiter.getStats().requestsMade;
  const points = reflectionPoints(tabUrl, dom);

  for (const point of points) {
    let canaryBody = '';
    try {
      const res = await http.get(point.probeUrl);
      if (res.status !== 200 || !res.contentType.includes('html')) continue;
      canaryBody = res.bodyText;
    } catch {
      continue;
    }

    const canary = new URL(point.probeUrl).searchParams.get(point.param) ?? '';
    if (!canary || !canaryBody.includes(canary)) continue;

    const context = classifyReflection(canaryBody, canary);
    const marker = randToken('BSXSS');
    const payload = payloadFor(context, marker);

    let executed = false;
    try {
      const probe = new URL(point.probeUrl);
      probe.searchParams.set(point.param, payload);
      const probeRes = await http.get(probe.toString());
      if (probeRes.status === 200 && probeRes.bodyText.includes(payload.slice(0, 20))) {
        executed = await confirmViaDom(tabId, probe.toString(), marker);
      }
    } catch {
      executed = false;
    }

    const location = `${point.source} parameter "${point.param}" (${CONTEXT_LABEL[context]})`;

    if (executed) {
      findings.push({
        id: nextId(),
        category: 'xss',
        mode: 'active',
        tags: ['xss-confirmed', 'xss'],
        title: `Confirmed reflected XSS in ${point.source} parameter "${point.param}"`,
        description:
          `A context-adapted payload for ${CONTEXT_LABEL[context]} executed: the marker reached document.title ` +
          'in a hidden same-origin iframe (DOM observation, not blind inference). This is a confirmed reflected XSS sink.',
        severity: 'high',
        confidence: 'high',
        confirmed: true,
        location,
        evidence: redactedSnippet(`payload context: ${CONTEXT_LABEL[context]}\nmarker observed in document.title`, 300),
        remediation:
          'Encode all user input for its output context (HTML, attribute, JavaScript). Prefer contextual auto-escaping frameworks, ' +
          'deploy a strict Content-Security-Policy without unsafe-inline, and validate input on arrival.',
        ...cvssFields('xss:confirmed'),
        reproSteps: [
          `Request ${point.probeUrl} with the parameter set to the ${CONTEXT_LABEL[context]} payload.`,
          'Load the resulting URL in the application origin.',
          'Observe the marker in document.title — the payload executed.',
        ],
      });
    } else {
      findings.push({
        id: nextId(),
        category: 'xss',
        mode: 'active',
        tags: ['xss-hint'],
        title: `Reflected input without confirmed execution — review hint (${point.param})`,
        description:
          `The value of ${point.source} parameter "${point.param}" is reflected in the response (${CONTEXT_LABEL[context]}) ` +
          'but the marker payload did NOT execute under DOM observation (likely encoded, CSP-blocked, or context-neutralized). ' +
          'This is a REVIEW HINT, not a vulnerability — verify manually.',
        severity: 'low',
        confidence: 'low',
        confirmed: false,
        location,
        evidence: redactedSnippet(`reflected in: ${CONTEXT_LABEL[context]}`, 200),
        remediation:
          'Manually verify output encoding for this sink; if user input reaches it unencoded in an executable context, treat as XSS.',
        ...cvssFields('xss:review-hint'),
        reproSteps: [
          `Request the page with ${point.param} set to a canary value.`,
          'Locate the canary in the raw response and check its encoding context.',
        ],
      });
    }
  }

  // POST forms are never auto-submitted: report as manual review hints.
  const postForms = dom.forms.filter((f) => f.method === 'post' && f.inputCount > 0);
  if (postForms.length > 0) {
    findings.push({
      id: nextId(),
      category: 'xss',
      mode: 'active',
      tags: ['xss-hint'],
      title: `${postForms.length} POST form(s) not auto-tested — manual review`,
      description:
        'POST forms were deliberately not submitted (state-changing). Their inputs should be manually tested for stored/reflected XSS with proper authorization.',
      severity: 'info',
      confidence: 'high',
      confirmed: false,
      location: postForms
        .slice(0, 5)
        .map((f) => f.action || '(same page)')
        .join(', '),
      remediation: 'Manually test POST inputs with context-aware payloads in an authorized session.',
      ...cvssFields('xss:review-hint'),
      requestCount: 0,
    });
  }

  const spent = http.limiter.getStats().requestsMade - before;
  const per = findings.length > 0 ? Math.max(1, Math.round(spent / findings.length)) : 0;
  for (const f of findings) {
    if (f.requestCount === undefined) f.requestCount = per;
  }
  return { findings };
}
