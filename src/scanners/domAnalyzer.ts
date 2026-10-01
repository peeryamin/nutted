/**
 * DOM structure analyzer — turns the content script's collected data into
 * passive findings (forms, iframes, comments, XSS sink hints).
 * No interaction with the page beyond reading the DOM.
 */
import type { DomScanData, Finding } from '../lib/types';

let findingSeq = 0;

const SENSITIVE_COMMENT_RE = /(todo|fixme|hack|password|passwd|secret|api[_-]?key|token|private|credentials|backdoor)/i;

export function analyzeDom(dom: DomScanData): Finding[] {
  const findings: Finding[] = [];
  const push = (f: Omit<Finding, 'id' | 'category'>): void => {
    findings.push({ ...f, id: `dom-${findingSeq++}`, category: 'dom' });
  };

  const isHttp = dom.url.startsWith('http://');

  // Login forms over plain HTTP.
  for (const form of dom.forms) {
    if (form.hasPassword && isHttp) {
      push({
        title: 'Login form served over plain HTTP',
        description:
          `A form containing a password field submits from an HTTP page ` +
          `(action: ${form.action || '(same page)'}). Credentials would travel unencrypted.`,
        severity: 'high',
        confidence: 'high',
        location: `form -> ${form.action || dom.url}`,
        remediation: 'Serve the page and form over HTTPS and enforce HSTS.',
      });
    }
  }

  if (dom.hiddenInputCount > 0) {
    push({
      title: `${dom.hiddenInputCount} hidden form field(s) detected`,
      description:
        'Hidden inputs sometimes carry prices, roles, IDs, or state that the ' +
        'server trusts. They are trivially editable in the browser.',
      severity: 'info',
      confidence: 'high',
      remediation:
        'Never trust hidden-field values server-side; re-validate and re-derive ' +
        'sensitive values (prices, roles) on the backend.',
    });
  }

  const crossOriginIframes = dom.iframes.filter((f) => !f.sameOrigin && f.src);
  if (crossOriginIframes.length > 0) {
    push({
      title: `${crossOriginIframes.length} cross-origin iframe(s) embedded`,
      description:
        'Third-party iframes expand the trust boundary of the page. Review what ' +
        'each one does and whether sandbox attributes are warranted.',
      severity: 'info',
      confidence: 'high',
      location: crossOriginIframes.slice(0, 3).map((f) => f.src).join(', '),
      remediation:
        'Audit third-party iframes; add sandbox attributes where interactivity ' +
        'allows it, and prefer CSP frame-src allow-lists.',
    });
  }

  const sensitiveComments = dom.comments.filter((c) => SENSITIVE_COMMENT_RE.test(c));
  if (sensitiveComments.length > 0) {
    push({
      title: `${sensitiveComments.length} HTML comment(s) mention sensitive keywords`,
      description:
        'HTML comments containing words like TODO, password, secret, or token were ' +
        'found. Comments ship to every visitor and are a classic info-leak vector.',
      severity: 'low',
      confidence: 'medium',
      evidence: sensitiveComments[0].slice(0, 200),
      remediation: 'Strip sensitive comments in production builds; keep notes in the repo, not the HTML.',
    });
  } else if (dom.comments.length > 20) {
    push({
      title: `${dom.comments.length} HTML comments on the page`,
      description:
        'A large number of HTML comments were found. Individually harmless, but ' +
        'worth a skim for leaked paths, internal hostnames, or developer notes.',
      severity: 'info',
      confidence: 'high',
      remediation: 'Minify/strip comments in production builds.',
    });
  }

  if (dom.inlineHandlerCount > 0) {
    push({
      title: `${dom.inlineHandlerCount} inline event handler(s) detected`,
      description:
        'Inline handlers (onclick, onload, …) were found in the markup. They are ' +
        'incompatible with a strict Content-Security-Policy and often indicate ' +
        'legacy code that is harder to audit for XSS.',
      severity: 'info',
      confidence: 'high',
      remediation: 'Move handlers into external scripts and enforce a strict CSP.',
    });
  }

  // XSS sink hints — informational; manual review required.
  for (const sink of dom.sinks) {
    findings.push({
      id: `sink-${findingSeq++}`,
      category: 'sinks',
      title: `Potential DOM XSS sink: ${sink.sink} (${sink.count}×)`,
      description:
        `Inline JavaScript uses ${sink.sink}, a known DOM-based XSS sink pattern. ` +
        'This is a hint for manual review only — it is NOT a confirmed vulnerability. ' +
        'Check whether attacker-controlled data can reach the sink.',
      severity: 'low',
      confidence: 'low',
      evidence: sink.sample.slice(0, 200),
      remediation:
        'Prefer safe DOM APIs (textContent, createElement). If HTML insertion is ' +
        'required, sanitize with a library such as DOMPurify and validate the data flow.',
    });
  }

  return findings;
}
