/**
 * HTTP security header checker — evaluates captured response headers
 * against OWASP best practices.
 */
import type { Finding } from '../lib/types';

let findingSeq = 0;

export function checkHeaders(
  headers: Record<string, string>,
  isHttps: boolean,
): Finding[] {
  const findings: Finding[] = [];
  const h = (name: string): string | undefined => headers[name.toLowerCase()];
  const push = (f: Omit<Finding, 'id' | 'category'>): void => {
    findings.push({ ...f, id: `header-${findingSeq++}`, category: 'headers' });
  };

  if (Object.keys(headers).length === 0) {
    push({
      title: 'No response headers captured',
      description:
        'BugSeek could not observe the page\'s HTTP response headers ' +
        '(the navigation may predate the extension). Header checks were skipped.',
      severity: 'info',
      confidence: 'high',
      remediation: 'Reload the page and run the scan again to capture headers.',
    });
    return findings;
  }

  if (!h('content-security-policy')) {
    push({
      title: 'Missing Content-Security-Policy header',
      description:
        'No CSP was observed. Without it, the browser has no policy restricting ' +
        'where scripts, styles, and other resources may load from, which makes ' +
        'XSS exploitation significantly easier.',
      severity: 'medium',
      confidence: 'high',
      location: 'HTTP response headers',
      remediation:
        'Deploy a Content-Security-Policy (start with a report-only policy, then enforce). ' +
        'See the OWASP CSP cheat sheet for a starter policy.',
    });
  }

  if (isHttps && !h('strict-transport-security')) {
    push({
      title: 'Missing Strict-Transport-Security header',
      description:
        'The site is served over HTTPS but does not send HSTS, leaving users ' +
        'exposed to SSL-stripping downgrade attacks on first visit.',
      severity: 'medium',
      confidence: 'high',
      location: 'HTTP response headers',
      remediation:
        'Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` ' +
        'and consider HSTS preloading once stable.',
    });
  }

  const csp = h('content-security-policy') ?? '';
  if (!h('x-frame-options') && !/frame-ancestors/i.test(csp)) {
    push({
      title: 'Missing X-Frame-Options header',
      description:
        'Neither X-Frame-Options nor a CSP frame-ancestors directive was observed. ' +
        'The page may be embeddable in a malicious iframe (clickjacking).',
      severity: 'low',
      confidence: 'high',
      location: 'HTTP response headers',
      remediation:
        'Send `X-Frame-Options: DENY` (or SAMEORIGIN) or add a `frame-ancestors` ' +
        'directive to the Content-Security-Policy.',
    });
  }

  if (!h('x-content-type-options')) {
    push({
      title: 'Missing X-Content-Type-Options header',
      description:
        'Without `nosniff`, browsers may MIME-sniff responses, which can turn ' +
        'innocent file types into executable content in older attack scenarios.',
      severity: 'low',
      confidence: 'high',
      location: 'HTTP response headers',
      remediation: 'Send `X-Content-Type-Options: nosniff`.',
    });
  }

  if (!h('referrer-policy')) {
    push({
      title: 'Missing Referrer-Policy header',
      description:
        'Without a Referrer-Policy the browser may leak full URLs (including query ' +
        'strings that can contain tokens) to third-party sites on navigation.',
      severity: 'low',
      confidence: 'high',
      location: 'HTTP response headers',
      remediation:
        'Send a restrictive policy such as `Referrer-Policy: strict-origin-when-cross-origin` ' +
        'or `no-referrer`.',
    });
  }

  if (!h('permissions-policy') && !h('feature-policy')) {
    push({
      title: 'Missing Permissions-Policy header',
      description:
        'No Permissions-Policy was observed, so powerful browser features ' +
        '(camera, microphone, geolocation, …) are not explicitly restricted.',
      severity: 'info',
      confidence: 'high',
      location: 'HTTP response headers',
      remediation:
        'Send a Permissions-Policy that disables features the page does not need, ' +
        'e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=()`.',
    });
  }

  const server = h('server');
  if (server) {
    const leaksVersion = /\d+\.\d+/.test(server);
    push({
      title: `Server header discloses "${server}"`,
      description:
        'The Server response header reveals the web server software' +
        (leaksVersion ? ' including its version' : '') +
        ', which helps attackers target known vulnerabilities for that stack.',
      severity: leaksVersion ? 'low' : 'info',
      confidence: 'high',
      location: 'HTTP response headers',
      remediation:
        'Suppress or genericise the Server header (e.g. server_tokens off; in nginx).',
    });
  }

  const poweredBy = h('x-powered-by');
  if (poweredBy) {
    push({
      title: `X-Powered-By header discloses "${poweredBy}"`,
      description:
        'The X-Powered-By header reveals backend technology details that aid ' +
        'targeted attacks.',
      severity: 'info',
      confidence: 'high',
      location: 'HTTP response headers',
      remediation: 'Remove the X-Powered-By header (e.g. expose_php=Off; helmet.js hidePoweredBy).',
    });
  }

  return findings;
}
