/**
 * Cookie auditor — enumerates cookies via the chrome.cookies API and checks
 * Secure / HttpOnly / SameSite flags plus domain scoping.
 */
import type { Finding } from '../lib/types';

let findingSeq = 0;

/** Cookie names that usually carry session/auth state. */
const SESSION_NAME_RE =
  /(sess|session|auth|token|jwt|sid|phpsessid|jsessionid|aspsession|connect\.sid|csrf)/i;

export async function auditCookies(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const isHttps = url.startsWith('https://');

  let cookies: chrome.cookies.Cookie[];
  try {
    cookies = await chrome.cookies.getAll({ url });
  } catch (err) {
    findings.push({
      id: `cookie-error-${findingSeq++}`,
      category: 'cookies',
      title: 'Could not read cookies',
      description: `The cookies API failed for this page: ${String(err)}`,
      severity: 'info',
      confidence: 'high',
      remediation: 'Re-run the scan; if it persists, the page may restrict cookie access.',
    });
    return findings;
  }

  if (cookies.length === 0) {
    findings.push({
      id: `cookie-none-${findingSeq++}`,
      category: 'cookies',
      title: 'No cookies observed',
      description: 'No cookies were visible to the extension for this page.',
      severity: 'info',
      confidence: 'high',
      remediation: 'No action needed.',
    });
    return findings;
  }

  for (const cookie of cookies) {
    const isSession = SESSION_NAME_RE.test(cookie.name);
    const loc = `cookie "${cookie.name}" (domain ${cookie.domain})`;

    if (isHttps && !cookie.secure) {
      findings.push({
        id: `cookie-nosecure-${findingSeq++}`,
        category: 'cookies',
        title: `Cookie "${cookie.name}" missing Secure flag`,
        description:
          'This cookie is sent over HTTPS but lacks the Secure flag, so the browser ' +
          'may still send it over plain HTTP (e.g. after a downgrade or to a sibling ' +
          'HTTP endpoint), exposing it to network sniffing.',
        severity: isSession ? 'medium' : 'low',
        confidence: 'high',
        location: loc,
        remediation: 'Set the Secure attribute on the cookie so it is only ever sent over HTTPS.',
      });
    }

    if (isSession && !cookie.httpOnly) {
      findings.push({
        id: `cookie-nohttponly-${findingSeq++}`,
        category: 'cookies',
        title: `Session cookie "${cookie.name}" missing HttpOnly flag`,
        description:
          'This looks like a session/auth cookie but is readable from JavaScript. ' +
          'Any XSS vulnerability on the site could then steal the session.',
        severity: 'medium',
        confidence: 'medium',
        location: loc,
        remediation: 'Set the HttpOnly attribute so the cookie is inaccessible to JavaScript.',
      });
    }

    if (cookie.sameSite === 'no_restriction' && !cookie.secure) {
      findings.push({
        id: `cookie-samesite-${findingSeq++}`,
        category: 'cookies',
        title: `Cookie "${cookie.name}" uses SameSite=None without Secure`,
        description:
          'SameSite=None requires the Secure flag; modern browsers reject this ' +
          'combination, which breaks the cookie and signals a misconfiguration. ' +
          'It also maximises the cookie\'s exposure to cross-site requests.',
        severity: 'high',
        confidence: 'high',
        location: loc,
        remediation:
          'Either add the Secure flag (HTTPS only) or switch to SameSite=Lax/Strict ' +
          'if cross-site sending is not required.',
      });
    } else if (cookie.sameSite === 'unspecified') {
      findings.push({
        id: `cookie-samesite-unset-${findingSeq++}`,
        category: 'cookies',
        title: `Cookie "${cookie.name}" has no explicit SameSite attribute`,
        description:
          'Without an explicit SameSite attribute the cookie falls back to the ' +
          'browser default (Lax in modern browsers). Explicit is better than implicit.',
        severity: 'low',
        confidence: 'high',
        location: loc,
        remediation: 'Set an explicit SameSite value (Lax is a safe default; Strict for sensitive cookies).',
      });
    }

    if (cookie.domain.startsWith('.')) {
      findings.push({
        id: `cookie-parentdomain-${findingSeq++}`,
        category: 'cookies',
        title: `Cookie "${cookie.name}" scoped to parent domain "${cookie.domain}"`,
        description:
          'The cookie is shared with all subdomains of the parent domain. If any ' +
          'subdomain is compromised (or hosts untrusted content), the cookie is exposed there too.',
        severity: 'info',
        confidence: 'medium',
        location: loc,
        remediation:
          'If the cookie is only needed on one host, drop the Domain attribute so the ' +
          'cookie becomes host-only.',
      });
    }
  }

  return findings;
}
