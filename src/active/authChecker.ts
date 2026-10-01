/**
 * Authentication checks (active testing).
 *
 * Two tiers, strictly gated:
 *
 *  OBSERVATIONAL (always allowed under the base authorization grant):
 *   - login form inventory from the DOM collection
 *   - session token handling observations (JWT-shaped cookies, tokens in
 *     storage is out of scope for the content script — cookie metadata only)
 *
 *  PROBING (requires the SEPARATE allowAuthProbes grant in the authorization
 *  record — never implied):
 *   - default-credential probes against detected login forms (small,
 *     well-known list; rate-limited; max 6 attempts)
 *   - brute-force protection indicators (a few sequential failed logins,
 *     looking for 429 / Retry-After / CAPTCHA / lockout signals)
 *
 * Password VALUES are never persisted; only the well-known pair labels
 * (e.g. "admin/admin") appear in findings, since the pair itself IS the
 * vulnerability being reported.
 */
import { scoreFinding } from '../lib/cvss';
import type { AuthorizationRecord, DomScanData, Finding } from '../lib/types';
import type { ActiveHttpClient } from './httpClient';
import { redactedSnippet } from './httpClient';

let findingSeq = 0;
const MAX_DEFAULT_ATTEMPTS = 6;

function nextId(): string {
  findingSeq++;
  return `auth-${findingSeq}`;
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

/**
 * Well-known default credential pairs (public knowledge — shipped in every
 * scanner wordlist; NOT secrets). Kept minimal and ordered by likelihood.
 */
const DEFAULT_CREDENTIALS: Array<[string, string]> = [
  ['admin', 'admin'],
  ['admin', 'password'],
  ['administrator', 'administrator'],
  ['root', 'root'],
  ['admin', '123456'],
  ['user', 'user'],
];

const SUCCESS_HINT_RE = /dashboard|welcome|log\s*out|sign\s*out|my\s*account|profile/i;
const FAILURE_HINT_RE = /invalid|incorrect|failed|try again|wrong|denied|unauthorized|does not exist/i;
const CAPTCHA_HINT_RE = /captcha|recaptcha|challenge|verify you are human/i;

interface LoginForm {
  actionUrl: string;
  usernameField: string;
  passwordField: string;
  extraFields: Array<[string, string]>;
}

function detectLoginForms(dom: DomScanData, tabUrl: string): LoginForm[] {
  const forms: LoginForm[] = [];
  // dom.forms doesn't carry field names; reconstruct from inputs heuristically.
  const passwordInputs = dom.inputs.filter((i) => i.type === 'password');
  if (passwordInputs.length === 0) return forms;

  for (const form of dom.forms) {
    if (!form.hasPassword) continue;
    let actionUrl: string;
    try {
      actionUrl = new URL(form.action || tabUrl, tabUrl).toString();
    } catch {
      continue;
    }
    const usernameField =
      dom.inputs.find((i) => /user|login|email|account/i.test(i.name || i.id))?.name ||
      dom.inputs.find((i) => ['text', 'email'].includes(i.type) && !i.hidden)?.name ||
      'username';
    const passwordField =
      passwordInputs.find((i) => i.name)?.name || 'password';
    const extraFields: Array<[string, string]> = dom.inputs
      .filter((i) => i.hidden && i.name)
      .slice(0, 5)
      .map((i) => [i.name, ''] as [string, string]);
    forms.push({ actionUrl, usernameField, passwordField, extraFields });
  }
  return forms.slice(0, 2);
}

function looksLikeSuccess(res: {
  status: number;
  finalUrl: string;
  bodyText: string;
  headers: Record<string, string>;
}): boolean {
  if (res.status === 302 || res.status === 303) return true;
  const setCookie = res.headers['set-cookie'] ?? '';
  const sessionish = /session|auth|token|sid/i.test(setCookie);
  const body = res.bodyText.slice(0, 4000);
  if (FAILURE_HINT_RE.test(body)) return false;
  if (sessionish && SUCCESS_HINT_RE.test(body)) return true;
  if (sessionish && !/login|sign\s*in/i.test(res.finalUrl)) return true;
  return false;
}

export interface AuthCheckResult {
  findings: Finding[];
}

export async function checkAuthentication(
  http: ActiveHttpClient,
  authz: AuthorizationRecord,
  tabUrl: string,
  dom: DomScanData,
): Promise<AuthCheckResult> {
  const findings: Finding[] = [];
  const before = http.limiter.getStats().requestsMade;

  const loginForms = detectLoginForms(dom, tabUrl);

  // --- Observational: login form inventory. ---
  if (loginForms.length > 0) {
    findings.push({
      id: nextId(),
      category: 'auth',
      mode: 'active',
      tags: ['auth-login-form'],
      title: `${loginForms.length} login form(s) detected`,
      description:
        `Login form(s) found at ${loginForms.map((f) => new URL(f.actionUrl).pathname).join(', ')}. ` +
        'Authentication entry points are high-value targets: verify credential policies, brute-force protections, and session handling.',
      severity: 'info',
      confidence: 'high',
      confirmed: true,
      location: loginForms[0].actionUrl,
      remediation: 'Inventory authentication endpoints and ensure they enforce strong credential and lockout policies.',
      ...cvssFields('api:endpoint-discovered'),
      requestCount: 0,
    });
  }

  // --- Observational: JWT-shaped session material in cookies (metadata only). ---
  try {
    const cookies = await chrome.cookies.getAll({ url: tabUrl });
    const jwtish = cookies.filter((c) =>
      /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(c.value),
    );
    for (const c of jwtish.slice(0, 3)) {
      const flags: string[] = [];
      if (!c.secure) flags.push('missing Secure');
      if (!c.httpOnly) flags.push('missing HttpOnly');
      findings.push({
        id: nextId(),
        category: 'auth',
        mode: 'active',
        tags: ['auth-jwt-cookie'],
        title: `JWT used as cookie "${c.name}"${flags.length > 0 ? ` (${flags.join(', ')})` : ''}`,
        description:
          `Cookie "${c.name}" holds a JWT-shaped value (value redacted to prefix). ` +
          'Verify the token has a short expiry, is validated server-side (signature + claims), and the cookie carries Secure/HttpOnly/SameSite.',
        severity: flags.length > 0 ? 'low' : 'info',
        confidence: 'medium',
        confirmed: true,
        location: `cookie: ${c.name}`,
        evidence: `${c.name}=${c.value.slice(0, 8)}… (redacted)`,
        remediation:
          'Use short-lived JWTs, validate signature/audience/expiry server-side, and set Secure, HttpOnly, and SameSite on the cookie.',
        ...cvssFields('api:endpoint-discovered'),
        requestCount: 0,
      });
    }
  } catch {
    /* cookies API unavailable */
  }

  // --- Probing tier: hard gate on allowAuthProbes. ---
  if (!authz.allowAuthProbes) {
    if (loginForms.length > 0) {
      findings.push({
        id: nextId(),
        category: 'auth',
        mode: 'active',
        tags: ['auth-probes-skipped'],
        title: 'Credential probing skipped — not authorized',
        description:
          'Login forms were found, but default-credential and brute-force checks were skipped because the authorization record ' +
          'does not include the separate login-testing grant. Re-authorize with "allow login-form testing" to enable them.',
        severity: 'info',
        confidence: 'high',
        confirmed: true,
        remediation: 'No action needed unless deeper auth testing is in scope.',
        ...cvssFields('api:endpoint-discovered'),
        requestCount: 0,
      });
    }
    return { findings };
  }

  if (loginForms.length === 0) {
    findings.push({
      id: nextId(),
      category: 'auth',
      mode: 'active',
      tags: ['auth-no-form'],
      title: 'No login forms detected — credential probing not applicable',
      description:
        'The authorization record permits login-form testing, but no password forms were found on the scanned page.',
      severity: 'info',
      confidence: 'high',
      confirmed: true,
      remediation: 'Point the scanner at the login page directly to test authentication.',
      ...cvssFields('api:endpoint-discovered'),
      requestCount: 0,
    });
    return { findings };
  }

  // --- Default-credential probes (explicitly authorized only). ---
  const form = loginForms[0];
  let attempts = 0;
  let succeeded: [string, string] | null = null;

  for (const [user, pass] of DEFAULT_CREDENTIALS.slice(0, MAX_DEFAULT_ATTEMPTS)) {
    attempts++;
    const body = new URLSearchParams();
    body.set(form.usernameField, user);
    body.set(form.passwordField, pass);
    for (const [k, v] of form.extraFields) body.set(k, v);
    try {
      const res = await http.post(form.actionUrl, body.toString());
      if (looksLikeSuccess(res)) {
        succeeded = [user, pass];
        break;
      }
      // Stop early on lockout/CAPTCHA signals — don't hammer.
      if (res.status === 429 || CAPTCHA_HINT_RE.test(res.bodyText.slice(0, 4000))) break;
    } catch {
      break;
    }
  }

  if (succeeded) {
    const [user, pass] = succeeded;
    findings.push({
      id: nextId(),
      category: 'auth',
      mode: 'active',
      tags: ['auth', 'default-creds'],
      title: `Default credentials accepted: ${user}/${pass}`,
      description:
        `The login form accepted the well-known default pair ${user}/${pass} on attempt ${attempts} (explicitly authorized test). ` +
        'This is a complete authentication bypass for that account. Per honeypot analysis, trivially-easy successes are also scored for trap probability.',
      severity: 'critical',
      confidence: 'high',
      confirmed: true,
      location: form.actionUrl,
      evidence: `accepted pair: ${user}/${pass} (well-known default — not a leaked secret)`,
      remediation:
        'Force a password change on first boot, disable or remove default accounts, and enforce unique per-installation credentials.',
      ...cvssFields('auth:default-credentials'),
      reproSteps: [
        `Open the login form at ${form.actionUrl}.`,
        `Submit username "${user}" with the default password.`,
        'Observe successful authentication (session established / redirected past login).',
      ],
      requestCount: attempts,
    });
  } else {
    findings.push({
      id: nextId(),
      category: 'auth',
      mode: 'active',
      tags: ['auth', 'default-creds-rejected'],
      title: `Default credential probes rejected (${attempts} attempts)`,
      description:
        `Tested ${attempts} well-known default pairs against the login form; all were rejected. Good posture for this control.`,
      severity: 'info',
      confidence: 'high',
      confirmed: true,
      location: form.actionUrl,
      remediation: 'No action needed. Keep default accounts disabled and monitor for credential-stuffing.',
      ...cvssFields('api:endpoint-discovered'),
      requestCount: attempts,
    });
  }

  // --- Brute-force protection indicators (a few sequential failures). ---
  let sawProtection = false;
  const protectionNotes: string[] = [];
  for (let i = 0; i < 3; i++) {
    const body = new URLSearchParams();
    body.set(form.usernameField, `bugseek_nonexistent_${Date.now() % 100000}`);
    body.set(form.passwordField, `wrong-password-${i}`);
    try {
      const res = await http.post(form.actionUrl, body.toString());
      if (res.status === 429) {
        sawProtection = true;
        protectionNotes.push('HTTP 429 rate limiting');
      }
      if (res.headers['retry-after']) {
        sawProtection = true;
        protectionNotes.push('Retry-After header');
      }
      if (CAPTCHA_HINT_RE.test(res.bodyText.slice(0, 4000))) {
        sawProtection = true;
        protectionNotes.push('CAPTCHA/challenge presented');
      }
      if (/locked|too many attempts|try again later/i.test(res.bodyText.slice(0, 4000))) {
        sawProtection = true;
        protectionNotes.push('lockout messaging');
      }
    } catch {
      break;
    }
    if (sawProtection) break;
  }

  if (!sawProtection) {
    findings.push({
      id: nextId(),
      category: 'auth',
      mode: 'active',
      tags: ['auth', 'no-bruteforce-protection'],
      title: 'No brute-force protection indicators observed on login',
      description:
        'Three sequential failed logins produced no rate limiting (429), Retry-After, CAPTCHA, or lockout signals. ' +
        'This is a missing-control observation, not an exploited flaw — credential guessing was not attempted beyond these probes.',
      severity: 'low',
      confidence: 'medium',
      confirmed: false,
      location: form.actionUrl,
      evidence: '3 failed logins → 200 responses, no throttling signals',
      remediation:
        'Add progressive delays, account lockout or CAPTCHA after failed attempts, and rate limiting on the login endpoint.',
      ...cvssFields('auth:brute-force-indicators'),
      reproSteps: [
        `Submit 3 failed logins to ${form.actionUrl}.`,
        'Observe the absence of 429 / Retry-After / CAPTCHA / lockout responses.',
      ],
      requestCount: 3,
    });
  } else {
    findings.push({
      id: nextId(),
      category: 'auth',
      mode: 'active',
      tags: ['auth', 'bruteforce-protected'],
      title: `Brute-force protections present (${protectionNotes.join(', ')})`,
      description:
        'Failed-login probes triggered defensive signals. Good posture for this control.',
      severity: 'info',
      confidence: 'high',
      confirmed: true,
      location: form.actionUrl,
      evidence: redactedSnippet(protectionNotes.join('; '), 200),
      remediation: 'No action needed.',
      ...cvssFields('api:endpoint-discovered'),
      requestCount: 3,
    });
  }

  const spent = http.limiter.getStats().requestsMade - before;
  const per = findings.length > 0 ? Math.max(1, Math.round(spent / findings.length)) : 0;
  for (const f of findings) {
    if (f.requestCount === undefined) f.requestCount = per;
  }
  return { findings };
}
