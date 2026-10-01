/**
 * Secret-detection regex patterns for scanning JavaScript source.
 *
 * These only flag *well-known* credential formats. Generic high-entropy
 * string detection is intentionally left out of Phase 1 to keep false
 * positives low. All reported evidence is redacted by the caller.
 */
import type { Severity } from './types';

export interface SecretPattern {
  id: string;
  name: string;
  /** Must include the `g` flag handling; scanSecrets() re-instantiates it. */
  regex: RegExp;
  severity: Severity;
  description: string;
  remediation: string;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'aws-access-key',
    name: 'AWS access key ID',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: 'critical',
    description:
      'A hardcoded AWS access key ID was found in client-side JavaScript. ' +
      'If the matching secret key is also exposed (or the key has broad IAM permissions), ' +
      'attackers can operate your AWS resources directly.',
    remediation:
      'Rotate the key immediately in IAM. Remove it from client-side code and issue ' +
      'credentials from a secure backend or a secrets manager instead.',
  },
  {
    id: 'stripe-live-key',
    name: 'Stripe live secret key',
    regex: /\b[rs]k_live_[0-9A-Za-z]{16,}\b/g,
    severity: 'critical',
    description:
      'A Stripe LIVE secret key was found in client-side JavaScript. Anyone who copies ' +
      'this key can create charges, refunds, and payouts against the account.',
    remediation:
      'Roll the key immediately in the Stripe dashboard. Secret keys must only ever live ' +
      'server-side; the browser should only ever see publishable (pk_*) keys.',
  },
  {
    id: 'google-api-key',
    name: 'Google API key',
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    severity: 'high',
    description:
      'A Google Cloud API key was found in client-side JavaScript. Depending on which APIs ' +
      'are enabled and whether HTTP-referrer restrictions are set, it may be abusable for ' +
      'quota theft or billed API calls.',
    remediation:
      'Restrict the key (HTTP referrers / API restrictions) in Google Cloud Console, ' +
      'rotate it, and proxy sensitive API calls through your backend.',
  },
  {
    id: 'slack-token',
    name: 'Slack token',
    regex: /\bxox[bpras]-[0-9A-Za-z\-]{10,}\b/g,
    severity: 'high',
    description:
      'A Slack token was found in client-side JavaScript. Tokens of this form can grant ' +
      'access to Slack workspaces, channels, and messages depending on scopes.',
    remediation:
      'Revoke the token in the Slack app admin panel immediately and rotate any ' +
      'credentials it may have had access to.',
  },
  {
    id: 'github-token',
    name: 'GitHub token',
    regex: /\b(ghp_[0-9A-Za-z]{36}|gho_[0-9A-Za-z]{36}|ghu_[0-9A-Za-z]{36}|ghs_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,})\b/g,
    severity: 'high',
    description:
      'A GitHub token was found in client-side JavaScript. Depending on scopes it may ' +
      'grant read/write access to private repositories and organisations.',
    remediation:
      'Revoke the token at github.com/settings/tokens immediately. Never ship tokens ' +
      'in frontend code; use a backend proxy for GitHub API calls.',
  },
  {
    id: 'private-key',
    name: 'Private key material',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'critical',
    description:
      'Private key material (PEM block header) was found in client-side JavaScript. ' +
      'This is almost certainly an accidental leak of server-side credentials.',
    remediation:
      'Treat the key as compromised: generate a new keypair, revoke/replace the old ' +
      'one everywhere it was trusted, and remove it from all client-facing code.',
  },
  {
    id: 'mongodb-uri',
    name: 'MongoDB connection string',
    regex: /\bmongodb(?:\+srv)?:\/\/[^\s"'`\\]+/g,
    severity: 'high',
    description:
      'A MongoDB connection string was found in client-side JavaScript. It typically ' +
      'embeds a username and password and the database host.',
    remediation:
      'Rotate the database credentials immediately, restrict network access to the ' +
      'database, and never expose connection strings to the browser.',
  },
  {
    id: 'jwt',
    name: 'JSON Web Token',
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    severity: 'medium',
    description:
      'A JSON Web Token was found hardcoded in JavaScript. It may be a test/dummy ' +
      'token, but a live token could grant authenticated access as the embedded user.',
    remediation:
      'Verify whether the token is live (check expiry/claims). Never hardcode live ' +
      'tokens in frontend code; obtain them at runtime via an auth flow.',
  },
  {
    id: 'generic-secret-assignment',
    name: 'Hardcoded secret assignment',
    regex: /\b(api[_-]?key|api[_-]?secret|secret[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|private[_-]?key|db[_-]?password|db[_-]?pass)\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]/gi,
    severity: 'medium',
    description:
      'A variable that looks like a secret or API credential is assigned a literal ' +
      'string value in client-side JavaScript. Pattern-matched generically, so manual ' +
      'review is advised.',
    remediation:
      'Confirm whether the value is a real credential. If so, rotate it and move it ' +
      'server-side; the frontend should only hold public identifiers.',
  },
  {
    id: 'password-assignment',
    name: 'Hardcoded password',
    regex: /\bpassword\s*[:=]\s*["'`][^"'`\s]{4,}["'`]/gi,
    severity: 'medium',
    description:
      'A literal password value was found in client-side JavaScript.',
    remediation:
      'Rotate the credential and remove it from client-side code. Use proper auth ' +
      'flows instead of embedding passwords.',
  },
  {
    id: 'debug-flag',
    name: 'Debug flag enabled',
    regex: /["']?(?:DEBUG|debug)["']?\s*[:=]\s*(?:true|1)\b/g,
    severity: 'low',
    description:
      'A debug flag appears to be enabled in client-side JavaScript. Debug modes can ' +
      'leak stack traces, verbose errors, or internal state.',
    remediation:
      'Ensure debug flags are disabled in production builds.',
  },
];

/** Heuristic filter to skip obvious placeholders and test values. */
const PLACEHOLDER_RE =
  /(your[_-]?key|example|test|dummy|placeholder|changeme|xxx+|1234|abcd|sample|demo|none|null|undefined)/i;

export function isPlaceholder(match: string): boolean {
  return PLACEHOLDER_RE.test(match);
}

/** Keep only a short prefix of a secret for display; never show the full value. */
export function redactSecret(match: string): string {
  const prefix = match.slice(0, 8);
  return `${prefix}… (redacted)`;
}
