/**
 * Runs the secret regex patterns over collected JavaScript sources.
 * All reported evidence is redacted; placeholder/test values are skipped.
 */
import { SECRET_PATTERNS, isPlaceholder, redactSecret } from '../lib/regexes';
import type { Finding } from '../lib/types';

export interface ScriptSource {
  /** Human-readable label, e.g. "inline <script> #3" or the script URL. */
  label: string;
  code: string;
}

let findingSeq = 0;
const MAX_MATCHES_PER_PATTERN = 5;

export function scanSecrets(sources: ScriptSource[]): Finding[] {
  const findings: Finding[] = [];

  for (const src of sources) {
    for (const pattern of SECRET_PATTERNS) {
      // Re-instantiate so `lastIndex` state never leaks between scans.
      const flags = pattern.regex.flags.includes('g')
        ? pattern.regex.flags
        : pattern.regex.flags + 'g';
      const re = new RegExp(pattern.regex.source, flags);

      let match: RegExpExecArray | null;
      let reported = 0;
      while ((match = re.exec(src.code)) !== null && reported < MAX_MATCHES_PER_PATTERN) {
        // Guard against zero-width matches looping forever.
        if (match.index === re.lastIndex) re.lastIndex++;

        const matched = match[0];
        if (isPlaceholder(matched)) continue;
        reported++;

        findings.push({
          id: `secret-${pattern.id}-${findingSeq++}`,
          category: 'secrets',
          title: `${pattern.name} exposed in JavaScript`,
          description: pattern.description,
          severity: pattern.severity,
          confidence:
            pattern.severity === 'critical' || pattern.severity === 'high'
              ? 'high'
              : 'medium',
          location: src.label,
          evidence: redactSecret(matched),
          remediation: pattern.remediation,
        });
      }
    }
  }

  return findings;
}
