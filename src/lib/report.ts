/**
 * Markdown report generator — turns a ScanResult into a bug-bounty-ready
 * Markdown document with severity tags, CVSS scores, trap flags, attack
 * chains, reproduction steps, and remediation notes.
 */
import {
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  type Finding,
  type ScanResult,
  type Severity,
} from './types';
import { basisLabel } from './authorization';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function countBySeverity(r: ScanResult): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  for (const f of r.findings) counts[f.severity]++;
  return counts;
}

function escapeCodeFence(text: string): string {
  return text.replace(/```/g, '``\u200b`');
}

function scopeLine(r: ScanResult): string {
  if (r.mode === 'active' && r.authorization) {
    const a = r.authorization;
    const s = r.activeStats;
    return (
      `Active testing (authorized: ${basisLabel(a.type)}` +
      `${a.programName ? ` — ${a.programName}` : ''}, confirmed ` +
      `${a.confirmedAt.slice(0, 10)}). ` +
      `${s?.requestsMade ?? 0} rate-limited request(s) sent ` +
      `(≥${s?.rateLimitMs ?? '?'}ms gap). ` +
      `Backend ${s?.backendReachable ? 'reachable' : 'offline — standalone local results'}.`
    );
  }
  return 'Passive reconnaissance only — no requests were sent to the target beyond loading its public resources. No active testing was performed.';
}

function findingBlock(f: Finding, n: number): string[] {
  const lines: string[] = [];
  const trap = f.honeypotSuspect ? ' 🪤 POSSIBLE TRAP' : '';
  const conf =
    f.mode === 'active'
      ? f.confirmed
        ? ' ✅ confirmed'
        : ' 🔍 review hint'
      : '';
  lines.push(`#### ${n}. [${SEVERITY_LABEL[f.severity]}]${trap}${conf} ${f.title}`);
  lines.push('');
  lines.push(f.description);
  lines.push('');
  if (f.location) lines.push(`- **Location:** \`${f.location}\``);
  lines.push(`- **Confidence:** ${f.confidence}`);
  lines.push(`- **Category:** ${f.category}`);
  if (f.mode) lines.push(`- **Mode:** ${f.mode}`);
  if (f.cvssScore !== undefined) {
    lines.push(
      `- **CVSS v3.1:** ${f.cvssScore.toFixed(1)}` +
        (f.cvssVector ? ` \`${f.cvssVector}\`` : ''),
    );
  }
  if (f.trapProbability !== undefined && f.trapProbability > 0) {
    lines.push(
      `- **Trap probability:** ${Math.round(f.trapProbability * 100)}%` +
        (f.honeypotSuspect ? ' — flagged, not reported as a vulnerability' : ''),
    );
  }
  if (f.requestCount !== undefined && f.requestCount > 0) {
    lines.push(`- **Requests spent:** ${f.requestCount}`);
  }
  if (f.attackChainIds && f.attackChainIds.length > 0) {
    lines.push(`- **Attack chains:** ${f.attackChainIds.join(', ')}`);
  }
  if (f.cvssJustification) {
    lines.push('');
    lines.push(`_Why this CVSS score: ${f.cvssJustification}_`);
  }
  if (f.trapSignals && f.trapSignals.length > 0 && (f.trapProbability ?? 0) > 0) {
    lines.push('');
    lines.push(`_Trap signals: ${f.trapSignals.join(' • ')}_`);
  }
  if (f.evidence) {
    lines.push('');
    lines.push('```');
    lines.push(escapeCodeFence(f.evidence));
    lines.push('```');
  }
  if (f.reproSteps && f.reproSteps.length > 0) {
    lines.push('');
    lines.push('**Reproduction:**');
    lines.push('');
    f.reproSteps.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
  }
  if (f.references && f.references.length > 0) {
    lines.push('');
    lines.push(`**References:** ${f.references.join(', ')}`);
  }
  lines.push('');
  lines.push(`**Remediation:** ${f.remediation}`);
  lines.push('');
  return lines;
}

export function buildMarkdownReport(r: ScanResult): string {
  const counts = countBySeverity(r);
  const lines: string[] = [];

  lines.push('# BugSeek AI — Security Reconnaissance Report');
  lines.push('');
  lines.push(`- **Target:** ${r.targetUrl}`);
  lines.push(`- **Scanned:** ${r.scannedAt}`);
  lines.push(`- **Duration:** ${(r.durationMs / 1000).toFixed(1)}s`);
  lines.push(`- **Mode:** ${r.mode === 'active' ? 'Active testing' : 'Passive reconnaissance'}`);
  lines.push(`- **Scope:** ${scopeLine(r)}`);
  lines.push('');

  lines.push('## Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('| --- | --- |');
  for (const sev of SEVERITIES) {
    lines.push(`| ${SEVERITY_LABEL[sev]} | ${counts[sev]} |`);
  }
  lines.push(`| **Total** | **${r.findings.length}** |`);
  const trapCount = r.findings.filter((f) => f.honeypotSuspect).length;
  if (trapCount > 0) {
    lines.push(`| _Flagged as possible traps_ | _${trapCount}_ |`);
  }
  lines.push('');

  lines.push('## Technology fingerprint');
  lines.push('');
  if (r.tech.length === 0) {
    lines.push('No technologies identified from passive signals.');
  } else {
    for (const t of r.tech) {
      lines.push(`- **${t.name}**${t.version ? ` ${t.version}` : ''} _(detected via ${t.source})_`);
    }
  }
  lines.push('');

  // Attack chains (active scans).
  const chains = r.chains ?? [];
  if (chains.length > 0) {
    lines.push('## Attack chains');
    lines.push('');
    lines.push(
      'Individual findings linked into higher-impact narratives. ' +
        'Chains marked AI-deepened were verified by the backend AI agent.',
    );
    lines.push('');
    chains.forEach((c, i) => {
      lines.push(`### Chain ${i + 1}. [${SEVERITY_LABEL[c.severity]}] ${c.title}`);
      lines.push('');
      lines.push(c.description);
      lines.push('');
      lines.push(`- **Impact:** ${c.impact}`);
      lines.push(`- **Confidence:** ${c.confidence}`);
      if (c.cvssScore !== undefined) lines.push(`- **Max member CVSS:** ${c.cvssScore.toFixed(1)}`);
      lines.push(`- **Findings:** ${c.findingIds.join(', ')}`);
      if (c.aiDeepened) lines.push('- **AI-deepened:** yes');
      lines.push('');
    });
  }

  // Findings: vulnerabilities first, trap-flagged items in their own section.
  const vulns = r.findings.filter((f) => !f.honeypotSuspect);
  const traps = r.findings.filter((f) => f.honeypotSuspect);

  lines.push('## Findings');
  lines.push('');
  const sorted = [...vulns].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
  if (sorted.length === 0) {
    lines.push('No findings. The checks did not surface any issues on this target.');
    lines.push('');
  }
  let currentSev: Severity | '' = '';
  let n = 0;
  for (const f of sorted) {
    if (f.severity !== currentSev) {
      currentSev = f.severity;
      n = 0;
      lines.push(`### ${SEVERITY_LABEL[f.severity]} findings`);
      lines.push('');
    }
    n++;
    lines.push(...findingBlock(f, n));
  }

  if (traps.length > 0) {
    lines.push('## Flagged as possible traps (not reported as vulnerabilities)');
    lines.push('');
    lines.push(
      'These findings scored at or above the trap-probability threshold. ' +
        'They are deliberately NOT reported as vulnerabilities — verify manually; they may be honeypots, canary tokens, or intentionally-vulnerable demo fixtures.',
    );
    lines.push('');
    let tn = 0;
    for (const f of traps) {
      tn++;
      lines.push(...findingBlock(f, tn));
    }
  }

  lines.push('---');
  lines.push('');
  lines.push(
    '_Generated by BugSeek AI. Findings are hints for manual review unless marked confirmed. ' +
    'Only test targets you are authorized to test._',
  );
  lines.push('');

  return lines.join('\n');
}

/** Safe filename for the downloaded report. */
export function reportFilename(targetUrl: string, scannedAt: string): string {
  let host = 'target';
  try {
    host = new URL(targetUrl).hostname.replace(/[^a-z0-9.-]/gi, '_');
  } catch {
    /* keep default */
  }
  const date = scannedAt.slice(0, 10);
  return `bugseek-report-${host}-${date}.md`;
}
