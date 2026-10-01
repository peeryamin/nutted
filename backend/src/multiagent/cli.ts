#!/usr/bin/env node
/**
 * BugSeek swarm CLI — run the multi-agent super agent from the terminal.
 *
 *   npx tsx src/multiagent/cli.ts --target https://example.com --scope full-domain
 *
 * Flags:
 *   --target <url>        (required) target to test — you must be authorized
 *   --scope <mode>        full-domain | subdomain | page   (default: subdomain)
 *   --subdomains          include subdomains (with full-domain)
 *   --rps <n>             requests/sec across all workers (default: 2, max: 10)
 *   --max-workers <n>     cap specialists (default: 7)
 *   --concurrency <n>     parallel workers (default: 3)
 *   --max-tokens <n>      global LLM token budget (default: 120000)
 *   --timeout-min <n>     wall-clock cap in minutes (default: 10)
 *   --allow-private       allow private/internal targets (self-hosted labs)
 *   --specialists a,b,c   force specialist set (ids: recon,secrets,headers,cors,xss,idor,auth,graphql)
 *   --out <file.md>       write Markdown report to file (default: stdout)
 *   --mock                use the mock LLM provider (no API key, for testing)
 *
 * Env: GEMINI_API_KEY (unless --mock). Model tiers via GEMINI_ROUTINE_MODEL /
 * GEMINI_REASONING_MODEL like the rest of the backend.
 */
import { writeFileSync } from 'node:fs';
import { runMultiAgentScan, renderMarkdownReport } from './orchestrator.js';
import { MockProvider } from '../llm/mock.js';
import { runHeadAgent } from './head.js';
import type { SpecialistId } from './types.js';

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
function flag(name: string): boolean {
  return process.argv.includes(name);
}

async function main(): Promise<void> {
  const target = arg('--target');
  if (!target) {
    console.error('Missing --target. Example: npx tsx src/multiagent/cli.ts --target https://example.com');
    process.exit(2);
  }
  const scopeMode = (arg('--scope') ?? 'subdomain') as 'full-domain' | 'subdomain' | 'page';
  if (!['full-domain', 'subdomain', 'page'].includes(scopeMode)) {
    console.error('--scope must be full-domain, subdomain, or page');
    process.exit(2);
  }
  const specialists = arg('--specialists')
    ?.split(',')
    .map((s) => s.trim())
    .filter(Boolean) as SpecialistId[] | undefined;

  const useMock = flag('--mock');
  const onEvent = (e: { kind: string; message: string }) =>
    console.error(`[${e.kind}] ${e.message}`);

  console.error(`BugSeek swarm starting against ${target}`);
  console.error('Confirm: you are authorized to test this target (bounty program, contract, or ownership).');

  const scope = {
    mode: scopeMode,
    includeSubdomains: flag('--subdomains'),
    excludedHosts: [] as string[],
    excludedPaths: [] as string[],
  };
  const limits = {
    maxWorkers: Number(arg('--max-workers') ?? 7),
    maxConcurrency: Number(arg('--concurrency') ?? 3),
    maxTotalTokens: Number(arg('--max-tokens') ?? 120_000),
    maxDurationMs: Number(arg('--timeout-min') ?? 10) * 60_000,
    requestsPerSecond: Math.min(10, Number(arg('--rps') ?? 2)),
    allowPrivateTargets: flag('--allow-private'),
  };

  const outcome = useMock
    ? await runHeadAgent({
        targetUrl: target,
        scope: { ...scope, maxRequestsPerSecond: limits.requestsPerSecond },
        provider: new MockProvider(),
        limits,
        specialists,
        onEvent,
      })
    : await runMultiAgentScan({ targetUrl: target, scope, limits, specialists, onEvent });

  const md = renderMarkdownReport(outcome);
  const out = arg('--out');
  if (out) {
    writeFileSync(out, md, 'utf8');
    console.error(`Report written to ${out}`);
  } else {
    console.log(md);
  }
  console.error(
    `Done: ${outcome.findings.length} findings, ${outcome.testsRun} tests, ` +
      `${outcome.tokensUsed.input + outcome.tokensUsed.output} tokens, ` +
      `${(outcome.durationMs / 1000).toFixed(1)}s.`,
  );
}

main().catch((err) => {
  console.error(`Swarm failed: ${(err as Error).message}`);
  process.exit(1);
});
