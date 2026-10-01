import {
  makeCompletion,
  type LLMCompletion,
  type LLMCompletionRequest,
  type LLMProvider,
} from './provider.js';
import type { PlannedTest, ReflectionDecision } from '../agent/engine.js';

/**
 * Deterministic stub provider for tests, local dev, and CI.
 * No network calls, no cost. Recognizes the engine's prompt markers
 * (<!--TEST-PLAN-REQUEST--> / <!--REFLECTION-REQUEST-->) and applies
 * fixed, explainable rules instead of model reasoning.
 *
 * The mock deliberately mirrors the real decision contract so behavior
 * verified against it transfers to the Claude provider.
 */
export class MockProvider implements LLMProvider {
  readonly name = 'mock';

  async complete(req: LLMCompletionRequest): Promise<LLMCompletion> {
    const systemText = req.messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n');
    const userText = req.messages.filter((m) => m.role === 'user').map((m) => m.content).join('\n');
    if (userText.includes('<!--TEST-PLAN-REQUEST-->')) {
      return makeCompletion(JSON.stringify(this.plan(userText)), { inputTokens: 400, outputTokens: 250 });
    }
    if (userText.includes('<!--REFLECTION-REQUEST-->')) {
      return makeCompletion(JSON.stringify(this.reflect(userText)), { inputTokens: 600, outputTokens: 300 });
    }
    // ── BugSeek swarm (multi-agent) prompts ──
    if (systemText.includes('MODE: PLANNING')) {
      return makeCompletion(JSON.stringify(this.swarmPlan(userText)), { inputTokens: 500, outputTokens: 300 });
    }
    if (systemText.includes('MODE: TRIAGE')) {
      return makeCompletion(JSON.stringify(this.swarmTriage(userText)), { inputTokens: 400, outputTokens: 60 });
    }
    if (systemText.includes('MODE: FULL VERDICT')) {
      return makeCompletion(JSON.stringify(this.swarmVerdict(userText)), { inputTokens: 600, outputTokens: 350 });
    }
    if (systemText.includes('HEAD AGENT')) {
      if (userText.includes('CONDITIONAL specialists to spawn')) {
        return makeCompletion(
          JSON.stringify({ specialists: ['xss', 'idor'], rationale: 'mock: exercising conditional spawn paths' }),
          { inputTokens: 500, outputTokens: 60 },
        );
      }
      if (userText.includes('Review these findings')) {
        return makeCompletion(JSON.stringify({ reviews: [], chains: [] }), { inputTokens: 800, outputTokens: 40 });
      }
      if (userText.includes('executive summary')) {
        return makeCompletion(
          'Mock executive summary: the swarm completed its run. Verify all findings manually before reporting.',
          { inputTokens: 700, outputTokens: 40 },
        );
      }
    }
    return makeCompletion(JSON.stringify({ note: 'mock provider: unrecognized prompt' }), {
      inputTokens: 10,
      outputTokens: 10,
    });
  }

  /** Swarm worker planning: small fixed plan; the worker filters unknown tools. */
  private swarmPlan(prompt: string): Array<Record<string, unknown>> {
    const target = /^TARGET: (.+)$/m.exec(prompt)?.[1]?.trim() ?? 'https://example.com';
    const maxActions = Number(/^MAX_ACTIONS: (\d+)$/m.exec(prompt)?.[1] ?? 4);
    const tests = [
      { id: 't1', name: 'Fetch target homepage', tool: 'fetch_url', args: { url: target }, priority: 1, rationale: 'Baseline response for fingerprinting.' },
      { id: 't2', name: 'Evaluate security headers', tool: 'check_security_headers', args: { url: target }, priority: 2, rationale: 'Missing headers are high-confidence findings.' },
      { id: 't3', name: 'Probe CORS policy', tool: 'probe_cors', args: { url: target }, priority: 3, rationale: 'CORS misconfiguration check.' },
      { id: 't4', name: 'Audit cookie flags', tool: 'inspect_cookies', args: { url: target }, priority: 4, rationale: 'Cookie hardening check.' },
      { id: 't5', name: 'Mine JavaScript for endpoints', tool: 'fetch_js', args: { url: target }, priority: 5, rationale: 'Endpoint discovery from scripts.' },
    ];
    return tests.slice(0, Math.max(1, Math.min(maxActions, tests.length)));
  }

  /** Swarm triage: cheap deterministic filter mirroring the reflect() rules. */
  private swarmTriage(prompt: string): { triage: 'candidate' | 'no-finding'; reason: string } {
    const obs = this.parseSwarmObservation(prompt);
    if (!obs) return { triage: 'no-finding', reason: 'mock: could not parse observation' };
    if (!obs.ok) return { triage: 'no-finding', reason: `mock: tool failed (${obs.error ?? 'unknown'})` };
    const data = (obs.data ?? {}) as Record<string, unknown>;
    if (Array.isArray(data['missing']) && data['missing'].length > 0)
      return { triage: 'candidate', reason: `mock: ${data['missing'].length} security headers missing` };
    if (data['vulnerable'] === true) return { triage: 'candidate', reason: 'mock: CORS probe indicates misconfiguration' };
    if (data['reflectedUnencoded'] === true) return { triage: 'candidate', reason: 'mock: canary reflected unencoded' };
    if (Array.isArray(data['issues']) && data['issues'].length > 0)
      return { triage: 'candidate', reason: 'mock: cookie flag issues found' };
    if (typeof data['serverDisclosure'] === 'string' && data['serverDisclosure'])
      return { triage: 'candidate', reason: 'mock: server technology disclosed' };
    if (Array.isArray(data['secretShapes']) && data['secretShapes'].length > 0)
      return { triage: 'candidate', reason: 'mock: secret-shaped strings in JS' };
    if (data['introspectionEnabled'] === true)
      return { triage: 'candidate', reason: 'mock: GraphQL introspection enabled' };
    return { triage: 'no-finding', reason: 'mock: no vulnerability indicators' };
  }

  /** Swarm verdict: reuse the engine's reflect() rules via a translated prompt. */
  private swarmVerdict(prompt: string): ReflectionDecision {
    const obs = this.parseSwarmObservation(prompt);
    if (!obs) return this.noFinding('mock: could not parse observation for verdict');
    const pseudo =
      `TOOL: ${obs.tool ?? ''}\n\`\`\`json\n` +
      JSON.stringify({ ok: obs.ok, status: obs.status, data: obs.data, bodyExcerpt: obs.bodyExcerpt, error: obs.error }) +
      `\n\`\`\``;
    const decision = this.reflect(pseudo);
    return {
      ...decision,
      location: (obs.args?.['url'] as string) ?? decision.location,
    } as ReflectionDecision;
  }

  private parseSwarmObservation(prompt: string): {
    tool?: string; ok?: boolean; status?: number; error?: string;
    data?: Record<string, unknown>; bodyExcerpt?: string; args?: Record<string, unknown>;
  } | null {
    const tool = /^TEST: .+$/m.exec(prompt) ? /^TOOL: (.+)$/m.exec(prompt)?.[1]?.trim() : undefined;
    const m = /```json\n([\s\S]*?)\n```/.exec(prompt);
    if (!m) return null;
    try {
      const parsed = JSON.parse(m[1]) as {
        test?: string; tool?: string; ok?: boolean; status?: number; error?: string;
        data?: Record<string, unknown>; bodyExcerpt?: string;
      };
      return { tool: parsed.tool ?? tool, ...parsed };
    } catch {
      return null;
    }
  }

  private plan(prompt: string): PlannedTest[] {
    const target = /^TARGET: (.+)$/m.exec(prompt)?.[1]?.trim() ?? 'https://example.com';
    return [
      {
        id: 't1', name: 'Fetch target homepage', category: 'recon', tool: 'fetch_url',
        args: { url: target }, priority: 1,
        rationale: 'Baseline response for fingerprinting and follow-up tests.',
      },
      {
        id: 't2', name: 'Evaluate security headers', category: 'headers', tool: 'check_security_headers',
        args: { url: target }, priority: 2,
        rationale: 'Missing headers are low-hanging, high-confidence findings.',
      },
      {
        id: 't3', name: 'Probe CORS policy', category: 'cors', tool: 'probe_cors',
        args: { url: target }, priority: 3,
        rationale: 'CORS misconfiguration can enable account takeover when chained.',
      },
      {
        id: 't4', name: 'Audit cookie flags', category: 'cookies', tool: 'inspect_cookies',
        args: { url: target }, priority: 4,
        rationale: 'Weak cookie flags weaken session security.',
      },
      {
        id: 't5', name: 'Test reflected input handling', category: 'xss', tool: 'probe_reflected_xss',
        args: { url: target, param: 'q' }, priority: 5,
        rationale: 'Benign canary reflection check for reflected XSS.',
      },
    ];
  }

  private reflect(prompt: string): ReflectionDecision {
    const tool = /^TOOL: (.+)$/m.exec(prompt)?.[1]?.trim() ?? '';
    const block = /```json\n([\s\S]*?)\n```/.exec(prompt)?.[1] ?? '{}';
    let obs: {
      ok?: boolean; status?: number; error?: string;
      bodyExcerpt?: string;
      data?: Record<string, unknown>;
    } = {};
    try {
      obs = JSON.parse(block);
    } catch {
      return this.noFinding('could not parse tool result');
    }

    // Honeypot heuristics first — traps take precedence over findings.
    const excerpt = obs.bodyExcerpt ?? '';
    if (/thinkstcanary|canarytoken|honeypot|cowrie/i.test(excerpt)) {
      return {
        verdict: 'honeypot',
        trapProbability: 0.9,
        severity: 'info',
        confidence: 'high',
        category: 'trap',
        title: 'Possible honeypot: canary token pattern in response',
        description:
          'The response contains patterns associated with honeypots/canary tokens. Treated as a trap, not a vulnerability.',
        evidence: excerpt.slice(0, 200),
        reproSteps: [],
        remediation: 'Do not interact further; exclude this endpoint from scope.',
        references: [],
        reasoning: 'mock: canary/honeypot signature detected in response body',
      };
    }

    if (!obs.ok) {
      return this.noFinding(`tool ${tool} failed: ${obs.error ?? 'unknown error'}`);
    }
    const data = obs.data ?? {};

    if (tool === 'probe_cors' && data['vulnerable'] === true) {
      return this.finding({
        severity: 'high', confidence: 'high', category: 'cors',
        title: 'CORS misconfiguration: arbitrary origin reflected with credentials',
        description:
          'The application reflects an attacker-controlled Origin and sets Access-Control-Allow-Credentials: true, ' +
          'allowing a malicious site to read authenticated responses.',
        location: 'Access-Control-Allow-Origin response header',
        evidence: `ACA0: ${String(data['allowOrigin'])}; ACAC: ${String(data['allowCredentials'])}`,
        reproSteps: [
          'Send a GET request with Origin: https://evil.bugseek-test.invalid',
          'Observe Access-Control-Allow-Origin echoing the attacker origin with Access-Control-Allow-Credentials: true',
        ],
        remediation: 'Use an explicit allowlist of trusted origins; never reflect arbitrary origins with credentials.',
        references: ['https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny'],
        reasoning: 'mock: attacker origin reflected with credentials=true',
      });
    }

    if (tool === 'probe_reflected_xss' && data['reflectedUnencoded'] === true) {
      return this.finding({
        severity: 'high', confidence: 'medium', category: 'xss',
        title: 'Reflected input returned unencoded (potential reflected XSS)',
        description:
          'A benign canary value sent as a query parameter was reflected in the response without HTML encoding. ' +
          'Manual verification is required to confirm script execution context.',
        location: `query parameter "${String(data['param'] ?? 'q')}"`,
        evidence: `canary reflected unencoded: ${String(data['canary'] ?? '')}`,
        reproSteps: [
          `Request the URL with ?${String(data['param'] ?? 'q')}=<canary>`,
          'Observe the canary value reflected unencoded in the HTML response',
        ],
        remediation: 'Contextually encode all user-controlled output; deploy Content-Security-Policy.',
        references: ['https://owasp.org/www-community/attacks/xss/'],
        reasoning: 'mock: canary reflected without encoding',
      });
    }

    if (tool === 'check_security_headers' && Array.isArray(data['missing']) && data['missing'].length > 0) {
      const missing = (data['missing'] as string[]).join(', ');
      const hasCsp = (data['missing'] as string[]).includes('content-security-policy');
      return this.finding({
        severity: hasCsp ? 'medium' : 'low', confidence: 'high', category: 'headers',
        title: `Missing security headers: ${missing}`,
        description:
          'One or more OWASP-recommended security headers are absent, reducing defense-in-depth ' +
          'against clickjacking, MIME sniffing, and downgrade attacks.',
        evidence: `missing: ${missing}`,
        reproSteps: ['Send a GET request and inspect response headers'],
        remediation: 'Set Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.',
        references: ['https://owasp.org/www-project-secure-headers/'],
        reasoning: 'mock: required headers absent from response',
      });
    }

    if (tool === 'inspect_cookies' && Array.isArray(data['issues']) && data['issues'].length > 0) {
      const issues = data['issues'] as string[];
      const severe = issues.some((i) => i.includes('SameSite=None'));
      return this.finding({
        severity: severe ? 'medium' : 'low', confidence: 'high', category: 'cookies',
        title: 'Weak cookie security flags',
        description: 'Session/tracking cookies are missing hardening flags: ' + issues.join('; '),
        evidence: issues.slice(0, 3).join('; '),
        reproSteps: ['Send a GET request and inspect Set-Cookie response headers'],
        remediation: 'Set Secure, HttpOnly, and an appropriate SameSite attribute on all cookies.',
        references: ['https://owasp.org/www-community/controls/SecureCookieAttribute'],
        reasoning: 'mock: cookie flag issues detected',
      });
    }

    if (tool === 'fetch_url' && typeof data['serverDisclosure'] === 'string' && data['serverDisclosure']) {
      return this.finding({
        severity: 'info', confidence: 'high', category: 'tech',
        title: `Server technology disclosed: ${data['serverDisclosure']}`,
        description: 'Response headers disclose server/framework version details, aiding targeted attacks.',
        evidence: String(data['serverDisclosure']),
        reproSteps: ['Send a GET request and inspect Server / X-Powered-By headers'],
        remediation: 'Remove or genericize Server and X-Powered-By headers.',
        references: [],
        reasoning: 'mock: version disclosure in headers',
      });
    }

    return this.noFinding(`mock: no vulnerability indicators in ${tool} result`);
  }

  private finding(partial: Omit<ReflectionDecision, 'verdict' | 'trapProbability' | 'reasoning'> & { reasoning: string }): ReflectionDecision {
    return { verdict: 'finding', trapProbability: 0.05, ...partial };
  }

  private noFinding(reasoning: string): ReflectionDecision {
    return { verdict: 'no-finding', trapProbability: 0, reasoning };
  }
}
