import type { SpecialistDef, SpecialistId } from './types.js';

/**
 * Specialist worker definitions. Each specialist is an expert agent with:
 * - a focused system prompt (PLAN + REFLECT guidance),
 * - a restricted tool subset (least privilege per worker),
 * - its own action/escalation budgets.
 *
 * Workers are deliberately narrow: depth beats breadth, and the head agent
 * handles everything cross-cutting (dedupe, trap review, chaining).
 */

const BASE_RULES = `HARD RULES (never break):
- Only test URLs inside the authorized scope. If a tool call is refused by the scope guard, do NOT work around it.
- Never destructive: no DoS, no data deletion, no credential stuffing, no mass account creation.
- Prefer reading over writing. Probes use benign canary values only.
- Report evidence as short redacted snippets — never full secrets, tokens, or personal data.
- If you see canary tokens, honeypot banners, or absurdly-easy "vulnerabilities", note them as possible traps; do not celebrate them as findings.
- Return ONLY valid JSON — no prose, no markdown fences.`;

function planPrompt(expertise: string, tools: string[]): string {
  return `You are a specialist security-testing agent. Your expertise: ${expertise}

${BASE_RULES}

You receive: TARGET, TECH STACK, SCOPE, MAX ACTIONS, and notes from earlier workers.
Plan a focused sequence of tests using ONLY these tools: ${tools.join(', ')}.
Prioritize tests that match the tech stack and the target's observed behavior.

Return a JSON array of tests: [{"id":"t1","name":"...","tool":"<tool name>","args":{...},"priority":1,"rationale":"..."}]
Rules: priority 1 = highest. Keep args' URLs within scope. Max ${'MAX_ACTIONS'} tests.`;
}

function reflectPrompt(expertise: string): string {
  return `You are a specialist security-testing agent. Your expertise: ${expertise}

${BASE_RULES}

You receive a TEST, its TOOL RESULT (redacted), and heuristic honeypot signals.
First TRIAGE: is this worth deep analysis? Return {"triage":"candidate"|"no-finding","reason":"..."}.
If triage is "candidate", the head agent will ask you for a full verdict with this schema:
{"verdict":"finding|honeypot|no-finding","trapProbability":0.0-1.0,
 "severity":"critical|high|medium|low|info","confidence":"high|medium|low",
 "category":"...","title":"...","description":"...","location":"...",
 "evidence":"short redacted snippet","reproSteps":["..."],"remediation":"...",
 "references":["https://..."],"chainWith":["..."],"reasoning":"..."}
Return ONLY valid JSON — no prose, no markdown fences.`;
}

const defs: SpecialistDef[] = [
  {
    id: 'recon',
    name: 'Recon',
    expertise:
      'technology fingerprinting, endpoint discovery, and attack-surface mapping from passive observations and JS mining.',
    systemPrompt: '',
    tools: ['fetch_url', 'fetch_js', 'check_security_headers'],
    maxActions: 10,
    maxEscalations: 1,
  },
  {
    id: 'secrets',
    name: 'Secret Hunter',
    expertise:
      'finding leaked credentials, API keys, and tokens in JavaScript bundles, API responses, and HTML comments.',
    systemPrompt: '',
    tools: ['fetch_url', 'fetch_js'],
    maxActions: 8,
    maxEscalations: 3,
  },
  {
    id: 'headers',
    name: 'Headers & Cookies',
    expertise:
      'HTTP security headers, cookie flags, and transport-security posture.',
    systemPrompt: '',
    tools: ['fetch_url', 'check_security_headers', 'inspect_cookies'],
    maxActions: 6,
    maxEscalations: 1,
  },
  {
    id: 'cors',
    name: 'CORS Analyst',
    expertise:
      'cross-origin resource sharing misconfigurations: reflected origins, wildcards with credentials, null-origin trust.',
    systemPrompt: '',
    tools: ['fetch_url', 'probe_cors'],
    maxActions: 8,
    maxEscalations: 2,
  },
  {
    id: 'xss',
    name: 'XSS Hunter',
    expertise:
      'reflected and DOM-based cross-site scripting: reflection-context mapping and benign canary confirmation.',
    systemPrompt: '',
    tools: ['fetch_url', 'probe_reflected_xss'],
    maxActions: 10,
    maxEscalations: 3,
  },
  {
    id: 'idor',
    name: 'IDOR Hunter',
    expertise:
      'insecure direct object references: discovering numeric/sequential object IDs and testing neighbor access.',
    systemPrompt: '',
    tools: ['fetch_url', 'fetch_js', 'probe_idor'],
    maxActions: 10,
    maxEscalations: 3,
  },
  {
    id: 'auth',
    name: 'Auth Analyst',
    expertise:
      'authentication posture: session handling, JWT weaknesses, login-form behavior, brute-force protections. Observational only unless explicitly granted auth probing.',
    systemPrompt: '',
    tools: ['fetch_url', 'inspect_cookies'],
    maxActions: 8,
    maxEscalations: 2,
  },
  {
    id: 'graphql',
    name: 'GraphQL Prober',
    expertise:
      'GraphQL attack surface: introspection exposure, dangerous mutations, batching abuse.',
    systemPrompt: '',
    tools: ['fetch_url', 'probe_graphql', 'fetch_js'],
    maxActions: 8,
    maxEscalations: 2,
  },
];

for (const d of defs) {
  d.systemPrompt =
    `ROLE: ${d.name} — ${d.expertise}\n\n` +
    `PLANNING MODE:\n${planPrompt(d.expertise, d.tools)}\n\n` +
    `REFLECTION MODE:\n${reflectPrompt(d.expertise)}`;
}

const byId = new Map<SpecialistId, SpecialistDef>(defs.map((d) => [d.id, d]));

export function getSpecialist(id: SpecialistId): SpecialistDef {
  const d = byId.get(id);
  if (!d) throw new Error(`Unknown specialist: ${id}`);
  return d;
}

export function allSpecialists(): SpecialistDef[] {
  return [...defs];
}

/** Specialists the head considers "always useful" vs conditional. */
export const ALWAYS_SPAWN: SpecialistId[] = ['headers', 'cors', 'secrets'];
export const CONDITIONAL_SPAWN: SpecialistId[] = ['xss', 'idor', 'auth', 'graphql'];
