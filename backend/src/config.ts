import 'dotenv/config';

function str(name: string, def: string): string {
  return process.env[name] ?? def;
}

function num(name: string, def: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) {
    throw new Error(`Invalid numeric env var ${name}=${raw}`);
  }
  return n;
}

function bool(name: string, def: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  return raw === '1' || raw.toLowerCase() === 'true';
}

export interface AppConfig {
  port: number;
  nodeEnv: string;
  isProd: boolean;
  jwtSecret: string;
  databaseUrl?: string;
  redisUrl?: string;
  llmProvider: 'mock' | 'claude' | 'gemini';
  anthropicApiKey?: string;
  anthropicModel: string;
  geminiApiKey?: string;
  geminiRoutineModel: string;
  geminiReasoningModel: string;
  agentMaxActions: number;
  agentMaxDurationMs: number;
  agentRequestsPerSecond: number;
  allowPrivateTargets: boolean;
  apiRateLimitPerMin: number;
  corsOrigin: string;
}

function loadConfig(): AppConfig {
  const nodeEnv = str('NODE_ENV', 'development');
  const isProd = nodeEnv === 'production';
  let jwtSecret = process.env['JWT_SECRET'];
  if (!jwtSecret) {
    if (isProd) {
      throw new Error('JWT_SECRET must be set in production');
    }
    jwtSecret = 'dev-only-secret-do-not-use-in-production';
    console.warn('[config] JWT_SECRET not set — using insecure dev default');
  }

  const llmProviderRaw = str('LLM_PROVIDER', 'gemini').toLowerCase();
  if (llmProviderRaw !== 'mock' && llmProviderRaw !== 'claude' && llmProviderRaw !== 'gemini') {
    throw new Error(`Unsupported LLM_PROVIDER=${llmProviderRaw} (expected "mock", "claude", or "gemini")`);
  }
  const anthropicApiKey = process.env['ANTHROPIC_API_KEY'] || undefined;
  if (llmProviderRaw === 'claude' && !anthropicApiKey) {
    throw new Error(
      'LLM_PROVIDER=claude requires ANTHROPIC_API_KEY to be set (env var only, never hardcoded)'
    );
  }
  // Note: LLM_PROVIDER=gemini WITHOUT a key does NOT throw here — the
  // provider factory falls back to the mock provider with a warning, so
  // `npm run dev` keeps working with zero infrastructure/keys.

  const allowPrivateTargets = bool('ALLOW_PRIVATE_TARGETS', false);
  if (allowPrivateTargets && isProd) {
    throw new Error('ALLOW_PRIVATE_TARGETS must be false in production (SSRF guardrail)');
  }

  return {
    port: num('PORT', 3000),
    nodeEnv,
    isProd,
    jwtSecret,
    databaseUrl: process.env['DATABASE_URL'] || undefined,
    redisUrl: process.env['REDIS_URL'] || undefined,
    llmProvider: llmProviderRaw,
    anthropicApiKey,
    anthropicModel: str('ANTHROPIC_MODEL', 'claude-sonnet-4-5'),
    geminiApiKey: process.env['GEMINI_API_KEY'] || undefined,
    geminiRoutineModel: str('GEMINI_ROUTINE_MODEL', 'gemini-3.8-flash'),
    geminiReasoningModel: str('GEMINI_REASONING_MODEL', 'gemini-3.1-pro-preview'),
    agentMaxActions: num('AGENT_MAX_ACTIONS', 40),
    agentMaxDurationMs: num('AGENT_MAX_DURATION_MIN', 15) * 60 * 1000,
    agentRequestsPerSecond: num('AGENT_REQUESTS_PER_SECOND', 2),
    allowPrivateTargets,
    apiRateLimitPerMin: num('API_RATE_LIMIT_PER_MIN', 120),
    corsOrigin: str('CORS_ORIGIN', '*'),
  };
}

export const config: AppConfig = loadConfig();
