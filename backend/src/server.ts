import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import type { AppConfig } from './config.js';
import type { Database } from './db/db.js';
import type { JobQueue } from './queue/queue.js';
import type { LLMProvider } from './llm/provider.js';
import { ScanOrchestrator } from './orchestrator/orchestrator.js';
import { healthRoutes } from './routes/health.js';
import { authRoutes } from './routes/auth.js';
import { scanRoutes, type ScanRouteDeps } from './routes/scans.js';
import { reportRoutes } from './routes/reports.js';
import { swarmRoutes } from './routes/multiagent.js';
import { v1CompatRoutes } from './routes/v1compat.js';

export interface ServerDeps {
  config: AppConfig;
  db: Database;
  queue: JobQueue;
  provider: LLMProvider;
  orchestrator: ScanOrchestrator;
}

export function buildApp(deps: ServerDeps): FastifyInstance {
  const app = Fastify({ logger: false });

  app.register(cors, { origin: deps.config.corsOrigin });
  app.register(rateLimit, {
    max: deps.config.apiRateLimitPerMin,
    timeWindow: '1 minute',
  });

  // Friendly JSON error shape for thrown guardrail errors.
  app.setErrorHandler((err: Error & { statusCode?: number }, _request, reply) => {
    const status = err.statusCode ?? 500;
    if (status >= 500) {
      console.error('[api] internal error:', err);
    }
    reply.status(status).send({ error: err.message ?? 'Internal server error' });
  });

  const routeDeps: ScanRouteDeps = {
    db: deps.db,
    queue: deps.queue,
    provider: deps.provider,
    orchestrator: deps.orchestrator,
  };

  app.register(async (instance) => {
    await healthRoutes(instance, routeDeps);
    await authRoutes(instance, routeDeps);
    await scanRoutes(instance, routeDeps);
    await swarmRoutes(instance, routeDeps);
    await v1CompatRoutes(instance, routeDeps);
    await reportRoutes(instance, routeDeps);
  });

  return app;
}
