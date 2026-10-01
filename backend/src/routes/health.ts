import type { FastifyInstance } from 'fastify';
import type { Database } from '../db/db.js';
import type { JobQueue } from '../queue/queue.js';
import type { LLMProvider } from '../llm/provider.js';

export interface RouteDeps {
  db: Database;
  queue: JobQueue;
  provider: LLMProvider;
}

export async function healthRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  app.get('/health', async () => ({
    status: 'ok',
    version: '0.2.0',
    db: deps.db.kind,
    queue: deps.queue.kind,
    llm: deps.provider.name,
    time: new Date().toISOString(),
  }));
}
