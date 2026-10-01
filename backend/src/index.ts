import { config } from './config.js';
import { createDatabase } from './db/db.js';
import { createQueue } from './queue/queue.js';
import { createLLMProvider } from './llm/index.js';
import { ScanOrchestrator } from './orchestrator/orchestrator.js';
import { buildApp } from './server.js';

async function main(): Promise<void> {
  const db = await createDatabase(config.databaseUrl);
  const queue = await createQueue(config.redisUrl);
  const provider = createLLMProvider();
  console.log(`[llm] provider: ${provider.name}`);

  const orchestrator = new ScanOrchestrator({ db, queue, config, provider });
  await queue.start((job) => orchestrator.handleJob(job.scanId));

  const app = buildApp({ config, db, queue, provider, orchestrator });
  await app.listen({ port: config.port, host: '0.0.0.0' });
  console.log(`[api] BugSeek AI backend listening on :${config.port}`);

  const shutdown = async () => {
    console.log('[api] shutting down…');
    await app.close();
    await queue.close();
    await db.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((err) => {
  console.error('[api] fatal:', err);
  process.exit(1);
});
