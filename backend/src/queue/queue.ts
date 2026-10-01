/**
 * Scan job queue abstraction.
 *
 * - `BullMQQueue` (BullMQ + Redis) when REDIS_URL is set — production path.
 * - `MemoryQueue` otherwise — in-process, zero infrastructure, so
 *   `npm run dev` works locally. Jobs are NOT durable in memory mode
 *   (documented limitation; fine for local dev).
 */

export interface ScanJob {
  scanId: string;
}

export type JobHandler = (job: ScanJob) => Promise<void>;

export interface JobQueue {
  readonly kind: 'bullmq' | 'memory';
  enqueue(job: ScanJob): Promise<void>;
  start(handler: JobHandler): Promise<void>;
  close(): Promise<void>;
}

class MemoryQueue implements JobQueue {
  readonly kind = 'memory' as const;
  private handler: JobHandler | null = null;
  private pending: ScanJob[] = [];
  private running = false;
  private closed = false;

  async enqueue(job: ScanJob): Promise<void> {
    if (this.closed) throw new Error('queue closed');
    this.pending.push(job);
    void this.drain();
  }

  async start(handler: JobHandler): Promise<void> {
    this.handler = handler;
    void this.drain();
  }

  private async drain(): Promise<void> {
    if (this.running || !this.handler || this.closed) return;
    this.running = true;
    try {
      while (this.pending.length > 0 && !this.closed) {
        const job = this.pending.shift();
        if (!job) break;
        try {
          await this.handler(job);
        } catch (err) {
          console.error(`[queue] job ${job.scanId} failed:`, err);
        }
      }
    } finally {
      this.running = false;
    }
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}

class BullMQQueue implements JobQueue {
  readonly kind = 'bullmq' as const;
  // BullMQ is imported lazily so the backend boots without Redis configured.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private queue: any = null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private worker: any = null;
  private redisUrl: string;

  constructor(redisUrl: string) {
    this.redisUrl = redisUrl;
  }

  private async ensureQueue(): Promise<void> {
    if (!this.queue) {
      const { Queue } = await import('bullmq');
      this.queue = new Queue('bugseek-scans', {
        connection: { url: this.redisUrl },
        defaultJobOptions: { attempts: 2, backoff: { type: 'exponential', delay: 5000 } },
      });
    }
  }

  async enqueue(job: ScanJob): Promise<void> {
    await this.ensureQueue();
    await this.queue.add('scan', job, { jobId: `scan-${job.scanId}` });
  }

  async start(handler: JobHandler): Promise<void> {
    const { Worker } = await import('bullmq');
    this.worker = new Worker(
      'bugseek-scans',
      async (bullJob) => {
        await handler(bullJob.data as ScanJob);
      },
      { connection: { url: this.redisUrl }, concurrency: 2 }
    );
    this.worker.on('failed', (job: unknown, err: Error) => {
      console.error('[queue] bullmq job failed:', (job as { id?: string })?.id, err.message);
    });
  }

  async close(): Promise<void> {
    await this.worker?.close().catch(() => undefined);
    await this.queue?.close().catch(() => undefined);
  }
}

export async function createQueue(redisUrl?: string): Promise<JobQueue> {
  if (redisUrl) {
    console.log('[queue] using BullMQ + Redis');
    return new BullMQQueue(redisUrl);
  }
  console.log('[queue] no REDIS_URL — using in-process memory queue (not durable)');
  return new MemoryQueue();
}
