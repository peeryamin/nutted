import { randomUUID } from 'node:crypto';
import type {
  ApiKeyRecord,
  AuthorizationRecord,
  AuthzType,
  Finding,
  PlanTier,
  Scan,
  ScanStatus,
  UserRecord,
} from '../types.js';

export interface CreateScanInput {
  userId: string;
  targetUrl: string;
  mode: 'passive' | 'active';
  scope: Scan['scope'];
  authorizationId?: string;
  techStack?: Scan['techStack'];
}

export interface CreateAuthorizationInput {
  userId: string;
  type: AuthzType;
  programName?: string;
  referenceUrl?: string;
  statement: string;
}

export interface ScanPatch {
  status?: ScanStatus;
  techStack?: Scan['techStack'];
  progress?: Scan['progress'];
  error?: string;
  startedAt?: string;
  finishedAt?: string;
}

/**
 * Persistence abstraction. `MemoryDatabase` is the default so `npm run dev`
 * works with zero infrastructure; `PostgresDatabase` (Supabase-compatible
 * PostgreSQL) is used when DATABASE_URL is set. Both obey the same contract.
 */
export interface Database {
  readonly kind: 'memory' | 'postgres';

  createUser(email: string, passwordHash: string): Promise<UserRecord>;
  getUserByEmail(email: string): Promise<UserRecord | null>;
  getUserById(id: string): Promise<UserRecord | null>;
  setUserPlan(userId: string, plan: PlanTier): Promise<void>;

  createApiKey(
    userId: string,
    name: string,
    keyHash: string,
    keyPrefix: string
  ): Promise<ApiKeyRecord>;
  listApiKeys(userId: string): Promise<ApiKeyRecord[]>;
  getApiKeyByHash(keyHash: string): Promise<ApiKeyRecord | null>;
  touchApiKey(id: string): Promise<void>;
  revokeApiKey(id: string, userId: string): Promise<boolean>;

  createAuthorization(input: CreateAuthorizationInput): Promise<AuthorizationRecord>;
  getAuthorization(id: string): Promise<AuthorizationRecord | null>;

  createScan(input: CreateScanInput): Promise<Scan>;
  updateScan(id: string, patch: ScanPatch): Promise<Scan | null>;
  getScan(id: string): Promise<Scan | null>;
  listScans(userId: string, limit: number, offset: number): Promise<{ scans: Scan[]; total: number }>;

  addFinding(f: Omit<Finding, 'id' | 'createdAt'>): Promise<Finding>;
  listFindings(scanId: string): Promise<Finding[]>;

  recordUsage(userId: string, kind: string, quantity: number, scanId?: string): Promise<void>;
  countScansSince(userId: string, sinceIso: string): Promise<number>;
  sumUsageSince(userId: string, kind: string, sinceIso: string): Promise<number>;

  close(): Promise<void>;
}

const nowIso = () => new Date().toISOString();

export class MemoryDatabase implements Database {
  readonly kind = 'memory' as const;
  private users = new Map<string, UserRecord>();
  private usersByEmail = new Map<string, UserRecord>();
  private apiKeys = new Map<string, ApiKeyRecord>();
  private apiKeysByHash = new Map<string, ApiKeyRecord>();
  private authorizations = new Map<string, AuthorizationRecord>();
  private scans = new Map<string, Scan>();
  private findings = new Map<string, Finding[]>();
  private usage: Array<{ userId: string; kind: string; quantity: number; scanId?: string; at: string }> = [];

  async createUser(email: string, passwordHash: string): Promise<UserRecord> {
    const normalized = email.trim().toLowerCase();
    if (this.usersByEmail.has(normalized)) throw new Error('email_taken');
    const user: UserRecord = {
      id: randomUUID(),
      email: normalized,
      passwordHash,
      plan: 'free',
      createdAt: nowIso(),
    };
    this.users.set(user.id, user);
    this.usersByEmail.set(normalized, user);
    return { ...user };
  }

  async getUserByEmail(email: string): Promise<UserRecord | null> {
    return this.usersByEmail.get(email.trim().toLowerCase()) ?? null;
  }

  async getUserById(id: string): Promise<UserRecord | null> {
    return this.users.get(id) ?? null;
  }

  async setUserPlan(userId: string, plan: PlanTier): Promise<void> {
    const u = this.users.get(userId);
    if (u) u.plan = plan;
  }

  async createApiKey(
    userId: string,
    name: string,
    keyHash: string,
    keyPrefix: string
  ): Promise<ApiKeyRecord> {
    const rec: ApiKeyRecord = {
      id: randomUUID(),
      userId,
      name,
      keyHash,
      keyPrefix,
      createdAt: nowIso(),
    };
    this.apiKeys.set(rec.id, rec);
    this.apiKeysByHash.set(keyHash, rec);
    return { ...rec };
  }

  async listApiKeys(userId: string): Promise<ApiKeyRecord[]> {
    return [...this.apiKeys.values()].filter((k) => k.userId === userId).map((k) => ({ ...k }));
  }

  async getApiKeyByHash(keyHash: string): Promise<ApiKeyRecord | null> {
    return this.apiKeysByHash.get(keyHash) ?? null;
  }

  async touchApiKey(id: string): Promise<void> {
    const k = this.apiKeys.get(id);
    if (k) k.lastUsedAt = nowIso();
  }

  async revokeApiKey(id: string, userId: string): Promise<boolean> {
    const k = this.apiKeys.get(id);
    if (!k || k.userId !== userId || k.revokedAt) return false;
    k.revokedAt = nowIso();
    return true;
  }

  async createAuthorization(input: CreateAuthorizationInput): Promise<AuthorizationRecord> {
    const rec: AuthorizationRecord = {
      id: randomUUID(),
      confirmedAt: nowIso(),
      ...input,
    };
    this.authorizations.set(rec.id, rec);
    return { ...rec };
  }

  async getAuthorization(id: string): Promise<AuthorizationRecord | null> {
    return this.authorizations.get(id) ?? null;
  }

  async createScan(input: CreateScanInput): Promise<Scan> {
    const scan: Scan = {
      id: randomUUID(),
      userId: input.userId,
      targetUrl: input.targetUrl,
      mode: input.mode,
      status: 'queued',
      scope: input.scope,
      authorizationId: input.authorizationId,
      techStack: input.techStack ?? [],
      progress: { completedSteps: 0, totalSteps: 0 },
      createdAt: nowIso(),
    };
    this.scans.set(scan.id, scan);
    this.findings.set(scan.id, []);
    return { ...scan };
  }

  async updateScan(id: string, patch: ScanPatch): Promise<Scan | null> {
    const s = this.scans.get(id);
    if (!s) return null;
    Object.assign(s, patch);
    return { ...s };
  }

  async getScan(id: string): Promise<Scan | null> {
    const s = this.scans.get(id);
    return s ? { ...s } : null;
  }

  async listScans(
    userId: string,
    limit: number,
    offset: number
  ): Promise<{ scans: Scan[]; total: number }> {
    const all = [...this.scans.values()]
      .filter((s) => s.userId === userId)
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    return {
      scans: all.slice(offset, offset + limit).map((s) => ({ ...s })),
      total: all.length,
    };
  }

  async addFinding(f: Omit<Finding, 'id' | 'createdAt'>): Promise<Finding> {
    const rec: Finding = { ...f, id: randomUUID(), createdAt: nowIso() };
    const list = this.findings.get(f.scanId);
    if (!list) throw new Error('scan_not_found');
    list.push(rec);
    return { ...rec };
  }

  async listFindings(scanId: string): Promise<Finding[]> {
    return (this.findings.get(scanId) ?? []).map((f) => ({ ...f }));
  }

  async recordUsage(userId: string, kind: string, quantity: number, scanId?: string): Promise<void> {
    this.usage.push({ userId, kind, quantity, scanId, at: nowIso() });
  }

  async countScansSince(userId: string, sinceIso: string): Promise<number> {
    return this.usage.filter(
      (u) => u.userId === userId && u.kind === 'scan' && u.at >= sinceIso
    ).length;
  }

  async sumUsageSince(userId: string, kind: string, sinceIso: string): Promise<number> {
    return this.usage
      .filter((u) => u.userId === userId && u.kind === kind && u.at >= sinceIso)
      .reduce((sum, u) => sum + u.quantity, 0);
  }

  async close(): Promise<void> {
    // nothing to release
  }
}

/**
 * PostgreSQL implementation (Supabase-compatible). `pg` is imported lazily
 * so the backend still boots without the dependency installed when DATABASE_URL
 * is unset (memory mode).
 */
export class PostgresDatabase implements Database {
  readonly kind = 'postgres' as const;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private pool: any;

  private constructor(pool: unknown) {
    this.pool = pool;
  }

  static async connect(databaseUrl: string): Promise<PostgresDatabase> {
    const { Pool } = await import('pg');
    const pool = new Pool({ connectionString: databaseUrl, max: 10 });
    await pool.query('SELECT 1');
    return new PostgresDatabase(pool);
  }

  private toScan(row: Record<string, unknown>): Scan {
    return {
      id: row['id'] as string,
      userId: row['user_id'] as string,
      targetUrl: row['target_url'] as string,
      mode: row['mode'] as Scan['mode'],
      status: row['status'] as Scan['status'],
      scope: row['scope'] as Scan['scope'],
      authorizationId: (row['authorization_id'] as string) ?? undefined,
      techStack: (row['tech_stack'] as Scan['techStack']) ?? [],
      progress: row['progress'] as Scan['progress'],
      error: (row['error'] as string) ?? undefined,
      createdAt: (row['created_at'] as Date).toISOString(),
      startedAt: row['started_at'] ? (row['started_at'] as Date).toISOString() : undefined,
      finishedAt: row['finished_at'] ? (row['finished_at'] as Date).toISOString() : undefined,
    };
  }

  private toFinding(row: Record<string, unknown>): Finding {
    return {
      id: row['id'] as string,
      scanId: row['scan_id'] as string,
      category: row['category'] as string,
      title: row['title'] as string,
      description: row['description'] as string,
      severity: row['severity'] as Finding['severity'],
      cvssScore: row['cvss_score'] != null ? Number(row['cvss_score']) : undefined,
      cvssVector: (row['cvss_vector'] as string) ?? undefined,
      confidence: row['confidence'] as Finding['confidence'],
      trapProbability: Number(row['trap_probability'] ?? 0),
      honeypotSuspect: Boolean(row['honeypot_suspect']),
      location: (row['location'] as string) ?? undefined,
      evidence: (row['evidence'] as string) ?? undefined,
      reproSteps: (row['repro_steps'] as string[]) ?? [],
      remediation: (row['remediation'] as string) ?? '',
      references: (row['references'] as string[]) ?? [],
      createdAt: (row['created_at'] as Date).toISOString(),
    };
  }

  async createUser(email: string, passwordHash: string): Promise<UserRecord> {
    const normalized = email.trim().toLowerCase();
    try {
      const { rows } = await this.pool.query(
        `INSERT INTO users (email, password_hash) VALUES ($1, $2)
         RETURNING id, email, password_hash, plan, created_at`,
        [normalized, passwordHash]
      );
      const r = rows[0];
      return {
        id: r.id,
        email: r.email,
        passwordHash: r.password_hash,
        plan: r.plan,
        createdAt: r.created_at.toISOString(),
      };
    } catch (e: unknown) {
      if (e && typeof e === 'object' && (e as { code?: string }).code === '23505') {
        throw new Error('email_taken');
      }
      throw e;
    }
  }

  async getUserByEmail(email: string): Promise<UserRecord | null> {
    const { rows } = await this.pool.query(`SELECT * FROM users WHERE email = $1`, [
      email.trim().toLowerCase(),
    ]);
    if (!rows[0]) return null;
    const r = rows[0];
    return {
      id: r.id,
      email: r.email,
      passwordHash: r.password_hash,
      plan: r.plan,
      createdAt: r.created_at.toISOString(),
    };
  }

  async getUserById(id: string): Promise<UserRecord | null> {
    const { rows } = await this.pool.query(`SELECT * FROM users WHERE id = $1`, [id]);
    if (!rows[0]) return null;
    const r = rows[0];
    return {
      id: r.id,
      email: r.email,
      passwordHash: r.password_hash,
      plan: r.plan,
      createdAt: r.created_at.toISOString(),
    };
  }

  async setUserPlan(userId: string, plan: PlanTier): Promise<void> {
    await this.pool.query(`UPDATE users SET plan = $2 WHERE id = $1`, [userId, plan]);
  }

  async createApiKey(
    userId: string,
    name: string,
    keyHash: string,
    keyPrefix: string
  ): Promise<ApiKeyRecord> {
    const { rows } = await this.pool.query(
      `INSERT INTO api_keys (user_id, name, key_hash, key_prefix)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [userId, name, keyHash, keyPrefix]
    );
    const r = rows[0];
    return {
      id: r.id,
      userId: r.user_id,
      name: r.name,
      keyHash: r.key_hash,
      keyPrefix: r.key_prefix,
      createdAt: r.created_at.toISOString(),
      lastUsedAt: r.last_used_at?.toISOString(),
      revokedAt: r.revoked_at?.toISOString(),
    };
  }

  async listApiKeys(userId: string): Promise<ApiKeyRecord[]> {
    const { rows } = await this.pool.query(
      `SELECT * FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId]
    );
    return rows.map((r: Record<string, unknown>) => ({
      id: r['id'] as string,
      userId: r['user_id'] as string,
      name: r['name'] as string,
      keyHash: '***',
      keyPrefix: r['key_prefix'] as string,
      createdAt: (r['created_at'] as Date).toISOString(),
      lastUsedAt: r['last_used_at'] ? (r['last_used_at'] as Date).toISOString() : undefined,
      revokedAt: r['revoked_at'] ? (r['revoked_at'] as Date).toISOString() : undefined,
    }));
  }

  async getApiKeyByHash(keyHash: string): Promise<ApiKeyRecord | null> {
    const { rows } = await this.pool.query(`SELECT * FROM api_keys WHERE key_hash = $1`, [keyHash]);
    if (!rows[0]) return null;
    const r = rows[0];
    return {
      id: r.id,
      userId: r.user_id,
      name: r.name,
      keyHash: r.key_hash,
      keyPrefix: r.key_prefix,
      createdAt: r.created_at.toISOString(),
      lastUsedAt: r.last_used_at?.toISOString(),
      revokedAt: r.revoked_at?.toISOString(),
    };
  }

  async touchApiKey(id: string): Promise<void> {
    await this.pool.query(`UPDATE api_keys SET last_used_at = now() WHERE id = $1`, [id]);
  }

  async revokeApiKey(id: string, userId: string): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      `UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
      [id, userId]
    );
    return (rowCount ?? 0) > 0;
  }

  async createAuthorization(input: CreateAuthorizationInput): Promise<AuthorizationRecord> {
    const { rows } = await this.pool.query(
      `INSERT INTO authorizations (user_id, type, program_name, reference_url, statement)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [input.userId, input.type, input.programName ?? null, input.referenceUrl ?? null, input.statement]
    );
    const r = rows[0];
    return {
      id: r.id,
      userId: r.user_id,
      type: r.type,
      programName: r.program_name ?? undefined,
      referenceUrl: r.reference_url ?? undefined,
      statement: r.statement,
      confirmedAt: r.confirmed_at.toISOString(),
    };
  }

  async getAuthorization(id: string): Promise<AuthorizationRecord | null> {
    const { rows } = await this.pool.query(`SELECT * FROM authorizations WHERE id = $1`, [id]);
    if (!rows[0]) return null;
    const r = rows[0];
    return {
      id: r.id,
      userId: r.user_id,
      type: r.type,
      programName: r.program_name ?? undefined,
      referenceUrl: r.reference_url ?? undefined,
      statement: r.statement,
      confirmedAt: r.confirmed_at.toISOString(),
    };
  }

  async createScan(input: CreateScanInput): Promise<Scan> {
    const { rows } = await this.pool.query(
      `INSERT INTO scans (user_id, target_url, mode, scope, authorization_id, tech_stack, progress)
       VALUES ($1, $2, $3, $4::jsonb, $5, $6::jsonb, $7::jsonb) RETURNING *`,
      [
        input.userId,
        input.targetUrl,
        input.mode,
        JSON.stringify(input.scope),
        input.authorizationId ?? null,
        JSON.stringify(input.techStack ?? []),
        JSON.stringify({ completedSteps: 0, totalSteps: 0 }),
      ]
    );
    return this.toScan(rows[0]);
  }

  async updateScan(id: string, patch: ScanPatch): Promise<Scan | null> {
    const sets: string[] = [];
    const vals: unknown[] = [];
    let i = 1;
    const push = (col: string, v: unknown, json = false) => {
      sets.push(`${col} = $${i++}${json ? '::jsonb' : ''}`);
      vals.push(json ? JSON.stringify(v) : v);
    };
    if (patch.status !== undefined) push('status', patch.status);
    if (patch.techStack !== undefined) push('tech_stack', patch.techStack, true);
    if (patch.progress !== undefined) push('progress', patch.progress, true);
    if (patch.error !== undefined) push('error', patch.error);
    if (patch.startedAt !== undefined) push('started_at', patch.startedAt);
    if (patch.finishedAt !== undefined) push('finished_at', patch.finishedAt);
    if (sets.length === 0) return this.getScan(id);
    vals.push(id);
    const { rows } = await this.pool.query(
      `UPDATE scans SET ${sets.join(', ')} WHERE id = $${i} RETURNING *`,
      vals
    );
    return rows[0] ? this.toScan(rows[0]) : null;
  }

  async getScan(id: string): Promise<Scan | null> {
    const { rows } = await this.pool.query(`SELECT * FROM scans WHERE id = $1`, [id]);
    return rows[0] ? this.toScan(rows[0]) : null;
  }

  async listScans(
    userId: string,
    limit: number,
    offset: number
  ): Promise<{ scans: Scan[]; total: number }> {
    const { rows } = await this.pool.query(
      `SELECT * FROM scans WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );
    const { rows: cnt } = await this.pool.query(
      `SELECT COUNT(*)::int AS c FROM scans WHERE user_id = $1`,
      [userId]
    );
    return { scans: rows.map((r: Record<string, unknown>) => this.toScan(r)), total: cnt[0].c };
  }

  async addFinding(f: Omit<Finding, 'id' | 'createdAt'>): Promise<Finding> {
    const { rows } = await this.pool.query(
      `INSERT INTO findings
         (scan_id, category, title, description, severity, cvss_score, cvss_vector,
          confidence, trap_probability, honeypot_suspect, location, evidence,
          repro_steps, remediation, "references")
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,
      [
        f.scanId, f.category, f.title, f.description, f.severity,
        f.cvssScore ?? null, f.cvssVector ?? null, f.confidence,
        f.trapProbability, f.honeypotSuspect, f.location ?? null,
        f.evidence ?? null, f.reproSteps, f.remediation, f.references,
      ]
    );
    return this.toFinding(rows[0]);
  }

  async listFindings(scanId: string): Promise<Finding[]> {
    const { rows } = await this.pool.query(
      `SELECT * FROM findings WHERE scan_id = $1 ORDER BY created_at ASC`,
      [scanId]
    );
    return rows.map((r: Record<string, unknown>) => this.toFinding(r));
  }

  async recordUsage(userId: string, kind: string, quantity: number, scanId?: string): Promise<void> {
    await this.pool.query(
      `INSERT INTO usage_events (user_id, kind, quantity, scan_id) VALUES ($1, $2, $3, $4)`,
      [userId, kind, quantity, scanId ?? null]
    );
  }

  async countScansSince(userId: string, sinceIso: string): Promise<number> {
    const { rows } = await this.pool.query(
      `SELECT COUNT(*)::int AS c FROM usage_events
       WHERE user_id = $1 AND kind = 'scan' AND created_at >= $2::timestamptz`,
      [userId, sinceIso]
    );
    return rows[0].c;
  }

  async sumUsageSince(userId: string, kind: string, sinceIso: string): Promise<number> {
    const { rows } = await this.pool.query(
      `SELECT COALESCE(SUM(quantity), 0)::int AS s FROM usage_events
       WHERE user_id = $1 AND kind = $2 AND created_at >= $3::timestamptz`,
      [userId, kind, sinceIso]
    );
    return rows[0].s;
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

export async function createDatabase(databaseUrl?: string): Promise<Database> {
  if (databaseUrl) {
    console.log('[db] connecting to PostgreSQL (Supabase-compatible)');
    return PostgresDatabase.connect(databaseUrl);
  }
  console.log('[db] no DATABASE_URL — using in-memory store (data lost on restart)');
  return new MemoryDatabase();
}
