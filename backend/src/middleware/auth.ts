import type { FastifyRequest } from 'fastify';
import type { Database } from '../db/db.js';
import { hashApiKey, verifySession } from '../auth/auth.js';
import { PLAN_QUOTAS } from '../auth/usage.js';
import type { PlanTier } from '../types.js';

export interface AuthenticatedUser {
  id: string;
  email: string;
  plan: PlanTier;
  viaApiKey: boolean;
}

declare module 'fastify' {
  interface FastifyRequest {
    user?: AuthenticatedUser;
  }
}

/**
 * Authentication: Bearer JWT session OR `x-api-key` (bs_...).
 * Per the plan (§6.1), API-key access is a Pro+ feature.
 */
export function buildAuthenticate(db: Database) {
  return async function authenticate(request: FastifyRequest): Promise<void> {
    const authHeader = request.headers.authorization;
    const apiKey = request.headers['x-api-key'];

    if (typeof apiKey === 'string' && apiKey.startsWith('bs_')) {
      const rec = await db.getApiKeyByHash(hashApiKey(apiKey));
      if (!rec || rec.revokedAt) {
        throw Object.assign(new Error('Invalid or revoked API key'), { statusCode: 401 });
      }
      const user = await db.getUserById(rec.userId);
      if (!user) throw Object.assign(new Error('Invalid API key'), { statusCode: 401 });
      if (!PLAN_QUOTAS[user.plan].apiAccess) {
        throw Object.assign(new Error('API access requires the Pro plan or higher'), {
          statusCode: 403,
        });
      }
      await db.touchApiKey(rec.id).catch(() => undefined);
      request.user = { id: user.id, email: user.email, plan: user.plan, viaApiKey: true };
      return;
    }

    if (authHeader?.startsWith('Bearer ')) {
      const claims = verifySession(authHeader.slice(7));
      if (!claims) throw Object.assign(new Error('Invalid or expired token'), { statusCode: 401 });
      const user = await db.getUserById(claims.sub);
      if (!user) throw Object.assign(new Error('User not found'), { statusCode: 401 });
      request.user = { id: user.id, email: user.email, plan: user.plan, viaApiKey: false };
      return;
    }

    throw Object.assign(new Error('Authentication required (Bearer token or x-api-key)'), {
      statusCode: 401,
    });
  };
}

export function requireUser(request: FastifyRequest): AuthenticatedUser {
  if (!request.user) throw Object.assign(new Error('Authentication required'), { statusCode: 401 });
  return request.user;
}
