import { createHash, randomBytes } from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { config } from '../config.js';
import type { PlanTier } from '../types.js';

export interface SessionClaims {
  sub: string; // user id
  email: string;
  plan: PlanTier;
}

const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function signSession(user: { id: string; email: string; plan: PlanTier }): string {
  return jwt.sign(
    { email: user.email, plan: user.plan } as Omit<SessionClaims, 'sub'>,
    config.jwtSecret,
    { subject: user.id, expiresIn: TOKEN_TTL_SECONDS }
  );
}

export function verifySession(token: string): SessionClaims | null {
  try {
    const decoded = jwt.verify(token, config.jwtSecret) as jwt.JwtPayload & {
      email?: string;
      plan?: PlanTier;
    };
    if (!decoded.sub || !decoded.email || !decoded.plan) return null;
    return { sub: decoded.sub, email: decoded.email, plan: decoded.plan };
  } catch {
    return null;
  }
}

/**
 * API keys: the raw key is shown ONCE at creation. Only a SHA-256 hash is
 * stored server-side, so a database leak does not expose usable keys.
 */
export function generateApiKey(): { key: string; keyHash: string; keyPrefix: string } {
  const secret = randomBytes(32).toString('hex');
  const key = `bs_${secret}`;
  const keyHash = createHash('sha256').update(key).digest('hex');
  return { key, keyHash, keyPrefix: `bs_${secret.slice(0, 4)}` };
}

export function hashApiKey(key: string): string {
  return createHash('sha256').update(key).digest('hex');
}
