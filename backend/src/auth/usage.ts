import type { PlanTier } from '../types.js';

/**
 * Plan tiers per the product plan (§6.1) and business plan (§3, credit-metered).
 * Quotas are enforced at scan creation; feature gating (active testing, API
 * access, report formats) is enforced on the relevant endpoints.
 *
 * Credits are the billing unit: 1 credit = one passive recon scan,
 * 25 credits = one guided active agent scan. This protects margin — an
 * active scan costs ~65x a passive one in LLM spend (business plan §3.1).
 */
export interface PlanQuota {
  creditsPerMonth: number; // Infinity = unlimited
  activeTesting: boolean;
  apiAccess: boolean;
  reportFormats: Array<'md' | 'json' | 'pdf' | 'docx'>;
}

/** Credits consumed by one scan of the given mode. */
export const SCAN_CREDIT_COST = { passive: 1, active: 25 } as const;

export const PLAN_QUOTAS: Record<PlanTier, PlanQuota> = {
  free: {
    creditsPerMonth: 50,
    activeTesting: false,
    apiAccess: false,
    reportFormats: ['md', 'json'],
  },
  hunter: {
    creditsPerMonth: 300,
    activeTesting: true,
    apiAccess: false,
    reportFormats: ['md', 'json', 'pdf', 'docx'],
  },
  pro: {
    creditsPerMonth: 1500,
    activeTesting: true,
    apiAccess: true,
    reportFormats: ['md', 'json', 'pdf', 'docx'],
  },
  enterprise: {
    creditsPerMonth: Number.POSITIVE_INFINITY,
    activeTesting: true,
    apiAccess: true,
    reportFormats: ['md', 'json', 'pdf', 'docx'],
  },
};

export function monthStartIso(now: Date = new Date()): string {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString();
}
