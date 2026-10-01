import { z } from 'zod';
import type { Database } from '../db/db.js';
import type { AuthorizationRecord, AuthzType } from '../types.js';

/**
 * LEGAL GUARDRAIL — explicit authorization verification (product plan §8).
 *
 * Before ANY active testing, the user must confirm they have authorization
 * via a bug bounty program, pentest contract, or target ownership. The
 * confirmation is stored as an authorization record linked to the scan, so
 * there is an auditable trail of WHO authorized WHAT and WHEN.
 */

export const authorizationInputSchema = z.object({
  type: z.enum(['bug-bounty', 'pentest-contract', 'ownership']),
  programName: z.string().max(200).optional(),
  referenceUrl: z.string().url().max(500).optional(),
  statement: z
    .string()
    .min(20, 'Please describe your authorization (min 20 characters)')
    .max(2000),
  confirmed: z.literal(true, {
    errorMap: () => ({ message: 'You must explicitly confirm you are authorized to test this target' }),
  }),
});

export type AuthorizationInput = z.infer<typeof authorizationInputSchema>;

/**
 * Validate + persist an authorization record for an active scan.
 * Throws (400) if the confirmation is missing/invalid.
 */
export async function verifyAndRecordAuthorization(
  db: Database,
  userId: string,
  raw: unknown
): Promise<AuthorizationRecord> {
  const parsed = authorizationInputSchema.safeParse(raw);
  if (!parsed.success) {
    throw Object.assign(
      new Error(`Authorization required for active testing: ${parsed.error.issues[0]?.message}`),
      { statusCode: 400 }
    );
  }
  const input = parsed.data;
  return db.createAuthorization({
    userId,
    type: input.type as AuthzType,
    programName: input.programName,
    referenceUrl: input.referenceUrl,
    statement: input.statement,
  });
}
