/**
 * Central configuration for BugSeek AI.
 *
 * The backend base URL is a single constant so the sibling backend worker
 * (~/workspace/bugseek/backend, Fastify, default port 3000) can be wired in
 * without touching call sites. The extension stays fully functional when the
 * backend is unreachable — every apiClient call degrades gracefully.
 */

/** Base URL of the BugSeek backend API (Fastify). Override per deployment. */
export const BACKEND_BASE_URL = 'http://localhost:3000';

/** Network timeout for backend API calls, ms. */
export const BACKEND_REQUEST_TIMEOUT_MS = 8000;

/** Default minimum gap between active requests (conservative). */
export const DEFAULT_ACTIVE_REQUEST_GAP_MS = 1500;

/** Hard floor for the gap — the UI refuses anything lower. */
export const MIN_ACTIVE_REQUEST_GAP_MS = 250;

/** Safety cap on active HTTP requests per scan (DoS guardrail, plan §8). */
export const MAX_ACTIVE_REQUESTS_PER_SCAN = 120;

/** Per-request timeout for active probes, ms. */
export const ACTIVE_FETCH_TIMEOUT_MS = 10000;

/**
 * Trap-probability at or above which a finding is flagged as a possible
 * honeypot and NOT reported as a vulnerability (matches backend contract).
 */
export const TRAP_FLAG_THRESHOLD = 0.6;

/** Max characters of (redacted) evidence kept per finding. */
export const EVIDENCE_MAX_CHARS = 500;

/**
 * Deep inspect mode (devtools-level capture via chrome.debugger).
 * Bodies are captured only for in-scope URLs with text-ish content types,
 * capped in count and bytes; raw bodies live in memory only and are dropped
 * on detach.
 */
/** Max response bodies captured per deep-inspect session. */
export const DEEP_INSPECT_MAX_BODIES = 40;
/** Max bytes kept per captured body (decoded, then truncated). */
export const DEEP_INSPECT_MAX_BODY_BYTES = 200_000;
/** Only these response MIME types are body-captured (text-ish). */
export const DEEP_INSPECT_BODY_CONTENT_RE =
  /^(application\/(json|.*\+json|javascript|x-javascript|xml|.*\+xml|graphql|x-www-form-urlencoded)|text\/)/i;

/** Storage keys. */
export const STORAGE_KEYS = {
  authzPrefix: 'authz:',
  activeScanPrefix: 'activeScan:',
  lastActiveResult: 'lastActiveResult',
} as const;
