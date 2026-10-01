# BugSeek AI — API Contract (Backend ↔ Extension)

Base URL: `http://localhost:3000` (dev) — configurable via `PORT`.
All request/response bodies are JSON unless noted. Errors: `{ "error": "<message>" }`
with an appropriate HTTP status code.

## Authentication

Two schemes (both attach `request.user = { id, email, plan }`):

| Scheme | Header | Notes |
|---|---|---|
| Session JWT | `Authorization: Bearer <token>` | From `POST /api/auth/register` or `/login`. 7-day expiry. |
| API key | `x-api-key: bs_<secret>` | Pro+ plans only. Raw key shown **once** at creation; only a SHA-256 hash is stored. |

## Endpoints

### Health

`GET /health` → `200`
```json
{ "status": "ok", "version": "0.2.0", "db": "memory|postgres", "queue": "memory|bullmq", "llm": "gemini|claude|mock", "time": "2026-10-01T00:00:00.000Z" }
```

### Auth

`POST /api/auth/register` — body `{ "email": string, "password": string(min 8) }` → `201 { user, token }`
`POST /api/auth/login` — body `{ email, password }` → `200 { user, token }`
`GET /api/auth/me` 🔒 → `200 { user }`
`POST /api/auth/api-keys` 🔒 — body `{ "name" }` → `201 { id, name, keyPrefix, key, createdAt }` (`key` returned once)
`GET /api/auth/api-keys` 🔒 → `200 { keys: [{ id, name, keyPrefix, createdAt, lastUsedAt, revokedAt }] }` (hashes never exposed)
`DELETE /api/auth/api-keys/:id` 🔒 → `200 { revoked: true }`

`user = { id, email, plan: "free"|"hunter"|"pro"|"enterprise", createdAt }`

### Scans

`POST /api/scans` 🔒 — create a scan (validates guardrails, quota, then enqueues)```jsonc
{
  "targetUrl": "https://target.com",
  "mode": "passive" | "active",
  "scope": {                       // optional; confirmed with the user in the extension UI
    "mode": "full-domain"|"subdomain"|"page",   // default "full-domain"
    "includeSubdomains": true,                 // default true
    "excludedHosts": ["static.target.com"],    // default []
    "excludedPaths": ["/logout"],              // default []
    "maxRequestsPerSecond": 2                  // default from server config, hard cap 10
  },
  // REQUIRED for mode=active (plan §8 — explicit authorization):
  "authorization": {
    "type": "bug-bounty" | "pentest-contract" | "ownership",
    "programName": "Acme Bug Bounty",          // optional
    "referenceUrl": "https://hackerone.com/acme", // optional
    "statement": "I am authorized to test ... (min 20 chars)",
    "confirmed": true                          // must be literally true
  },
  "techStack": [{ "name": "React", "version": "18" }]  // optional, from extension fingerprinting
}
```
→ `201 { scan }`. Guardrail failures: `400` (missing/invalid authorization),
`403` (active testing on Free plan, or out-of-scope target), `429` (monthly credit quota exceeded).

`GET /api/scans?limit=20&offset=0` 🔒 → `200 { scans: [...], total }`
`GET /api/scans/:id` 🔒 → `200 { scan }` (`404` if not yours)

`GET /api/scans/:id/progress?since=0` 🔒 — poll progress events
```jsonc
{
  "scanId": "...", "status": "running",
  "progress": { "completedSteps": 3, "totalSteps": 5, "currentStep": "Running: Probe CORS policy" },
  "events": [{ "seq": 12, "at": "...", "kind": "status|step|finding|log|guardrail", "message": "...", "data": {} }],
  "latestSeq": 12
}
```
The extension polls with `since=<latestSeq>` (e.g. every 2s) for live updates.

`POST /api/scans/:id/pause` 🔒 → `200 { scan }` (running → paused; agent finishes current action then waits)
`POST /api/scans/:id/resume` 🔒 → `200 { scan }` (paused → running)
`POST /api/scans/:id/cancel` 🔒 → `200 { scan }` (→ cancelled; agent aborts)
`POST /api/scans/:id/retry` 🔒 → `200 { scan }` (failed/cancelled → queued again)

### Swarm (multi-agent "super agent")

`POST /api/swarm/scans` 🔒 — run the head agent + specialist worker swarm
inline (bounded by `timeoutMinutes`). Same lifecycle as ordinary scans:
**authorization record required**, **25 credits** charged (active-scan cost),
findings persisted, scan marked `completed`/`failed`. Requires Hunter+.
```jsonc
{
  "targetUrl": "https://target.com",
  "authorization": { /* REQUIRED — same shape as POST /api/scans mode=active */ },
  "scope": { "mode": "subdomain", "includeSubdomains": false, "excludedHosts": [], "excludedPaths": [] },
  "specialists": ["recon", "headers"],  // optional; omit for adaptive selection
  "maxWorkers": 4, "concurrency": 2,    // optional
  "requestsPerSecond": 2,               // optional, hard cap 5
  "maxTokens": 100000,                  // optional, global token budget
  "timeoutMinutes": 10,                 // optional, hard cap 20
  "allowPrivateTargets": false          // optional; true for local labs only
}
```
→ `200 { scanId, targetUrl, headSummary, findings, workerReports, testsRun, llmCalls, tokensUsed, durationMs, errors }`.
Findings are CVSS-scored and re-redacted server-side before persistence.

Invalid transitions → `409` (e.g. pausing a completed scan).

### Findings

`GET /api/scans/:id/findings` 🔒 → `200 { scanId, findings: [Finding...] }`
(see `docs/schemas.md` for the Finding schema)

`POST /api/scans/:id/findings` 🔒 — extension submits its Phase 1 passive findings
(scan must be `queued`, `running`, or `paused`; completed scans → `409`).
```jsonc
{
  "category": "secrets", "title": "...", "description": "...",
  "severity": "critical", "confidence": "high",
  "location": "https://target.com/app.js",       // optional
  "evidence": "const k = \"AKIA...\";",           // optional — REDACTED server-side before storage
  "remediation": "...", "reproSteps": ["..."], "references": ["https://..."],
  "trapProbability": 0                            // optional, 0..1
}
```
→ `201 { finding }`. The server re-redacts `evidence`/`location` (secrets, tokens,
PII → `[REDACTED:<kind>]`), attaches a CVSS v3.1 estimate, and flags
`trapProbability >= 0.6` as `honeypotSuspect`.

### Reports

`GET /api/scans/:id/report?format=pdf|docx|md|json` 🔒 → file download
(`Content-Disposition: attachment`). Only for `completed` scans (`409` otherwise).
Format availability follows the plan tier: Free → `md`, `json`; Hunter+ → all four.

🔒 = requires authentication.

## Plan tiers & quotas (enforced server-side)

Credit-metered per the business plan (§3): **1 credit = one passive recon
scan, 25 credits = one guided active agent scan.** Unused credits expire
monthly (no rollover); overage $5 per 100 credits (Hunter/Pro).

| Tier | Credits/month | Active testing | API keys | Report formats |
|---|---|---|---|---|
| free | 50 | ❌ | ❌ | md, json |
| hunter ($29) | 300 | ✅ | ❌ | all |
| pro ($99) | 1,500 | ✅ | ✅ | all |
| enterprise | custom pools | ✅ | ✅ | all |

## Legal guardrails (plan §8) — enforced, not advisory

1. **Authorization**: `mode=active` requires an explicit, stored authorization
   record (`type`, `statement`, `confirmed: true`). No record → no active scan,
   and the agent double-checks at runtime.
2. **Scope**: every active request is checked against the scan's scope policy
   (domains, subdomains, excluded paths/hosts). Out-of-scope → blocked + logged
   as a `guardrail` progress event. Redirects are re-checked.
3. **Rate limiting**: token-bucket throttling on all active requests
   (default 2 req/s, hard cap 10 req/s). Plus per-IP API rate limiting.
4. **SSRF protection**: target hosts resolving to private/internal IPs are
   refused unless `ALLOW_PRIVATE_TARGETS=true` (local test apps only; forbidden
   in production).
5. **No sensitive-data storage**: all finding evidence is redacted
   (secrets, tokens, credentials, PII, card numbers) before persistence.
