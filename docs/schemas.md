# BugSeek AI — Canonical JSON Schemas

These are the shared data contracts between the extension (Phase 1 + Phase 2)
and the backend. **Backward-compatibility rule:** fields may be ADDED, but
existing fields must never be renamed, removed, or have their meaning changed.
The extension sibling may extend these schemas; new fields must be optional.

Conventions: `id` = UUID string; timestamps = ISO 8601 strings;
`severity` ∈ `critical|high|medium|low|info`; `confidence` ∈ `high|medium|low`.

## Finding

Superset of the Phase 1 extension `Finding` (`bugseek/src/lib/types.ts`).
Phase 1 fields keep their names/meaning; backend-only fields are marked ★.

```jsonc
{
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "scanId": "…",                       // ★ backend: parent scan
  "category": "secrets",               // Phase 1: secrets|cookies|headers|tech|dom|sinks
                                       // ★ active: network|cors|api|xss|idor|auth|graphql|chain
  "title": "Exposed AWS key in JS bundle",
  "description": "…",
  "severity": "critical",
  "confidence": "high",
  "location": "https://target.com/app.js",  // optional; redacted
  "evidence": "const k = \"[REDACTED:aws-key]\";",  // optional; REDACTED + truncated (≤500 chars)
  "remediation": "…",

  // ★ backend additions (all optional for submitters):
  "cvssScore": 9.1,                    // ★ CVSS v3.1 base-score ESTIMATE (see below)
  "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  // ★
  "trapProbability": 0.05,             // ★ 0..1 honeypot/trap suspicion
  "honeypotSuspect": false,            // ★ true when trapProbability >= 0.6 → "possible trap, verify manually"
  "reproSteps": ["1. …", "2. …"],      // ★
  "references": ["https://owasp.org/…"], // ★
  "createdAt": "2026-10-01T00:00:00.000Z" // ★
}
```

### CVSS note
`cvssScore`/`cvssVector` are **heuristic estimates** computed from severity +
category via the official CVSS v3.1 base-score formula (`backend/src/reports/cvss.ts`),
clamped to the severity band. They are labeled "(estimate)" in every report and
must be validated by a human analyst before bounty submission.

### Evidence redaction contract
`evidence` and `location` **must never contain** raw secrets, tokens,
credentials, PII, or financial data. The backend enforces this with
`redactFindingEvidence()` (patterns: AWS keys, private keys, bearer tokens,
JWTs, `sk_live`/`pk_live` keys, `password=…` assignments, card numbers, emails,
phones) and truncates to 500 chars. The extension should redact client-side
too; the server re-redacts regardless.

## Scan

```jsonc
{
  "id": "…",
  "userId": "…",
  "targetUrl": "https://target.com/",
  "mode": "passive" | "active",
  "status": "queued" | "running" | "paused" | "completed" | "failed" | "cancelled",
  "scope": {
    "mode": "full-domain" | "subdomain" | "page",
    "includeSubdomains": true,
    "excludedHosts": [],
    "excludedPaths": ["/logout"],
    "maxRequestsPerSecond": 2
  },
  "authorizationId": "…",              // set for active scans (plan §8 audit trail)
  "techStack": [{ "name": "nginx", "version": "1.25" }],
  "progress": { "completedSteps": 3, "totalSteps": 5, "currentStep": "Running: Probe CORS policy" },
  "error": null,                       // set when status=failed
  "createdAt": "…", "startedAt": "…", "finishedAt": "…"
}
```

Valid status transitions: `queued→running|cancelled`,
`running→paused|completed|failed|cancelled`, `paused→running|cancelled`,
`failed|cancelled→queued` (retry).

## ScanProgressEvent (polling)

```jsonc
{ "seq": 12, "at": "2026-10-01T00:00:00.000Z",
  "kind": "status" | "step" | "finding" | "log" | "guardrail",
  "message": "Running: Probe CORS policy",
  "data": { } }
```
Poll `GET /api/scans/:id/progress?since=<latestSeq>`. `guardrail` events record
blocked actions (out-of-scope attempts, rate-limit waits are silent).

## Report (JSON format)

```jsonc
{ "scan": { /* Scan */ }, "findings": [ /* Finding */ ] }
```
PDF/DOCX/Markdown reports render the same data: cover (target, mode, scan ID,
authorization record), executive summary with severity breakdown + trap warning,
findings sorted by severity (title, severity, CVSS estimate + vector,
honeypot warning if flagged, description, location, redacted evidence,
reproduction steps, remediation, references), and a methodology/legal appendix.

## Authorization record (stored with active scans)

```jsonc
{ "id": "…", "userId": "…",
  "type": "bug-bounty" | "pentest-contract" | "ownership",
  "programName": "Acme Bug Bounty", "referenceUrl": "https://…",
  "statement": "I confirm …", "confirmedAt": "…" }
```

---

## Appendix E — Extension-side additions (Worker 3, Phase 2 active testing)

The extension (`bugseek/src/lib/types.ts`) keeps every field above with the
same names and meaning, and adds the following OPTIONAL fields. They are
extension-side only unless the backend adopts them.

### Finding — extension additions

| Field | Type | Meaning |
|---|---|---|
| `mode` | `'passive' \| 'active'` | Which scan produced the finding (default `'passive'`). |
| `tags` | `string[]` | Machine tags for attack-chain matching; see vocabulary below. |
| `cvssJustification` | `string` | Human-readable reason for the chosen CVSS metrics. |
| `trapSignals` | `string[]` | Signals that contributed to `trapProbability`. |
| `confirmed` | `boolean` | `true` = confirmed by observation (e.g. payload execution seen in the DOM); `false` = review hint, not a vulnerability. |
| `attackChainIds` | `string[]` | IDs of attack chains this finding participates in. |
| `requestCount` | `number` | Active HTTP requests spent to produce this finding (accountability). |

Extension `Finding.category` additions: `network` · `cors` · `api` · `xss` ·
`idor` · `auth` · `graphql` · `chain`.

### Deep Inspect (extension, active scans)

Opt-in devtools-level traffic visibility via `chrome.debugger` (CDP). The
`debugger` permission is OPTIONAL in the manifest and is requested at runtime
only when the user ticks "Deep inspect" — never at install time. Attach
happens only after a valid authorization record exists, and only on the
single target tab.

```jsonc
{
  "deepInspect": true,          // RUN_ACTIVE_SCAN message flag; default false
  "capturedBodies": [           // in-memory only, dropped on detach
    {
      "url": "https://target.com/api/users",
      "method": "GET",
      "status": 200,
      "mimeType": "application/json",
      "text": "…truncated body text…",  // ≤200,000 chars per body
      "truncated": true
    }
  ]
}
```

Safety contract (enforced in `src/active/deepInspect.ts`):

- Bodies captured ONLY for in-scope URLs, only for text-ish content types,
  capped at **40 bodies** and **200,000 chars per body**.
- Raw bodies live in memory for the scan duration and are dropped on detach.
  Only redacted snippets ever reach findings; raw bodies are never written to
  storage or reports.
- The session ALWAYS detaches: on scan end (`finally`), on tab close, on
  navigation-triggered detach, when the user opens DevTools, or if DOM
  collection fails before the main scan block.
- UX: Chrome shows a "…is debugging this browser" infobar while attached;
  attach fails while DevTools is already open on the same tab.

### Tag vocabulary (`src/lib/attackChains.ts`)

- CORS: `cors-creds`, `cors-wildcard`, `cors-reflected`, `cors-null`, `cors-reflected-open`, `cors-wildcard-observed`
- XSS: `xss-confirmed`, `xss-hint`, `xss`
- API: `api-endpoint`, `api-admin`, `api-docs`
- GraphQL: `graphql-introspection`, `graphql-mutation-dangerous`, `graphql-batching`, `graphql-endpoint`
- IDOR: `idor-enumerable`, `idor-pii-fields`, `idor-unguessable`, `idor`
- Auth: `auth`, `default-creds`, `default-creds-rejected`, `auth-anomaly`, `auth-login-form`, `auth-jwt-cookie`, `auth-probes-skipped`, `auth-no-form`, `no-bruteforce-protection`, `bruteforce-protected`
- Network: `sensitive-query-param`, `mixed-content`, `unusual-method`, `auth-header-usage`

### AuthorizationRecord — extension additions

Stored per target host in `chrome.storage.local` under `authz:<host>`.
No active request is sent before a record exists.

| Field | Type | Meaning |
|---|---|---|
| `targetHost` | `string` | Host the grant applies to (subdomains per scope). |
| `scope` | `ScopePolicy` | Same shape as the Scan `scope` above. |
| `allowAuthProbes` | `boolean` | SEPARATE grant for login-form testing (default credentials, brute-force checks). Never implied by the base grant. |
| `rateLimitMs` | `number` | Minimum gap between active requests (default 1500, floor 250). |

### AttackChain (extension; mirrored to backend via `/api/v1/chains/analyze`)

| Field | Type | Meaning |
|---|---|---|
| `id` | `string` | `chain-<pattern>-<seq>` |
| `title` / `description` / `impact` | `string` | Human-readable narrative. |
| `findingIds` | `string[]` | Ordered member finding IDs. |
| `severity` | `Severity` | Max member severity, floored at the pattern minimum. |
| `confidence` | `'high' \| 'medium' \| 'low'` | Pattern confidence. |
| `cvssScore?` | `number` | Highest member CVSS. |
| `aiDeepened?` | `boolean` | True after the backend AI agent verified/deepened the chain. |

### ScanResult — extension additions

| Field | Type | Meaning |
|---|---|---|
| `mode?` | `ScanMode` | `'passive'` (default) or `'active'`. |
| `chains?` | `AttackChain[]` | Attack chains (active scans). |
| `authorization?` | `AuthorizationRecord` | Snapshot of the grant used (active scans). |
| `activeStats?` | `ActiveScanStats` | `requestsMade`, `throttledMs`, `maxRequests`, `rateLimitMs`, `backendReachable`, `backendDeepened`. |

### ScanMessage additions (popup ↔ background ↔ content script)

- `{ type: 'RUN_ACTIVE_SCAN'; tabId: number }`
- `{ type: 'ACTIVE_PROGRESS'; step; requestsMade; rateLimitMs; nextRequestInMs }`
- `{ type: 'ACTIVE_DONE'; result: ScanResult }`
- `{ type: 'ACTIVE_ERROR'; error: string }`
- `{ type: 'XSS_PROBE'; url: string; marker: string }` (background → content script; response `{ ok, executed?, error? }`)

### Extension redaction conventions (in addition to the contract above)

- 8-char prefix convention from `src/lib/regexes.ts` (`redactSecret`) applies to all evidence, including active findings (`httpClient.redactedSnippet`).
- Traffic capture stores parameter NAMES only — never values; request/response bodies are never stored.
- IDOR evidence lists JSON field names only, never values.
- Default-credential findings name the well-known pair (e.g. `admin/admin`) because the pair itself is the vulnerability; these are public wordlist entries, not private credentials.
