# BugSeek AI — Backend (Phase 2)

Fastify + TypeScript API server, BullMQ/Redis scan job queue (with in-process
fallback), provider-agnostic LLM interface, and the AI agent engine
(**PLAN → ACT → OBSERVE → REFLECT**). PostgreSQL schema is Supabase-compatible.

> **Legal guardrails are first-class features** (product plan §8): explicit
> authorization verification before any active testing, scope enforcement on
> every active request, rate limiting on all active requests, SSRF protection,
> and redaction of sensitive data before persistence. See `docs/api.md`
> ("Legal guardrails") and the `src/guardrails/` code comments.

## Prerequisites

- Node.js 20+ (tested on Node 24)

Optional (production):
- Redis (or managed, e.g. Upstash) — otherwise an in-process memory queue is used
- PostgreSQL — a Supabase project's connection string works; otherwise an
  in-memory store is used (data lost on restart)
- Anthropic API key — otherwise the deterministic mock LLM provider is used

## Setup

```bash
cd ~/workspace/bugseek/backend
npm install          # note: if you hit EPERM on chown (some filesystems),
                     # retry with: npm install --no-bin-links --unsafe-perm
cp .env.example .env # then fill in values (never commit .env)
```

### Environment variables (see `.env.example`)

| Var | Required | Default | Purpose |
|---|---|---|---|
| `PORT` | no | `3000` | API listen port |
| `JWT_SECRET` | prod only | dev default + warning | Session token signing |
| `LLM_PROVIDER` | no | `gemini` | `gemini` (Google AI, default), `claude`, or `mock`. Without `GEMINI_API_KEY`, falls back to `mock` with a warning |
| `GEMINI_API_KEY` | for live Gemini | — | **Env var only. Never hardcode, never commit.** |
| `GEMINI_ROUTINE_MODEL` | no | `gemini-3.8-flash` | Flash-class model for high-volume routine calls (test planning) |
| `GEMINI_REASONING_MODEL` | no | `gemini-3.1-pro-preview` | Pro-class model for complex reasoning (reflection, severity, honeypot adjudication) |
| `ANTHROPIC_API_KEY` | when `LLM_PROVIDER=claude` | — | **Env var only. Never hardcode, never commit.** |
| `ANTHROPIC_MODEL` | no | `claude-sonnet-4-5` | Model for the Claude provider |
| `DATABASE_URL` | no | in-memory | Postgres connection string (Supabase: Project Settings → Database → URI). Apply `migrations/*.sql` via the Supabase SQL editor first |
| `REDIS_URL` | no | in-process queue | Redis URL for BullMQ (production job durability) |
| `AGENT_MAX_ACTIONS` | no | `40` | Max agent loop iterations per scan |
| `AGENT_MAX_DURATION_MIN` | no | `15` | Max agent wall-clock time per scan |
| `AGENT_REQUESTS_PER_SECOND` | no | `2` | Throttle for ALL active requests (hard cap 10) |
| `ALLOW_PRIVATE_TARGETS` | no | `false` | Allow RFC1918/localhost targets (local test apps like Juice Shop/DVWA). **Must stay false in production** |
| `API_RATE_LIMIT_PER_MIN` | no | `120` | Per-IP API rate limit |
| `CORS_ORIGIN` | no | `*` | CORS origin for the API |

## Run

```bash
npm run dev    # tsx watch — zero infrastructure needed (memory DB + queue + mock LLM)
npm run build  # tsc → dist/
npm start      # node dist/index.js
npm run smoke  # full in-process smoke test (no network, no paid APIs)
```

Health check: `GET http://localhost:3000/health`

## Project layout

```
backend/
├── migrations/001_init.sql      # Supabase/PostgreSQL schema (users, api_keys,
│                                #   authorizations, scans, findings, usage_events)
├── scripts/smoke.ts             # in-process smoke test (mock LLM, stub tools)
└── src/
    ├── index.ts                 # entrypoint: wire DB → queue → LLM → orchestrator → API
    ├── server.ts                # Fastify app builder (CORS, rate limit, error shape)
    ├── config.ts                # env config + validation (fails fast on bad/missing secrets)
    ├── types.ts                 # Scan, Finding, ScopePolicy, … (backward-compat w/ Phase 1)
    ├── db/db.ts                 # Database interface; MemoryDatabase (default) +
    │                            #   PostgresDatabase (lazy pg, Supabase-compatible)
    ├── auth/                    # bcrypt passwords, JWT sessions, API keys (hash-only storage)
    │   ├── auth.ts
    │   └── usage.ts             # plan tiers: free/hunter/pro/enterprise quotas
    ├── guardrails/              # ← plan §8, enforced in code
    │   ├── authorization.ts     # explicit authorization verification + audit record
    │   ├── scope.ts             # scope policy + per-request checks + SSRF guard
    │   ├── ratelimit.ts         # token-bucket throttle for active requests
    │   └── redact.ts            # secret/PII redaction before persistence
    ├── queue/queue.ts           # JobQueue interface; BullMQ+Redis or in-process fallback
    ├── llm/
    │   ├── provider.ts          # LLMProvider interface (swappable)
    │   ├── claude.ts            # Anthropic Messages API (key from env only)
    │   ├── mock.ts              # deterministic stub for tests/dev (no network)
    │   └── index.ts             # createLLMProvider() from LLM_PROVIDER
    ├── agent/
    │   ├── tools.ts             # guardrailed tools: fetch_url, check_security_headers,
    │                            #   probe_cors, probe_reflected_xss, inspect_cookies
    │   └── engine.ts            # PLAN → ACT → OBSERVE → REFLECT loop
    ├── orchestrator/
    │   └── orchestrator.ts      # scan state machine (queued→running→paused→completed/failed)
    │                            #   + progress events + quota/plan enforcement
    ├── reports/
    │   ├── cvss.ts              # CVSS v3.1 base-score estimates (labeled as estimates)
    │   ├── pdf.ts               # pdfkit report
    │   ├── docx.ts              # docx report
    │   └── markdown.ts          # markdown report
    ├── routes/                  # health, auth, scans, findings, reports
    └── middleware/auth.ts       # Bearer JWT or x-api-key (Pro+)
```

## API contract & schemas

- `../docs/api.md` — endpoints, auth, plan quotas, guardrails (the extension calls this)
- `../docs/schemas.md` — canonical Finding / Scan / Report JSON schemas

## Applying migrations to Supabase

1. Supabase Dashboard → your project → **SQL Editor** → New query
2. Paste `migrations/001_init.sql` → Run
3. Project Settings → Database → copy the **Connection string (URI)** into `DATABASE_URL`

The backend never needs the Supabase anon key — it connects directly to Postgres.

## Notes & limitations

- **In-memory mode is not durable**: scans, findings, and users vanish on restart.
  Use Postgres + Redis for anything beyond local dev.
- **The mock LLM is deterministic, not intelligent**: it follows fixed rules so
  tests are reproducible. Live reasoning comes from `LLM_PROVIDER=gemini`
  (default when `GEMINI_API_KEY` is set) or `claude`. Tiered routing keeps
  costs down: `GEMINI_ROUTINE_MODEL` (Flash-class) handles high-volume planning
  calls, `GEMINI_REASONING_MODEL` (Pro-class) handles reflection and severity
  judgment.
- **CVSS scores are estimates** (severity+category → v3.1 formula), always labeled
  as such; a human must validate before bounty submission.
- **Findings flagged `honeypotSuspect`** (trap probability ≥ 0.6) are shown as
  possible traps, not confirmed vulnerabilities.
- No Stripe billing yet (Phase 3); plan upgrades are currently manual
  (`db.setUserPlan` / SQL `UPDATE users SET plan = 'hunter' WHERE …`).
