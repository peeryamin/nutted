-- BugSeek AI — initial schema (Supabase-compatible PostgreSQL)
--
-- How to apply to a Supabase project:
--   1. Supabase Dashboard → your project → SQL Editor → New query
--   2. Paste this entire file and Run.
--   3. Set DATABASE_URL in the backend .env to the connection string from
--      Project Settings → Database → Connection string (URI).
--
-- The backend also runs fully without a database (in-memory mode) when
-- DATABASE_URL is unset — data is lost on restart in that mode.

-- Enable pgcrypto for gen_random_uuid() (usually already enabled on Supabase)
create extension if not exists "pgcrypto";

-- ── Users ────────────────────────────────────────────────────────────────
create table if not exists users (
  id            uuid primary key default gen_random_uuid(),
  email         text not null unique,
  password_hash text not null,
  plan          text not null default 'free'
                check (plan in ('free', 'hunter', 'pro', 'enterprise')),
  created_at    timestamptz not null default now()
);
create index if not exists users_email_idx on users (email);

-- ── API keys (only SHA-256 hashes stored; raw key shown once at creation) ─
create table if not exists api_keys (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references users (id) on delete cascade,
  name        text not null,
  key_hash    text not null unique,
  key_prefix  text not null,
  created_at  timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at  timestamptz
);
create index if not exists api_keys_user_idx on api_keys (user_id);
create index if not exists api_keys_hash_idx on api_keys (key_hash);

-- ── Authorization records (plan §8: auditable proof of authorization) ─────
create table if not exists authorizations (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null references users (id) on delete cascade,
  type          text not null check (type in ('bug-bounty', 'pentest-contract', 'ownership')),
  program_name  text,
  reference_url text,
  statement     text not null,
  confirmed_at  timestamptz not null default now()
);
create index if not exists authorizations_user_idx on authorizations (user_id);

-- ── Scans ────────────────────────────────────────────────────────────────
create table if not exists scans (
  id               uuid primary key default gen_random_uuid(),
  user_id          uuid not null references users (id) on delete cascade,
  target_url       text not null,
  mode             text not null check (mode in ('passive', 'active')),
  status           text not null default 'queued'
                   check (status in ('queued', 'running', 'paused', 'completed', 'failed', 'cancelled')),
  scope            jsonb not null,
  authorization_id uuid references authorizations (id),
  tech_stack       jsonb not null default '[]'::jsonb,
  progress         jsonb not null default '{"completedSteps":0,"totalSteps":0}'::jsonb,
  error            text,
  created_at       timestamptz not null default now(),
  started_at       timestamptz,
  finished_at      timestamptz
);
create index if not exists scans_user_idx on scans (user_id, created_at desc);
create index if not exists scans_status_idx on scans (status);

-- ── Findings (evidence column holds REDACTED snippets only — plan §8) ─────
create table if not exists findings (
  id               uuid primary key default gen_random_uuid(),
  scan_id          uuid not null references scans (id) on delete cascade,
  category         text not null,
  title            text not null,
  description      text not null,
  severity         text not null check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  cvss_score       numeric,
  cvss_vector      text,
  confidence       text not null check (confidence in ('high', 'medium', 'low')),
  trap_probability numeric not null default 0,
  honeypot_suspect boolean not null default false,
  location         text,
  evidence         text,  -- REDACTED before persistence; never raw secrets
  repro_steps      text[] not null default '{}',
  remediation      text not null default '',
  "references"     text[] not null default '{}',
  created_at       timestamptz not null default now()
);
create index if not exists findings_scan_idx on findings (scan_id);

-- ── Usage events (scan counts per plan tier, LLM calls, reports) ──────────
create table if not exists usage_events (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references users (id) on delete cascade,
  kind       text not null,  -- 'scan' | 'llm_call' | 'report'
  quantity   integer not null default 1,
  scan_id    uuid references scans (id) on delete set null,
  created_at timestamptz not null default now()
);
create index if not exists usage_events_user_idx on usage_events (user_id, kind, created_at);

-- ── Optional Row Level Security ──────────────────────────────────────────
-- The backend uses the service_role key (bypasses RLS). If you also expose
-- these tables to anon/authenticated clients, uncomment and adapt:
--
-- alter table users enable row level security;
-- alter table scans enable row level security;
-- alter table findings enable row level security;
-- create policy "own rows" on scans for all using (auth.uid() = user_id);
