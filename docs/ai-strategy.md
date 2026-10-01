**Date:** 2026-10-01
**Author:** Research worker (subagent)
**Updated:** 2026-10-01 — provider decision (see §0 below)
**Purpose:** (a) Document how Strix structures its AI backend, verified from its repo; (b) recommend a cost-vs-capability AI strategy for BugSeek given Peer's hard budget constraint.

> Conventions: prices marked **VERIFIED** were fetched live from official docs/APIs on 2026-10-01. Items marked **UNVERIFIED** could not be confirmed. Token counts and per-scan costs are the author's **ESTIMATES**, stated explicitly — they are model-of-the-world numbers, not vendor data.

---

## §0 — Provider decision: Google AI (Gemini) — Oct 2026 ✅ DECIDED

**Decision (Oct 2026): BugSeek's primary LLM provider is Google AI (the Gemini Developer API).** This replaces the earlier OpenRouter-default recommendation (which is **SUPERSEDED as the default** and retained in §B as an alternative/fallback provider — nothing else in this doc was deleted).

Why Gemini fits the student-budget constraint:

- **First-party pricing is now verified from Google's official docs** (closing the gap in §B.7 risk 5): https://ai.google.dev/gemini-api/docs/pricing. Canonical model IDs verified at https://ai.google.dev/gemini-api/docs/models (both pages last updated 2026-10-01 UTC).
- **The free tier** gives limited free input/output tokens on Flash models — ideal for dev and a metered free product tier (caveat: Google uses free-tier content to improve products; production scans must run on the paid tier).
- **Thinking/reasoning tokens are billed as output**, so keep thinking budgets tight on the agent loop.

### §0.1 Verified Gemini model lineup (official model IDs)

| Role in BugSeek | Model ID (VERIFIED) | Official description |
|---|---|---|
| **Agent / routine default (Tier 1+2 Flash workhorse)** | `gemini-3.8-flash` | "Our most intelligent Flash model, engineered for long-horizon software engineering, autonomous agents, and complex enterprise workflows." — Stable, New |
| **Flash fallback, same price** | `gemini-3.7-flash` | "previous-generation Flash model for complex coding, agentic workflows, and reliable multi-step execution." — Stable |
| **Flash fallback, same price** | `gemini-3.6-flash` | "previous-generation Flash model, balancing speed and multimodal capabilities across general agentic and everyday tasks." — Stable |
| **Ultra-cheap Tier-1 classifier** | `gemini-3.5-flash-lite` | Fast, budget-friendly Lite model — verified working Oct 2026 (exact official price UNVERIFIED; check the pricing page) |
| **Cheap Tier-1 / fallback agent** | `gemini-3.5-flash` ($1.50/$9.00, legacy) | Price-performance fallback for low-latency, high-volume tasks |
| **Strong reasoning (Pro-class, text agent)** | `gemini-3.1-pro-preview` | Complex reasoning, text, code, agentic workflows — 1M context |
| ~~**Strong reasoning fallback (cheaper)** | `gemini-2.5-pro`~~ | **DEPRECATED for new users** (API redirects to 3.x) — do not use |
| Also available | `gemini-3.1-flash-lite` ("frontier-class performance rivaling larger models at a fraction of the cost"), `gemini-3-flash-preview` | UNVERIFIED exact prices for the `-lite` entries on the official page; not load-bearing for this strategy |

### §0.2 Verified per-1M-token pricing (Google official pricing page, paid tier)

| Model | Input / 1M | Output / 1M | Context-cache read / 1M | Batch/Flex (50% off) |
|---|---|---|---|---|
| `gemini-3.8-flash` | **$0.75** through Dec 31, 2026; **$1.50** from Jan 1, 2027 | **$3.75** through 2026; **$7.50** from 2027 | $0.075 / $0.15 (+ $0.50/1M/hr storage through 2026) | $0.375 / $1.875 through 2026 |
| `gemini-3.7-flash` / `gemini-3.6-flash` | Same $0.75/$3.75 through 2026, then $1.50/$7.50 | | | Same |
| `gemini-2.5-flash-lite` | **$0.10** | **$0.40** | $0.01 | $0.05 / $0.20 | **DEPRECATED for new users** — reference only |
| `gemini-2.5-flash` | **$0.30** | **$2.50** | $0.03 | $0.15 / $1.25 | **DEPRECATED for new users** — reference only |
| `gemini-3.1-pro-preview` | **$2.00** | **$12.00** | — (UNVERIFIED: cache pricing for 3.1 Pro not isolated on the page) | $1.00 / $6.00 |
| `gemini-2.5-pro` | **$1.25** (≤200k ctx) / $2.50 (>200k) | **$10.00** (≤200k) / $15.00 (>200k) | $0.125 / $0.25 | $0.625 / $5.00 (≤200k) | **DEPRECATED for new users** — reference only |

Discounts (VERIFIED on the same page): **Batch API = 50% cost reduction** and **Flex tier = 50%** (both paid-tier, non-interactive workloads — ideal for offline re-triage of the finding backlog). Context caching: cache-read input at ~10% of the input price + $1.00/1M/hr storage. **Pricing cliff: the 3.x intro rates ($0.75/$3.75) double on Jan 1, 2027** — budget for $1.50/$7.50 in any plan that runs past December 2026. Source: https://ai.google.dev/gemini-api/docs/pricing

### §0.3 Gemini tier mapping for BugSeek

Keep the Strix-derived shape (§B.3) — same tiers, new model names:

- **Tier 0 — deterministic (no LLM), unchanged:** headers, cookie flags, TLS, regex secret detection, library-version → CVE lookup, DOM sink listing, subdomain enumeration. See §B.5 — nothing changes.
- **Tier 1 — cheap/high-volume:** `gemini-3.5-flash-lite` for secret triage, tech fingerprinting, dedup judge (Strix `STRIX_DEDUPE_MODEL` pattern), severity pre-scoring, honeypot-signal flagging. Use `gemini-3.8-flash` ($0.75/$3.75 intro) as the **default agent model** for the plan→act→observe loop in MVP/beta.
- **Tier 2 — strong reasoning:** `gemini-3.1-pro-preview` ($2.00/$12.00) only for attack-chain analysis, honeypot-vs-vuln judgment calls, exploit-validation planning, contextual severity — **escalation on low confidence only** (Tier-1 output carries a confidence score; below threshold → re-run the *same* question at Tier 2). Cheaper path: Batch/Flex 50% discount on the same model for offline work.
- **Routing hygiene, unchanged from §B.3:** every stage declares tier + max_cost_per_call; never silently upgrade tier on failure; one provider-agnostic gateway — route via LiteLLM with `gemini/` model IDs (LiteLLM pattern from §A.1), `GEMINI_API_KEY` default, OpenRouter kept as an alternate gateway (superseded as default).

### §0.4 Per-scan cost estimates (Gemini-first)

**Token assumptions (ESTIMATES, stated explicitly):** routine Tier-1 classification/triage calls ≈ **1–3k tokens** (avg 2k input / 0.5k output); agent turns ≈ **8k input / 1.5k output**; a deep agent run ≈ **30–50 turns** (modeled below at 40); a Pro-class reasoning turn ≈ **10k input / 2k output**.

| Scan type | Token shape (estimate) | Cost on Gemini |
|---|---|---|
| Passive recon scan (Tier 0 deterministic + ~15 triage calls ≈ 30k in / 7.5k out) | Lite triage | **~$0.01** on `gemini-2.5-flash-lite` (30k×$0.10/1M + 7.5k×$0.40/1M = $0.003+$0.003); ~$0.05 on `gemini-3.8-flash` |
| Deep scan, Flash-class only (40 turns ≈ 320k in / 60k out) | Default agent | **~$0.47** on `gemini-3.8-flash` ($0.24+$0.225); **~$0.25** on `gemini-2.5-flash` ($0.096+$0.15); ~$0.07 on Flash-Lite-only (capability caveat — keep off the agentic loop per §A.5) |
| Deep scan, Flash agent + Pro escalation (32 Flash turns + 8 Pro turns ≈ 256k+80k in / 48k+16k out) | Escalate on low confidence | **~$0.72** with `3.1-pro-preview` ($0.37 Flash + $0.35 Pro); **~$0.46** with `2.5-flash` + `2.5-pro` ($0.20 + $0.26) |

**Headline figures (intro pricing through Dec 2026):** passive scan **≈ $0.01**; deep scan on Flash-class **≈ $0.25–0.50**; deep scan with Pro-class escalation **≈ $0.45–0.75**. With Batch/Flex on offline re-triage, roughly halve those numbers. After Jan 1, 2027, the Flash-tier headline roughly doubles (3.x intro rate expires) — plan for ~$0.90–1.00 deep scans at standard rates. These are ESTIMATES; instrument the backend with Strix-style real cost capture (§A.4) and re-measure.

### §0.5 Default + fallback strategy (Gemini-first)

**MVP / beta (free tier, ship cheap):**
- Default agent: `gemini-3.8-flash`; triage/dedup: `gemini-2.5-flash-lite` (Strix `STRIX_DEDUPE_MODEL` pattern — separate model, same `GEMINI_API_KEY`). Blended estimate ≈ **$0.30–0.60 per deep scan**, ~$0.01 per passive scan.
- Free product tier = metered credits on **Google's free tier for dev/beta**, then paid-tier credits (e.g. 10 deep scans/month free ≈ $3–6/user — budget slightly above the old OpenRouter estimate because Gemini Flash is pricier than the cheapest OpenRouter weights; or fewer free scans). BYO Gemini API key removes the cap entirely — the Strix playbook.
- **Fallback on 429/5xx/timeout:** exponential backoff → cascade within tier (`3.8-flash` → `3.7-flash` → `3.6-flash`, all the same $0.75/$3.75 intro price) → degrade gracefully to Tier-1-only with "reduced confidence" labels. Escalate tier only on low-confidence findings — never auto-upgrade on failure. Batch/Flex for offline re-triage backlogs; OpenRouter as the alternate gateway if Google's API is down (superseded default, still configured).

**Paid scale (Hunter $29 / Pro $99 — tiers per the product plan §6.1):**
- Hunter $29: Tier-1 on Flash-Lite + agent on `3.8-flash` + Tier-2 escalation to `2.5-pro` ($1.25/$10) on low confidence; monthly AI budget ≈ $5–8/user → ~15–25 deep scans or ~1,000 passive scans. Scan-credit model.
- Pro $99: Tier-2 default `3.1-pro-preview` ($2/$12) for high-value targets, longer agent horizons, priority queueing; monthly AI budget ≈ $15–25/user.
- Both paid tiers: exact per-scan cost capture (LiteLLM provider-reported cost, like Strix's OpenRouter `usage.cost` capture), per-user monthly caps with 80%/100% alerts, batch API for offline re-triage (50% off).

### §0.6 Live verification findings (Oct 2026) — credential + model behavior

- **Credential verified working end-to-end via the vault** (no 401/403). Reusable CLI for tests: `~/workspace/skills/google-ai/bin/generate.py [--model MODEL] [--system TEXT] [PROMPT]` — authenticates through the stored vault credential, never a raw key. Backend e2e verification should use this CLI; keep real test calls minimal (1–2 per run) per Peer's budget.
- **Cheap default for tests: `gemini-3.5-flash-lite`** — fast (~1s response at verification). Use for dev/test loops and Tier-1 triage experiments.
- **`gemini-3.8-flash` and `gemini-flash-latest` returned 503 (high demand) at verification time** — treated as temporary capacity pressure, not a model problem. The in-tier cascade in §0.5 (`3.8` → `3.7` → `3.6`) exists precisely for this; retry with backoff before cascading.
- **2.5-series deprecation:** `gemini-2.5-flash` and `gemini-2.5-flash-lite` are **deprecated for new users** — the API redirects to 3.x equivalents. Do NOT set 2.5-series models as defaults for new deployments (including BugSeek). The $0.10/$0.40 `2.5-flash-lite` price in §0.2 is therefore not load-bearing for Peer; prefer `gemini-3.5-flash-lite` for the ultra-cheap tier (exact official price: verify at the pricing page and update this line).
- Net effect on §0.3/§0.5: Tier-1 = `gemini-3.5-flash-lite` (cheap default); remove 2.5-series from the recommended set for new users; agent default stays `gemini-3.8-flash` with the 3.7/3.6 cascade covering transient 503s.

---

## Part A — How Strix Uses AI

Source: `https://github.com/usestrix/strix` (v1.6.2, Apache-2.0), docs site `docs.strix.ai`. Files examined: `pyproject.toml`, `strix/config/models.py`, `strix/config/settings.py`, `strix/report/dedupe.py`, `strix/report/pricing.py`, `strix/llm/context_budget.py`, `AGENTS.md`, `docs/llm-providers/*.mdx`, `docs/quickstart.mdx`, `docs.strix.ai/llms.txt`.

### A.1 Provider-agnostic routing via LiteLLM

- Strix does **not** bind to one vendor. Core deps in `pyproject.toml`: `openai-agents[litellm]>=0.19.0,<0.20`, `openai>=2.45.0,<3`, `litellm>=1.101.0`. LiteLLM is the provider-compatibility layer ("supporting 100+ LLM providers" — `docs/llm-providers/overview.mdx`).
- Model selection is a single env var `STRIX_LLM` in LiteLLM `provider/model` format. A custom `StrixProvider` (a `MultiProvider`) routes "any non-OpenAI prefix through LiteLLM with the prefix preserved, so users type `deepseek/deepseek-chat` rather than `litellm/deepseek/deepseek-chat`" (`strix/config/models.py`).
- Supported providers include: OpenAI, Anthropic, DeepSeek, Moonshot, Google Vertex AI, AWS Bedrock, Azure OpenAI, **OpenRouter**, Novita AI, Vercel AI Gateway, Ollama, LM Studio/any OpenAI-compatible endpoint, plus OpenAI's ChatGPT-subscription backend ("codex") (`docs/llm-providers/*.mdx`; `models.py` `_CodexResponsesModel`).

### A.2 Default model: cheap via OpenRouter

- Quickstart (`docs/quickstart.mdx`): `export STRIX_LLM="openrouter/z-ai/glm-5.3"` — "For best results, use `openrouter/z-ai/glm-5.3` (the default pick), `openai/gpt-5.4`, `anthropic/claude-opus-4-6`, or `openai/gpt-5.2`."
- Provider overview table (`docs/llm-providers/overview.mdx`): "GLM-5.3 (default) | Z.ai (OpenRouter)".
- **Confirmed:** the quickstart default routes through **OpenRouter to Z.ai's GLM-5.3** — a cost-conscious, provider-agnostic default. Live OpenRouter pricing (VERIFIED via `openrouter.ai/api/v1/models`, 2026-10-01): `z-ai/glm-5.3` ≈ **$0.22 / $3.39** per 1M input/output tokens. Compare: OpenRouter lists OpenAI `gpt-5.4` at $2.50/$15.00 — the default is ~10× cheaper on input.

### A.3 Two-tier model routing (the key pattern to copy)

Strix does **not** run everything through one model. It supports a **secondary model for the dedupe judge**:

- `DedupeSettings.model` (`STRIX_DEDUPE_MODEL` env, `strix/config/settings.py`) — defaults to the main model, but can point at a different (cheaper) model **on its own endpoint with its own credentials** (`DEDUPE_LLM_API_KEY` / `DEDUPE_LLM_API_BASE`). `strix/report/dedupe.py` (`resolve_dedupe_model`) builds a separate `StrixProvider` bound to that endpoint so main-endpoint credentials never leak to the dedupe provider.
- The dedupe judge is a narrow classification task: "determine if a candidate vulnerability report describes the SAME vulnerability as any existing report" (system prompt in `dedupe.py`) — exactly the kind of Tier-1 work a cheap model handles well.
- Deterministic work is kept **out** of the LLM entirely: dependency-CVE dedup is done by deterministic package-identity comparison (`_dependency_identity`: same CVE + same package/ecosystem = duplicate, confidence 1.0) *before* any LLM call.

### A.4 Cost-control mechanisms found in the code

| Mechanism | Source |
|---|---|
| **Per-scan budget cap** — `--max-budget`; `run.json` carries `llm_usage.cost` vs the budget; AGENTS.md: "check `run.json` (`status`, `llm_usage.cost` vs the budget)" | `AGENTS.md` |
| **Real cost, not estimates** — LiteLLM success callback captures provider-reported cost; a custom OpenRouter streaming-handler subclass recovers OpenRouter's exact `usage.cost` per stream chunk (LiteLLM otherwise drops it, which "for new models (e.g. kimi-k3), reporting $0" would under-report) | `strix/config/models.py` (`_install_openrouter_stream_cost_capture`) |
| **Prompt caching** — `STRIX_PROMPT_CACHE` (default on), cache-block size 128 tokens; OpenRouter sticky sessions option (`STRIX_OPENROUTER_STICKY_SESSIONS`) to keep provider pinning so caches survive across turns | `strix/config/settings.py`, `models.py` |
| **Context compaction** — auto-compaction on by default; keep 8k tokens, tool-output caps 8k tokens / 2k lines / 50 KB; summarizer capped at 4k tokens | `strix/config/settings.py` (`ContextSettings`) |
| **Tool-call caps per turn** — `LLM_MAX_TOOL_CALLS_PER_TURN` (default 32); a `_TurnGuardModel` drops excess queued calls | `strix/config/models.py` |
| **Timeouts + retries** — request timeout 300s, stream-idle timeout, retry policy (max 5 retries, exponential backoff) for 429/5xx | `settings.py`, `models.py` |
| **Reasoning-effort dial** — `STRIX_REASONING_EFFORT` (default `high`) | `settings.py` |
| **Model-aware token budgets** — resolved from LiteLLM metadata per model, with configurable fallbacks | `strix/llm/context_budget.py` |

### A.5 Local-model support (with honest caveats)

- `ollama/` prefix routes through LiteLLM to a local Ollama (`STRIX_LLM="ollama/qwen3-vl"`, `LLM_API_BASE="http://localhost:11434"`); LM Studio/vLLM via OpenAI-compatible endpoints (`docs/llm-providers/local.mdx`).
- Strix's own docs are candid: "Strix relies on advanced agentic capabilities (tool use, multi-step planning, self-correction). **Most local models, especially those under 70B parameters, struggle with these complex tasks.** For critical assessments, we strongly recommend … Claude 4.5 Sonnet or GPT-5. Use local models only when privacy is the absolute priority." Recommended local models: Qwen3 VL, DeepSeek V3.1, Devstral 2. Small models (<~30B) "emit malformed or text-form tool calls far more often than frontier models" — prefer a capable model for agentic behavior.

### A.6 Strix takeaways for BugSeek

1. **One routing layer, many providers** (LiteLLM-style) — never hardcode a vendor; ship with a cheap OpenRouter default and let users override.
2. **Tiered models**: strong model for the agent, cheap model for judges/triage/dedup (`STRIX_DEDUPE_MODEL` pattern).
3. **Deterministic first**: CVE dedup by package identity before LLM; only ambiguous cases reach a model.
4. **Real cost accounting** against per-scan budgets (OpenRouter `usage.cost` capture) — copy this for BugSeek's paid-tier metering.
5. **Context/caching hygiene** (compaction, tool-output caps, prompt caching, sticky provider pinning) — these are the difference between a $0.10 scan and a $3 scan.

---
## Part B — Recommended AI Strategy for BugSeek (previous pass, OpenRouter-default)

> ⚠️ **STATUS (Oct 2026 update): the OpenRouter-default recommendation in this part is SUPERSEDED as the default** by the provider decision in §0 (Google AI/Gemini). This part is retained verbatim as an **alternative/fallback provider option** — the architecture (tiered routing, cost controls, deterministic-first) is unchanged; only the default gateway and model names moved. §A (Strix analysis) and §B.5/B.6 (deterministic work, local models) are unaffected.

### B.1 Verified price landscape (2026-10-01) [SUPERSEDED AS DEFAULT — retained as fallback provider reference]

Prices per **1M tokens, input / output**. All marked VERIFIED were fetched live today; links inline.

**Anthropic — official API pricing** (VERIFIED: https://platform.claude.com/docs/en/about-claude/pricing)

| Model | Input | Output | Cached-input read | Notes |
|---|---|---|---|---|
| Claude Haiku 4.5 | $1.00 | $5.00 | $0.10 | "near-frontier intelligence", fastest |
| Claude Sonnet 5 | $2.00 | $10.00 | $0.20 | new cheaper mid tier |
| Claude Sonnet 5.5 | $2.00 | $10.00 | $0.20 | |
| Claude Sonnet 4.6 | $3.00 | $15.00 | $0.30 | |
| Claude Opus 5.5 | $4.00 | $20.00 | $0.20 | new flagship pricing (was $5/$25) |
| Claude Opus 5 / 4.8 / 4.7 / 4.6 / 4.5 | $5.00 | $25.00 | $0.50 | |
| Claude Fable 5 / 5.1 | $10.00 | $50.00 | $1.00 / $0.25 | cache read 2.5¢ on 5.1 |
| Batch API | 50% off both sides | | | for non-interactive bulk triage |

**OpenAI — current official pricing** (VERIFIED: https://developers.openai.com/api/docs/pricing; the live page now lists the GPT-6 line first)

| Model | Input | Output | Notes |
|---|---|---|---|
| gpt-6-luna (short ctx) | $0.10 | $0.50 | cheapest frontier-vendor model; $0.01 cached input |
| gpt-6.1-sol | $2.00 | $10.00 | |
| gpt-6-astra | $10.00 | $50.00 | flagship |
| gpt-5.6-sol | $4.00 | $20.00 | promo pricing through 2026-11-21 |
| gpt-5.6-cyber ("Daybreak") | $12.50 | $75.00 | **security-specialized model** — note for the "strong reasoner" slot, though premium |
| gpt-5.3-codex | $1.75 | $14.00 | |

Older-but-current OpenAI models no longer on the live pricing page (VERIFIED via OpenRouter live API, which mirrors upstream rates): gpt-5.4-mini **$0.75/$4.50**, gpt-5.4-nano $0.20/$1.25, gpt-5-mini $0.25/$2.00, gpt-5-nano $0.05/$0.40, gpt-5.2 $1.75/$14.00, gpt-5.5 $5.00/$30.00.

**OpenRouter live prices** (VERIFIED: https://openrouter.ai/api/v1/models, 2026-10-01) — cheap/open-weight options:

| Model (OpenRouter id) | Input | Output | Notes |
|---|---|---|---|
| `deepseek/deepseek-v4-pro` | $0.21 | $0.42 | cheapest reasoning-capable model found |
| `deepseek/deepseek-v4.1-flash` | $0.03 | $0.50 | ultra-cheap flash tier |
| `z-ai/glm-5.3-flash` | $0.15 | $0.50 | Strix-family cheap tier |
| `z-ai/glm-5.3` | $0.22 | $3.39 | **Strix's default**; note input/output asymmetry |
| `qwen/qwen3.8-flash` | $0.15 | $0.47 | |
| `google/gemini-3.1-flash-lite` | $0.25 | $1.50 | |
| `google/gemini-3.5-flash` | $1.50 | $9.00 | official Google price per 3rd-party tables; OpenRouter ~same |
| `moonshotai/kimi-k3` | $0.66 | $10.00 | |
| `z-ai/glm-5.2` | $0.41 | $3.99 | |

**Local (Ollama / LM Studio):** $0 marginal API cost (hardware + electricity only). UNVERIFIED benchmark numbers omitted — see §B.6 for capability guidance.

### B.2 Per-scan cost estimates [SUPERSEDED AS DEFAULT — see §0.4 for the Gemini-first figures; retained for the OpenRouter fallback]

**Token assumptions (ESTIMATES, stated explicitly):** routine Tier-1 classification/triage calls ≈ 1–3k tokens (mostly input); agent reasoning turns ≈ 5–15k tokens; a deep agent run ≈ 30–50 turns.

| Scan type | Token shape (estimate) | Cheap tier | Mid tier | Frontier tier |
|---|---|---|---|---|
| Passive recon scan (mostly deterministic; ~10–20 triage calls) | ~40k in / ~10k out | **~$0.01** (glm-5.3-flash) | ~$0.09 (Haiku 4.5) | n/a |
| Deep agent scan, Tier-1 only (50 turns, deepseek-v4-pro) | ~400k in / ~50k out | **~$0.11** | — | — |
| Deep agent scan, mixed (cheap triage + Sonnet 4.6 reasoning for ~15 hard turns) | ~300k in (cheap) + ~100k in (Sonnet) / ~40k out | — | **~$0.60–0.90** | — |
| Deep agent scan, frontier (Opus 5.5 / Fable) | ~400k in / ~50k out | — | — | $2.00–5.00 |

Math example (cheap tier): 50 turns × (8,000 in × $0.21/1M + 1,000 out × $0.42/1M) = 50 × ($0.00168 + $0.00042) ≈ **$0.11/scan**. Frontier check: same shape on Sonnet 4.6 ≈ 50 × ($0.024 + $0.015) ≈ **$1.95/scan**. These are **ESTIMATES** — real numbers will come from instrumenting the backend with Strix-style per-scan cost capture (§A.4).

### B.3 Recommended tiered architecture [SUPERSEDED AS DEFAULT — see §0.3 for the Gemini tier mapping; the architecture below is retained for the OpenRouter fallback]

Route by task difficulty, not by user tier. Default = cheapest model that can do the job; escalate only on ambiguity or high-value signals.

**Tier 0 — No LLM at all (deterministic).** This is where most of the Phase-1 MVP passive recon already lives:
- HTTP header presence/values (CSP, HSTS, X-Frame-Options, etc.), cookie flags, TLS cert expiry/cipher suites
- Regex/entropy secret scanning on JS (then Tier-1 model triages only the hits)
- Tech fingerprinting via signature DB (Wappalyzer-style)
- robots.txt / sitemap.xml parsing; known-CVE lookup of detected JS library versions against OSV/NVD
- DOM sink enumeration (list sinks; don't judge exploitability yet)

**Tier 1 — Cheap/small models (~$0.03–0.50/1M in).** High-volume, narrow, structured-output tasks: secret triage (is this regex hit a real credential?), tech-stack classification, finding dedup (copy Strix's `STRIX_DEDUPE_MODEL` pattern: separate model + separate endpoint allowed), severity pre-scoring, honeypot-signal flagging.
Recommended defaults: `openrouter/deepseek/deepseek-v4-pro` ($0.21/$0.42) or `openrouter/z-ai/glm-5.3-flash` ($0.15/$0.50). Fallback within Tier 1: `openrouter/qwen/qwen3.8-flash`, `google/gemini-3.1-flash-lite` ($0.25/$1.50).

**Tier 2 — Strong models (~$2–5/1M in).** Only for: attack-chain reasoning, honeypot-vs-vuln judgment calls, exploit-validation planning, contextual severity, final report narrative. Recommended: `anthropic/claude-sonnet-5` ($2/$10) or `openai/gpt-5.6-sol` ($4/$20, promo through Nov 21 2026). Fallback: `anthropic/claude-sonnet-4-6`, or Tier-1 model with a "low confidence — verify" flag when budgets are tight.

**Routing rules (backend config):**
1. Every pipeline stage declares `tier` + `max_cost_per_call`; calls above the cap are refused before dispatch.
2. Escalation: Tier-1 output includes a confidence score; confidence < threshold (or "ambiguous") → re-run the *same* question at Tier 2. This bounds frontier spend to the genuinely hard cases (~10–30% of calls).
3. Fallback chain per tier on 429/5xx/timeout: primary → secondary (different provider) → queue-and-retry; never silently upgrade to a more expensive tier on failure (that's how bills explode).
4. Single provider-agnostic gateway: route everything through **OpenRouter** as the default (one API key, exact `usage.cost` per call like Strix does), with direct-provider keys as user-overridable options (cheaper for heavy users; avoids OpenRouter's small markup — UNVERIFIED margin size).

### B.4 Default + fallback strategy [SUPERSEDED AS DEFAULT — see §0.5; retained for the OpenRouter fallback]

**MVP / free tier (ship cheap, BYO-key friendly):**
- Default: OpenRouter + `deepseek/deepseek-v4-pro` for the agent loop, `z-ai/glm-5.3-flash` for triage/dedup. Estimated blended cost ≈ **$0.10–0.25 per deep scan**, ~$0.01 per passive scan.
- Free tier = metered credits (e.g. 10 deep scans/month free) so Peer subsidizes only ~$1–2/user/month. BYO OpenRouter/Anthropic/OpenAI key removes the cap entirely — the Strix model ("free, fully local, BYO LLM key").
- Fallback: if OpenRouter is down or a model 429s, cascade to the secondary model in the same tier; if all Tier-2 fails, degrade gracefully to Tier-1-only with "reduced confidence" labels rather than failing the scan.

**Paid scale (Hunter $29 / Pro $99 — tiers per the product plan §6.1):**
- Hunter $29: default Tier-1 + Tier-2 escalation on Sonnet-5-class; monthly AI budget ≈ $4–6/user → ~30–60 deep scans or ~400 passive scans. Price in a "scan credit" model so heavy users self-select upward.
- Pro $99: stronger Tier-2 default (Opus-5.5-class or Daybreak `gpt-5.6-cyber` for high-value targets), larger context budgets, longer agent horizons (more turns), priority queueing. Monthly AI budget ≈ $15–25/user.
- Both paid tiers: exact per-scan cost accounting (copy Strix's OpenRouter `usage.cost` capture), per-user monthly caps with 80%/100% alerts, batch API for offline re-triage (Anthropic 50% discount) of the finding backlog.

### B.5 What stays off the LLM (deterministic)

Per §B.3 Tier 0: headers, cookie flags, TLS checks, robots/sitemap mining, regex secret detection (LLM only triages hits), library-version → CVE lookup (OSV/NVD), DOM sink listing, subdomain enumeration (DNS/CT logs), port/service banners. Also deterministic pre-filters before any LLM judge: exact-duplicate finding suppression, dependency-CVE identity dedup (copy Strix's `_dependency_identity` approach). Rule of thumb: **if a regex, a DB lookup, or a parser can answer it, the LLM never sees it** — the LLM's job is judgment, not parsing.

### B.6 Local models (Ollama / LM Studio)

- **Realistic for:** Tier-1 triage/classification/dedup with structured JSON output — 7B–32B instruction-tuned models (Qwen3, DeepSeek-V3.1-class, Devstral-class per Strix's local guide) can do this with temp ~0.2 and a good tool-call template. Marginal cost $0 — good for the free tier and for privacy-sensitive targets.
- **Not realistic for:** the plan→act→observe→reflect agentic loop. Strix's docs are explicit: <70B models struggle with agentic tool-use; <30B emit malformed tool calls frequently. Keep the agent loop on hosted APIs.
- **Practical setup:** BugSeek backend should accept `LLM_API_BASE=http://localhost:11434` + model id for self-hosters (mirror Strix's `ollama/` prefix convention); require ≥16k context (`num_ctx`) since security prompts + tool schemas are large (Strix local-docs guidance).

### B.7 Risks & open questions

1. **Open-weight quality drift:** cheap models (GLM/DeepSeek flash tiers) change versions often; pin model snapshots and re-benchmark triage precision/recall monthly. **UNVERIFIED:** whether `deepseek-v4-pro` sustains exploit-validation quality — needs a BugSeek eval harness on DVWA/Juice Shop.
2. **OpenAI's Daybreak cyber models** (`gpt-5.6-cyber`, $12.50/$75) are purpose-built for security — worth a trial as the Tier-2 flagship, but premium; validate ROI before defaulting.
3. **Frontier-vendor price moves:** OpenAI's live page has already moved to the GPT-6 line; budget models get deprecated (5.4-mini/nano no longer listed). The OpenRouter-default design insulates BugSeek from any single vendor's deprecation.
4. **Free-tier abuse:** credit farming via throwaway accounts — require email verification + modest free credits; BYO key for unlimited.
5. **RESOLVED (Oct 2026):** Google's first-party Gemini API pricing was fetched from the official page (https://ai.google.dev/gemini-api/docs/pricing) — see §0.2. Gemini prices are now VERIFIED, not third-party tables.

---

*End of AI backend strategy analysis. Provider decision: Google AI (Gemini), Oct 2026 — §0 is the current primary recommendation; Part B (OpenRouter-default) is retained as the fallback-provider reference. See also: `docs/market-research.md` §7 (Strix deep dive).*
