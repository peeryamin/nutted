# BugSeek AI — Pitch Deck (source)

**Format:** one `##` section = one slide. A presentable HTML version lives at `docs/pitch-deck.html` (self-contained, double-click to present, arrow keys to navigate).
**Narrative arc:** follows product plan §9 — market is real → timing is right → wedge is specific → moat deepens → expansion path is clear.
**Honesty rules:** every number is sourced (research brief or plan). No invented stats, no fake testimonials, no fake logos.

---

## Slide 1 — Title

**BugSeek AI**
*The security researcher in your browser.*
AI-powered reconnaissance for bug bounty hunters — passive recon in one click, guided active testing with your authorization, reports your platform will accept.
Peer · Founder · October 2026

## Slide 2 — Problem

Bug bounty hunting is a skill-gated grind.
- 50,000+ researchers have earned a bounty — but the top 100 take ~10% of all payouts. The other 49,900 fight over scraps. (HackerOne HPSR)
- The expert stack is hostile to newcomers: Burp Suite Pro ($449/yr) has a cliff-like learning curve; Nuclei needs template-fu; autonomous agents (Strix, PentestGPT) are CLIs that need Docker and LLM keys.
- 67% of researchers already use AI/automation — but nothing puts it *where the target is*: the browser tab they already have open.
- Automation has a hidden tax: honeypots and canary traps. Submit a trap as a finding and you burn reputation, not just time. No major tool detects them.

## Slide 3 — Solution

**BugSeek AI: a Chrome extension that is the hunter's workflow.**
1. Open the target → confirm program scope (out-of-scope blocked automatically).
2. One click → passive recon: fingerprinting, headers, cookies, JS secrets, DOM analysis. Zero attack traffic.
3. Authorized? → the guided AI agent plans and executes active tests (XSS, IDOR, CORS, auth, GraphQL…) — confirmed findings marked as such, the rest surfaced as review hints.
4. Every finding gets a **trap-probability score** — honeypots quarantined before they reach your report.
5. Export a platform-ready draft (HackerOne fields, Bugcrowd VRT mapping, Immunefi PoC checklist). You review. You submit.

## Slide 4 — Product (demo narrative)

*[Live demo on OWASP Juice Shop — an intentionally vulnerable app. Never on unauthorized targets.]*
- Popup scan on the login page → 14 passive findings in 4 seconds: missing security headers, session cookie without Secure flag, exposed API key in JS bundle.
- "Authorize active test" → confirm scope dialog → agent runs: reflected XSS validated with a working PoC payload where execution is observed; other reflections surface as review hints.
- Trap analysis flags a too-easy SQL error page: 82% trap probability, excluded from the draft.
- One click → HackerOne-formatted report: title, CVSS 8.2, CWE-79, steps to reproduce, impact, evidence attached.

## Slide 5 — Why now

- **Agentic AI crossed the capability threshold.** Reasoning about security context — chaining findings into attack narratives — wasn't reliable 18 months ago. XBOW topping the HackerOne US leaderboard (late 2025) proves agents find real bugs.
- **The market is validating AI hunting.** 560+ autonomous-agent reports already accepted; AI-related vuln reports +210% YoY. (HackerOne HPSR)
- **Manifest V3 forced the right architecture.** Agent logic must live behind a backend API — which is exactly the SaaS shape we monetize.
- **The wedge is open.** Nobody owns the browser-native hunter workflow: Strix is a CLI, XBOW/Pentera are enterprise, Burp is a desktop proxy.

## Slide 6 — Market

- HackerOne paid **$81M** in the last year (+13% YoY); **$300M+ lifetime**. (Corrected from the plan's "$300M in 2025" — that figure is lifetime, not annual.)
- Verifiable 2025 platform total: **≈ $130–150M**/yr across HackerOne, Google VRP ($17M), Microsoft (~$20M), Meta ($4M), Bugcrowd, Immunefi.
- 50,000+ paid researchers; brutal power law = our wedge: *"help the other 49,900 earn."*
- Tool budgets are proven: hunters already pay $449/yr for Burp Pro; dev-security seats run $25–49/mo (Snyk, Semgrep, GitHub Advanced Security).

## Slide 7 — Competition (the honest slide)

| | What they are | Why we don't fight them head-on |
|---|---|---|
| **Strix** (~66k ★, Apache 2.0) | The benchmark open-source autonomous pentest agent — multi-agent, working-PoC validation, bug-bounty use case | Developer-first CLI. No browser UX, no trap detection, compliance-shaped reports. We match their PoC bar; we beat them on hunter workflow. Possibly: run Strix as one of our engines. |
| **XBOW** ($237M raised, $1B+) | Autonomous offensive security for enterprise dev teams | Defensive, CI/CD-shaped, enterprise-priced. Different buyer entirely. |
| **Pentera** ($250M raised, $1B+) | Enterprise exposure validation, $35k+/yr | Network/identity focus, five-figure deals. Not our buyer. |
| **Burp Suite Pro** ($449/yr) | The expert's proxy workbench | Desktop, steep learning curve. Our Hunter tier ($29/mo) undercuts it for beginners/intermediates. |
| **Nuclei** (~12k templates) | Signature-based known-vuln scanning | Gold standard for known CVEs — we complement it (templates as agent input), not replace it. |

**Our wedge, in one line:** *browser-native, hunter-workflow-shaped, trap-aware, platform-ready reporting.* Nobody owns that combination.

## Slide 8 — Business model

Freemium SaaS, metered by scan credits (1 credit = passive scan; 25 = guided agent scan). "Unlimited" is banned — LLM calls are the marginal cost.

| Tier | Price | For |
|---|---|---|
| Scout | $0 | Learners — 50 credits/mo, passive only |
| Hunter | $29/mo | Solo hunters — 300 credits, active testing, trap detection, platform reports |
| Pro | $99/mo | Consultants — 1,500 credits, API, shared workspaces |
| Enterprise | Custom | Teams — SSO, audit, self-host |

**Unit economics (assumptions in business plan §3.1):** passive scan ≈ $0.01 · active agent scan ≈ $0.65 → Hunter gross margin ≈ 87% typical / 73% worst-case · Pro ≈ 83% / 61%. Overage at $5/100 credits.

## Slide 9 — Traction & roadmap

- **Phase 1 — DONE (wks 1–2):** MV3 extension, passive recon (DOM, secrets, cookies, headers, fingerprinting), Markdown reports.
- **Phase 2 — IN BUILD (wks 3–4):** backend API (auth, queue, agent), guided active testing with PoC validation, honeypot detection v1, authorization/scope gates, PDF/DOCX + CVSS.
- **Phase 3 (mo 2–3):** trap detection v2, attack-chain reasoning, Stripe billing, platform report templates, **Chrome Web Store listing + Product Hunt + open-source the extension client (Apache 2.0)**.
- **Phase 4 (mo 4+):** anonymized pattern database, continuous monitoring, CI/CD action, SSO/self-host, public API.

## Slide 10 — Go-to-market

Student-budget sequencing — community first, paid last:
1. Product Hunt launch (security tools overperform; target top-5) + CWS listing.
2. r/bugbounty, r/netsec, infosec X, Discords — lead with useful artifacts (trap-detection research), not ads.
3. YouTube demos on Juice Shop/DVWA/HackTheBox (authorized targets only, stated on-screen).
4. Content: "How BugSeek found X" teardowns, bounty-economics explainers.
5. Open-source funnel: the Apache-2.0 extension client is the acquisition engine (Strix's playbook: 66k stars → Cloud → Enterprise).

## Slide 11 — Moat (deepens over time)

1. **Data flywheel:** every scan (anonymized, opt-in) trains trap detection and false-positive reduction. More users → smarter agent → more users.
2. **Workflow lock-in:** scope configs, scan history, report templates, platform-format muscle memory — hunters don't re-setup lightly.
3. **Backend API boundary:** the client is open-source; the agent, honeypot models, and report intelligence are proprietary services. Fork the client all you want — the paid value is behind the API.
4. **Trust + distribution:** OSS client = inspectable = installable. Stars compound.

## Slide 12 — Team & ask [TEMPLATE — Peer to fill]

- **Founder:** Peer — [background, e.g. security student, bounty experience, notable finds].
- **Hiring / advisors sought:** [e.g. founding engineer (backend/agents), security advisor with platform relationships].
- **The ask:** [e.g. $X pre-seed to fund 12 months: LLM inference credits, one hire, CWS/legal costs] — or "currently bootstrapped; seeking design partners and 50 beta hunters."
- **Contact:** [email] · [GitHub] · [X/Twitter]

## Slide 13 — Risks (we'd rather you hear them from us)

1. **Chrome Web Store review (MEDIUM):** active testing from an extension is a grey zone. → Passive-only store build, authorization-gated active flow, backend-hosted agent, sideload fallback.
2. **Strix ships a browser extension:** our wedge narrows. → Speed; trap detection and platform-report depth are harder to clone than a popup.
3. **LLM cost overruns:** → metered credits, tiered models, per-scan budgets, weekly monitoring.
4. **Platform policy shifts** on tooling-assisted reports → human-submits design, PoC-validated output only.
5. **Legal exposure** → authorization verification, scope enforcement, rate limiting, no sensitive-data exfiltration, ToS + disclosure policy (lawyer review pre-launch).

## Slide 14 — Closing

The hunters are already in the browser. The AI is already capable. The payouts are already growing 13% YoY.
**BugSeek AI meets them there.**
*The security researcher in your browser.*
[Contact / early-access link]
