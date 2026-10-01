# BugSeek AI — Business Plan

**Version:** 1.0 · October 2026 · DRAFT (internal)
**Grounding:** every market figure below comes from `docs/market-research.md` (Worker 1, Oct 2026) or the product plan. Figures from the plan that the research corrected are flagged. No invented statistics.

---

## 1. Executive summary

BugSeek AI is a Chrome extension that puts an AI security researcher inside the hunter's browser. Passive reconnaissance in one click (Phase 1, built); guided active testing with explicit authorization (Phase 2, in build); honeypot/trap detection and bounty-platform-ready reports as the differentiators nobody else owns.

**The wedge (from research):** do not compete as "another autonomous pentesting agent" — Strix (~66k stars), XBOW ($237M raised, $1B+), and Pentera ($250M raised, $1B+) own that sentence. BugSeek owns the **browser-native hunter workflow**: zero-setup UX, individual-hunter pricing, trap detection, and HackerOne/Bugcrowd/Immunefi-shaped reports.

**Business model:** freemium SaaS, metered by scan credits. Hunter $29/mo sits under a Burp Pro license ($449/yr ≈ $37/mo); Pro $99/mo for consultants; Enterprise custom.

---

## 2. Market (corrected figures)

The product plan's "platforms paid $300M+ in 2025" conflates an annual figure with a lifetime figure. The defensible numbers, all sourced in `market-research.md` §2:

| Figure | Value | Source |
|---|---|---|
| HackerOne payouts, 12 mo to Jun 2025 | **$81M** (+13% YoY) | HackerOne 9th Hacker-Powered Security Report |
| HackerOne cumulative lifetime payouts | **$300M+** (crossed Mar 2025) | Infosecurity Magazine |
| Verifiable 2025 platform total (H1 $81M + Google VRP $17M + Microsoft ~$20M + Meta $4M + Bugcrowd/Immunefi undisclosed) | **≈ $130–150M** | Research brief §2 |
| Researchers who earned ≥1 bounty | 50,000+ | HackerOne HPSR |
| Top-100 all-time earners' share | ~$31.8M (~10% of lifetime) — brutal power law | HackerOne HPSR |
| Researchers using AI/automation | 67%; 560+ autonomous-agent ("hackbot") valid reports | HackerOne HPSR |
| AI-related vuln reports | +210% YoY; prompt-injection +540% YoY | HackerOne HPSR |

**Investor-safe framing:** *"HackerOne alone has paid $300M+ lifetime — $81M in the last year, growing 13% YoY. The verifiable 2025 platform total is ~$130–150M, and AI-assisted hunting is the fastest-growing segment."*

**Positioning opportunity:** the power-law payout distribution (top 100 take ~10%) is the pitch — *"help the other 49,900 earn."* BugSeek lowers the skill floor: guided testing + validated PoCs + platform-ready reports for hunters who aren't Burp wizards yet.

**TAM note:** the plan estimates 500,000+ active hunters worldwide. Treat as a directional plan estimate (unverified by the research); projections below do not depend on it — they depend on bottom-up conversion math.

---

## 3. Business model — refined pricing (metered)

The research verdict: tiers are defensible, but **"unlimited scans" must die** — LLM agent calls are the marginal cost. Pricing is now credit-metered.

**Scan credits:** 1 credit = one passive recon scan · 25 credits = one guided active agent scan.

| Tier | Price | Credits/mo | Target | Key inclusions |
|---|---|---|---|---|
| **Scout** | $0 | 50 | Learners, top-of-funnel | Passive recon only, Markdown reports, community support |
| **Hunter** | $29/mo | 300 | Active solo hunters | Active agent testing, honeypot detection, platform-ready reports (H1/Bugcrowd/Immunefi), scan history, PDF/DOCX export |
| **Pro** | $99/mo | 1,500 | Freelancers, consultants | Everything in Hunter + API access, shared workspaces, priority agent queue, white-label reports |
| **Enterprise** | Custom | Custom pools | Security teams | SSO, audit logs, compliance reports, self-hosted agent option, SLA |

Overage: $5 per 100 credits (Hunter/Pro). Unused credits expire monthly (no rollover) — stated up front, standard fair-use.

### 3.1 LLM cost math (explicit assumptions)

| Cost component | Assumption | Unit cost |
|---|---|---|
| Passive scan | Rules engine in-extension (free) + cheap-model summary ≈ 4k in / 0.5k out tokens at ~$0.15/$0.60 per 1M | **≈ $0.01** |
| Active agent scan | Agentic loop (~40 turns ≈ 320k in / 60k out) on `gemini-3.8-flash` ($0.75/$3.75 intro) ≈ **$0.47**; with Pro-class escalation on low confidence only (`gemini-3.1-pro-preview` $2.00/$12.00) ≈ **$0.72** worst case | **≈ $0.65** |
| Tiered routing | Routine triage on cheap models; exploit reasoning on strong models (see AI-strategy doc) | margin lever |

**Per-tier unit economics:**

| Tier | Revenue | Typical usage assumption | Est. COGS | Gross margin |
|---|---|---|---|---|
| Scout | $0 | 30 passive scans | $0.30 | acquisition cost |
| Hunter | $29 | 120 passive + 4 active | $1.20 + $2.60 = **$3.80** | **≈ 87%** |
| Hunter (worst case: all credits → active) | $29 | 12 active scans | $7.80 | ≈ 73% |
| Pro | $99 | 400 passive + 20 active | $4.00 + $13.00 = **$17.00** | **≈ 83%** |
| Pro (worst case) | $99 | 60 active scans | $39.00 | ≈ 61% |

Even at adversarial full utilization, gross margins stay above 60%. The meter is the moat around the cost base: no "unlimited" tier can be arbitraged into a compute firehose. Guardrails that protect margin further: per-scan token budgets, cheap-model-first routing, caching of recon summaries, and rate limits (also a legal requirement — §8 of the plan).

---

## 4. Go-to-market

Sequenced for a student budget — community and content first, paid last:

1. **Product Hunt launch** (Phase 3, with CWS listing) — security tools overperform there; aim top-5.
2. **Hunter communities** — r/bugbounty, r/netsec, infosec Twitter/X, Discord servers. Lead with useful artifacts (trap-detection writeups), not ads.
3. **YouTube demos** — BugSeek finding real bugs on intentionally vulnerable apps (OWASP Juice Shop, DVWA, HackTheBox). Never on unauthorized targets; say so on-screen.
4. **Content marketing** — "How BugSeek found X" teardowns, honeypot-detection research notes, bounty-economics explainers using the corrected market numbers.
5. **Platform-adjacent positioning** — report templates for HackerOne (public Hacker API v1 for scope ingestion), Bugcrowd (VRT-mapped), Immunefi (PoC-mandatory format). No auto-submission, ever — format, human submits.
6. **Open-source funnel** (see §6) — the extension client as the acquisition engine.

**CAC assumption:** ~$25 blended (community/PLG-led). Payback on Hunter: <1 month at 87% margin.

---

## 5. Projections (conservative — assumptions explicit)

**Assumptions:** 5% free→paid conversion · 3% monthly logo churn · $25 blended CAC · pricing as §3 · Enterprise ACV $6k (Y1 pilots) → $12k (Y2).

| | End of Year 1 | End of Year 2 |
|---|---|---|
| Free (Scout) users | 3,000 | 15,000 |
| Hunter ($29) | 150 | 800 |
| Pro ($99) | 25 | 120 |
| Enterprise | 2 pilots | 8 |
| MRR (self-serve) | $6,825 | $35,080 |
| **ARR (incl. Enterprise)** | **≈ $94k** | **≈ $517k** |

Y1 math: 150×$29 + 25×$99 = $4,350 + $2,475 = $6,825 MRR → $81.9k + 2×$6k pilots ≈ **$94k ARR**.
Y2 math: 800×$29 + 120×$99 = $23,200 + $11,880 = $35,080 MRR → $421k + 8×$12k ≈ **$517k ARR**.

**What has to be true:** the Chrome Web Store listing survives review (plan risk: MEDIUM), Phase 2 agent validates PoCs at Strix's bar (working exploits, not guesses), and trap detection demonstrably saves submissions. If CWS rejects active testing, the sideload path preserves the funnel at lower conversion — modeled as a 40% haircut to Y1 paid conversion in the downside case (≈$60k ARR).

---

## 6. The open-source question — recommendation

**Question:** should BugSeek open-source the extension (Strix's playbook: community, trust, distribution) while monetizing Cloud/Pro?

### Tradeoffs

| | Open-source the extension client | Keep it closed |
|---|---|---|
| **Distribution** | GitHub stars are the discovery engine in this category (Strix: ~66k in 14 months). Free, compounding top-of-funnel. | Paid/SEO/community grind only; slower. |
| **Trust** | Security tooling that runs in your browser *must* be inspectable. OSS is the trust shortcut (Strix's "nothing leaves your machine" docs). | "Trust our black box with your targets" is a hard sell to hunters. |
| **Community** | Template/signature contributions (Nuclei's 12k-template moat was community-built), bug reports, translations. | All R&D on Peer's shoulders. |
| **Moat risk** | Anyone can fork the client. | Code secrecy as (weak) moat. |
| **Monetization** | Proven: Strix OSS → Cloud → Enterprise funnel. Client is free; the backend agent, honeypot models, and report intelligence are the paid product. | Simpler licensing story, but no funnel. |

**Recommendation: open-source the extension client under Apache 2.0; keep the backend proprietary.**

Reasoning:
1. **The moat isn't the client.** Passive recon (DOM scanning, header checks, regex secret scanning) is commodity logic — Wappalyzer and Retire.js already publish equivalents. The defensible assets are the **agent orchestration, honeypot-detection models, and the vulnerability-pattern data flywheel** — all of which live in the backend API, which stays closed.
2. **Strix proved the playbook in this exact category.** OSS → Cloud → Enterprise converted 66k stars into a managed business. BugSeek can run the same funnel one layer up (browser UX instead of CLI).
3. **Trust is existential for a browser security tool.** Hunters will not install a closed-source extension that watches every page they visit. Apache 2.0 + "passive recon runs locally, inspect it yourself" dissolves the objection.
4. **It turns competitors into supply chain.** The research notes BugSeek's backend could run Strix or Nuclei as agent tools — an OSS client makes that composition natural and creditable.

### License implications

- **Apache 2.0 (recommended for the client):** maximum adoption; permits commercial forks (which is fine — forks still point at *our* backend API for the paid features); patent grant; compatible with the ecosystem. This is Strix's license — the market has already voted.
- **AGPL:** would force cloud-hosted forks to open-source — stronger copyleft, but it poisons community adoption (companies ban AGPL dependencies) and deters the contributors we want. Rejected.
- **Source-available / BSL (e.g., "no competing SaaS for 2 years"):** a middle path if a cloud copycat emerges. Keep in the back pocket; don't lead with it — it reads as defensive before we have anything worth copying.
- **Backend:** proprietary, closed. No license needed — it's a service, not distributed code. The API boundary is the moat line; document it as such in CONTRIBUTING.

**Sequencing:** open-source at Phase 3 (CWS listing + Product Hunt), not now — ship Phase 1 closed to iterate fast, then open the client as the launch event. Announce the license intent early (in README) so the community trusts the direction.

---

## 7. Roadmap & milestones (from plan §7, research-adjusted)

- **Phase 1 (wks 1–2) — DONE:** passive recon extension (MV3), popup UI, Markdown reports.
- **Phase 2 (wks 3–4) — in build:** backend API (auth, queue, agent), guided active testing, PoC validation, honeypot v1, PDF/DOCX + CVSS, scope/authorization gates.
- **Phase 3 (mo 2–3):** trap-detection v2, attack-chain reasoning, IDOR/auth/GraphQL, Stripe billing, platform report templates, **CWS listing + Product Hunt + open-source the client**.
- **Phase 4 (mo 4+):** pattern database from anonymized scan data, continuous monitoring, CI/CD action, SSO/audit/self-host, public API.

## 8. Risks (honest)

1. **Chrome Web Store review (MEDIUM).** Active testing from an extension is a grey zone; MV3 remote-code rules are hard constraints. Mitigation: passive-only store build, authorization-gated active flow, backend-hosted agent logic, sideload fallback.
2. **Strix-class competition.** We don't out-agent them; we out-workflow them (browser UX, hunter reports, trap detection). If Strix ships a browser extension, the wedge narrows — speed matters.
3. **LLM cost overruns.** Metered credits + tiered models + per-scan budgets; monitored weekly.
4. **Platform policy shifts.** HackerOne/Bugcrowd/Immunefi could restrict tooling-assisted reports. Mitigation: human-submits design, valid-PoC-only output, responsible-disclosure posture.
5. **Legal exposure.** A security tool is a liability without guardrails. Mitigation: authorization verification, scope enforcement, rate limiting, no sensitive-data exfiltration, draft ToS/disclosure policy (lawyer review required before launch).

---

*All market figures sourced from `docs/market-research.md` (Oct 2026). Pricing math uses the assumptions in §3.1 — revisit quarterly as model prices move.*
