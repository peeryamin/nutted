# BugSeek AI — Market & Competitive Research Brief

**Date:** 2026-10-01 (research collected Sep 30 – Oct 1, 2026)
**Purpose:** Ground the product plan in the actual 2026 landscape: competitors, bounty-market payouts, SaaS pricing benchmarks, Chrome Web Store policy reality, and platform-integration requirements. Includes a deep dive on **Strix** (per Peer, Oct 2026).
**Method:** Web search + direct page fetches. Every factual claim carries a source URL. Items that could not be verified are marked **UNVERIFIED** or **UNCERTAIN**.

---

## Summary Table

| Area | Headline finding |
|---|---|
| Competitive field | Category has split in three: **enterprise validation** (Pentera, Horizon3.ai), **autonomous web pentest engines** (XBOW, Corgea, Intruder), **open-source agents** (PentestGPT, Strix, PentAGI, CAI). XBOW and Pentera are both $1B+ unicorns (2026 raises). |
| Key new competitor | **Strix** (~66k stars, Apache-2.0, launched Aug 2025) explicitly targets **bug bounty automation** as a use case — the closest thing to BugSeek's wedge, but as a developer-first CLI, not a browser extension. See §7. |
| Market size | **Plan's "$300M+ paid in 2025" needs correction:** HackerOne paid **$81M in the 12 months to Jun 2025** (13% YoY); **$300M+ is HackerOne's cumulative lifetime** total (crossed Mar 2025). Combined platform payouts 2025 ≈ $130–150M (see §2). |
| Pricing sanity check | Plan's tiers (Free $0 / Hunter $29 / Pro $99 / Enterprise custom) sit comfortably in the 2026 dev-security range: Burp Pro ~$449/yr ($37/mo), Snyk Team $25/dev/mo, Semgrep Team $35/dev/mo. BugSeek Hunter $29 ≈ one individual's Burp-equivalent budget — defensible. |
| CWS policy risk | No verified explicit ban on pentesting extensions, but CWS review is restrictive (broad permissions + automated data collection draw scrutiny); **plan's "MEDIUM" risk stands**. MV3 remotely-hosted-code rules force agent logic into the extension package or behind a backend API — the plan's 3-layer architecture already complies. |
| Platform integrations | HackerOne has a public Hacker API v1 (programs, scope, weaknesses, reports incl. **report submission**); Bugcrowd's API v1 is **restricted to enterprise/high-rep researchers**; Immunefi has **no documented public API** (unofficial community mirrors exist). No platform supports bulk automated submission — auto-submission is against policy. BugSeek should auto-*format* reports, submit manually. |
| Strix implication | Going head-to-head with Strix-class autonomous pentest agents is a losing fight for a new entrant. Sharpen the wedge: **browser-native Chrome UX, individual hunter workflow, honeypot/trap detection + contextual reasoning** (see §6). |

---

## 1. Competitors — The 2026 Landscape

A 2026 competitive survey (GitHub, data collected 2026-08-11) argues the category has split into three groups that are **not** substitutes for each other: enterprise validation platforms, autonomous web pentest engines, and open-source agents/research. That framing is used below.
Source: https://github.com/evkir/cyberai/blob/HEAD/docs/competitive-landscape-2026.md

### 1a. Enterprise validation platforms

**Pentera — automated security validation (exposure validation)**
- What it does: continuous simulated attack campaigns against enterprise networks/cloud/web-facing assets ("Automated Security Validation"); CTEM-oriented.
- Customers/funding: **$250M total raised; $1B+ valuation** (Series D $60M led by Evolution Equity Partners, Mar 2025 — reporting March 2025); **$100M+ ARR (Jan 2026), 1,200+ enterprise customers across 60 countries** per a competitor comparison page.
- Pricing: quote-based; one comparison cites **starting ~$35,000/year**.
- BugSeek difference: Pentera sells to security teams at five-figure annual deals with network/identity focus; BugSeek targets **individual hunters** at $29/mo via a browser extension. Not direct competitors — different buyer, different price band.
- Sources: http://techcrunch.com/2025/03/12/pentera-nabs-60m-at-a-1b-valuation-to-build-simulated-network-attacks-to-train-security-teams/ ; https://squr.ai/blog/compare/squr-vs-pentera ; https://www.selecthub.com/penetration-testing-tools/pentera-vs-astra-security/

**Horizon3.ai (NodeZero) — autonomous pentesting**
- What it does: agentless autonomous pentesting across internal/external/cloud/Kubernetes/AD; chains weaknesses, returns exploit proof with impact + mitigation guidance; first pentest "set up in minutes."
- Target: enterprise infrastructure/network security teams (continuous internal validation).
- Pricing: **not published** (packaging page carries no figure); one research note cites an AWS Marketplace one-time-test SKU at $15,000 (UNVERIFIED — secondhand).
- BugSeek difference: NodeZero is infrastructure/lateral-movement focused and enterprise-sold; BugSeek is web-app, hunter-focused, in-browser.
- Sources: https://www.stingrai.io/blog/automated-penetration-testing-platforms-2026 ; https://usawire.com/autonomous-penetration-testing-a-technical-buyers-guide-to-the-platforms-redefining-offensive-security/

### 1b. Autonomous web pentest engines (commercial)

**XBOW — AI offensive security**
- What it does: AI agents that autonomously discover, exploit, and validate web-app vulnerabilities at machine speed; findings gated on confirmed exploitation (low false positives); integrates with Microsoft Sentinel/Security Copilot and CI/CD.
- Traction: founded Jan 2024 by **Oege de Moor (creator of GitHub Copilot)**; **$120M Series C at $1B+ valuation (Mar 2026)** led by DFJ Growth + Northzone, plus **$35M strategic extension (May 2026)** from Accenture Ventures, NVIDIA NVentures, Samsung Ventures, SentinelOne; **$237M total raised**; 100+ customers incl. Moderna; **topped the HackerOne leaderboard in the US in late 2025**.
- Target: enterprise dev/security teams (defensive use — customers secure their own software).
- Pricing: **not public**; sold as continuous enterprise platform.
- BugSeek difference: XBOW is a defensive enterprise product (protect your own apps), not a hunter's tool for third-party bounty programs. Closest technology analog to BugSeek's agent vision, and its HackerOne-leaderboard proof point shows agentic pentesting works — but its wedge is enterprise CI/CD, not individual hunters.
- Sources: https://pulse2.com/xbow-120-million-raised-to-scale-autonomous-offensive-security-platform/ ; https://www.securityweek.com/autonomous-offensive-security-firm-xbow-raises-120m-at-1b-valuation/amp/?utm_source=augment-pulse.beehiiv.com&utm_medium=newsletter&utm_campaign=openai-is-eating-the-developer-stack ; https://pulse2.com/xbow-35-million-added-to-series-c-to-expand-autonomous-offensive-security-platform/ ; https://www.geekwire.com/2026/xbow-the-unicorn-with-a-seattle-mailbox-raises-another-35m-for-its-autonomous-hacking-platform/

**Corgea — autonomous web pentesting (Y Combinator)**
- What it does: AI agents plan and execute pentests of web apps/APIs (broken access control, IDOR, auth bypass, injection, SSRF, business-logic abuse); findings gated on validated exploitability; evidence packs + developer-native remediation (PR comments, Jira, CI/CD).
- Target: fast-moving dev teams.
- Pricing: one survey cites **published per-pentest plans starting at $4,000** (Jul 2026, secondhand — treat as UNVERIFIED unless reconfirmed on corgea.app); free trial/tier listed on comparison sites.
- BugSeek difference: Corgea sells per-pentest to dev teams; BugSeek sells a $29/mo personal tool to hunters. Same technology class (validated-exploit gating), different buyer.
- Sources: https://www.ycombinator.com/companies/corgea ; https://github.com/evkir/cyberai/blob/HEAD/docs/competitive-landscape-2026.md ; https://usawire.com/autonomous-penetration-testing-a-technical-buyers-guide-to-the-platforms-redefining-offensive-security/

**Intruder — AI web-app pentesting**
- What it does: on-demand AI-agent web-app pentests (white-box via GitHub/GitLab integration); agents built/trained by CREST-certified pentesters; results in hours.
- Target: SMBs and existing Intruder customers.
- Pricing: **starting at $3,500 per test** (announced Jul 16, 2026), pitched as ≤25% of a manual engagement.
- BugSeek difference: per-test pricing for companies testing their own apps; BugSeek is subscription for individuals testing bounty scope.
- Sources: https://securitybrief.co.uk/story/intruder-launches-ai-web-app-pentesting-at-lower-cost ; https://markets.financialcontent.com/postgazette/article/bizwire-2026-7-16-intruder-announces-ai-pentesting-for-web-applications

**BugDazz (SecureLayer7) / MindFort** — named in the 2026 buyer's-guide roundups as hybrid/service and autonomous web-pentest players respectively; no independently verified pricing found (**UNVERIFIED details** — treat as watch-list names only).
Source: https://usawire.com/autonomous-penetration-testing-a-technical-buyers-guide-to-the-platforms-redefining-offensive-security/

### 1c. Incumbent hunter tooling

**Burp Suite (PortSwigger)**
- What it does: the industry-standard proxy-based web pentesting platform (Proxy, Repeater, Intruder, Scanner, Collaborator); manual + automated.
- Target: professional pentesters; also the de-facto standard for serious bug bounty hunters.
- Pricing: Community free; **Professional $449/year per user** (~$37/mo; corroborated across a GitHub cheatsheet updated 2026, a skill spec, and reseller listings showing ~$1,100/2yr and ~$1,650/3yr, consistent with $449/yr); Enterprise Edition $6,995–$29,450/yr plans (quote-based per TechRadar); 30-day trial.
- AI status: PortSwigger is adding AI-assisted features, but Burp remains an expert-driven tool, not an autonomous agent (**UNCERTAIN** on the exact state of their 2026 AI features — not verified here).
- BugSeek difference: Burp requires deep expertise and is a desktop proxy workflow; BugSeek is **in-browser, AI-guided**, aimed at beginners/intermediates who find Burp's learning curve and $449/yr cost a barrier. Note: a hunter buying Burp Pro at ~$37/mo is exactly the budget band BugSeek's Hunter $29/mo competes in.
- Sources: https://github.com/ilias1988/hacking-cheatsheets/blob/HEAD/Burp-Suite/README.md ; https://github.com/tombook/secuclaw/blob/HEAD/skills/burp-suite/SKILL.md ; https://www.techradar.com/reviews/burp-suite-community-edition ; https://www.g2.com/products/burp-suite/reviews?filters%5Bnps_score%5D%5B%5D=5

**Nuclei (ProjectDiscovery)**
- What it does: fast YAML-template-based vulnerability scanner (HTTP/DNS/TCP/SSL/JS/WebSocket/headless); ~30.9k GitHub stars; **~12k community templates** with daily commits; template "Pioneers" program + template bounties.
- Target: pentesters, security teams, bug bounty hunters (recon/known-CVE triage).
- Pricing: **OSS free**; cloud platform (now called "Neo") — one community survey cites pay-as-you-go from **$250 (50 credits/seat)** (**UNVERIFIED** — not confirmed on projectdiscovery.io pricing); free cloud tier with generous limits per the README.
- BugSeek difference: Nuclei is signature-matching (template community is its moat); BugSeek's plan positions against it on **contextual reasoning and false-positive reduction** rather than template coverage. Realistic view: Nuclei's template engine is the gold standard for known-vuln detection; BugSeek should complement, not replace, that capability (e.g., run Nuclei templates as one input to the agent).
- Sources: https://github.com/vulnradar/vulnradar.dev/blob/HEAD/audits/AUDIT-014/research-competitors.md ; https://github.com/oz19944223/nuclei

### 1d. AI pentest agents (research / open-source)

**PentestGPT** (USENIX Security 2024, GreyDGL et al.; ~14.7k stars)
- What it is: open-source LLM pentesting agent — reasoning/generation/parsing modules; supports local LLM backends (Ollama); recent re-release as an autonomous pipeline reporting strong benchmark scores (~86.5% on an XBOW validation suite per a community ecosystem doc — secondhand, **UNCERTAIN**).
- Plan-correction note: the product plan calls it "advisory only." The original tool was human-in-the-loop (copilot), but it has since been re-released as an autonomous pipeline. Still fundamentally a **research/learning tool**, not a product; production evaluations in 2025–26 documented setup failures.
- Target: researchers, students, CTF players.
- Pricing: free / open-source.
- BugSeek difference: PentestGPT is self-hosted CLI for researchers; BugSeek productizes the agent for hunters with UX, reporting, and safety guardrails.
- Sources: https://github.com/ustadonerci/awesome-ai-security-tools/blob/HEAD/README.md ; https://usawire.com/autonomous-penetration-testing-a-technical-buyers-guide-to-the-platforms-redefining-offensive-security/ ; https://github.com/az0307/aurora-ai-agency/blob/HEAD/hexstrike-ai/april-redteam/docs/ai-tools-ecosystem.md

**HackerGPT / HackGPT**
- What it is: LLM chatbot assistants for pentesters (guidance, payload generation); one platform (HackGPT) announced enterprise ambitions with Metasploit integration and a roadmap toward "fully autonomous assessments v3.0 (Q1 2026)" — **UNCERTAIN** whether delivered; no independent verification found.
- Target: individual pentesters; pricing/model **UNVERIFIED**.
- BugSeek difference: chatbots advise; BugSeek's agent is supposed to *act* (scan, test, validate, report).
- Source: https://cyberpress.org/hackgpt-ai-powered/

**Other open-source agents worth tracking (all per the Aug 2026 awesome-list, github.com/ustadonerci/awesome-ai-security-tools):**
- **PentAGI** (vxcontrol) — fully autonomous multi-agent pentest framework with Docker sandboxing (~21.7k stars). Research-grade.
- **CAI – Cybersecurity AI** (Alias Robotics) — modular agent framework, **bug-bounty-ready**, 300+ LLM models; MIT for research / commercial license for production (~9.7k stars).
- **HexStrike-AI** — MCP server exposing 150+ security tools (nmap, gobuster, nuclei…) to AI agents; MIT (~10.8k stars). Useful reference for how BugSeek's backend could expose tools to its own agent.
- **Strix** — covered in depth in §7 (dedicated deep dive per Peer).

---

## 2. Bug Bounty Market — Payout Data (with plan correction)

**IMPORTANT CORRECTION to the product plan (§2.1, §9):** The plan states platforms "collectively paid out over $300M in bounties in 2025." Verification shows this conflates an annual figure with a lifetime figure:

- **HackerOne paid $81M in bounties over the 12 months Jul 2024–Jun 2025** (+13% YoY), per its 9th annual Hacker-Powered Security Report (published ~Sep 2025; also reported by BleepingComputer, Infosecurity Magazine).
  - Source: https://healsecurity.com/hackerone-paid-81-in-bug-bounty-with-emergence-of-bionic-hackers/ ; https://tech-insider.org/hackerone-vs-bugcrowd-vs-synack-2026/
- **HackerOne crossed $300M in *cumulative lifetime* payouts by March 2025** (Infosecurity Magazine; AI Security Intelligence).
  - Source: https://tech-insider.org/hackerone-vs-bugcrowd-vs-synack-2026/

Other 2025–26 data points (annual, recent):
- **Google VRP: $17M in 2025** (all-time high, +40% vs 2024; 700+ researchers). Google also uses Bugcrowd as its payment platform (per researcher-research notes, **UNCERTAIN** — secondhand).
  - Source: https://github.com/lissy93/bug-bounties/blob/HEAD/web/src/pages/learn/bug-bounty-economics-what-hunters-actually-earn.md
- **Microsoft: >$20M for Jul 2025–Jun 2026** (record; 562 researchers; prior year ~$17M); Microsoft attributes part of the surge to AI-assisted research.
  - Source: https://www.theregister.com/security/2026/08/04/ai-helps-microsoft-bug-hunters-chase-a-record-20m-payday/5282821
- **Meta: $4M in 2025; $25M lifetime.** Microsoft $16.6M in 2024, $60M+ lifetime.
  - Source: https://github.com/lissy93/bug-bounties/blob/HEAD/web/src/pages/learn/bug-bounty-economics-what-hunters-actually-earn.md
- **Bugcrowd: annual totals not disclosed; lifetime $50M+** (community aggregate estimate, secondhand — **UNCERTAIN**).
  - Source: https://github.com/lissy93/bug-bounties/blob/HEAD/web/src/pages/learn/bug-bounty-economics-what-hunters-actually-earn.md
- **Immunefi: total payouts UNVERIFIED** (no authoritative figure found in this research). One Sept 2025 research citation: **87.8% of cumulative platform spend ($88.34M) went to critical-severity bounties**; median payout ~$2,000 vs average ~$52,800 (power-law distribution).
  - Source: https://sqmagazine.co.uk/smart-contract-bug-bounties-statistics/

**Honest 2025 market sizing:** adding the verifiable annual figures (HackerOne $81M + Google $17M + Microsoft ~$20M + Meta $4M = ~$122M) plus undisclosed Bugcrowd/Immunefi/other programs, the collective annual figure is plausibly **~$130–150M**, not $300M. The plan's "$300M+" is better reframed as **"HackerOne alone has paid $300M+ lifetime; ~$81M in the last year, growing 13% YoY"** — still a strong investor line, and factually defensible.

Additional market color (all from HackerOne's 9th HPSR, via the sources above):
- 50,000+ researchers have earned at least one bounty; top 100 all-time earners collected ~$31.8M (~10% of lifetime payouts) — brutal power law, which is BugSeek's positioning opportunity ("help the other 49,900 earn").
- **AI trend:** 67% of researchers use AI/automation tools; 560+ "hackbot" (autonomous agent) valid reports submitted; AI-related vuln reports +210%; prompt-injection reports +540% YoY. The market is actively validating AI-assisted hunting.
- Source: https://healsecurity.com/hackerone-paid-81-in-bug-bounty-with-emergence-of-bionic-hackers/

---

## 3. Dev-Tool / Security SaaS Pricing Benchmarks

(All figures per-seat/month unless noted; sources dated 2026.)

| Tool | Free | Team / Mid | Enterprise | Source |
|---|---|---|---|---|
| **Snyk** | $0 (limited tests) | **$25/dev/mo** Team (annual); Ignite $1,260/dev/yr | Custom | https://dev.to/rahulxsingh/snyk-vs-semgrep-sca-platform-vs-custom-sast-rules-in-2026-3047 ; https://konvu.com/compare/snyk-vs-semgrep |
| **Semgrep** | $0 (OSS engine; free tier up to 10 contributors) | **$35/contributor/mo** Team | Custom | https://dev.to/rahulxsingh/is-snyk-worth-the-cost-complete-pricing-breakdown-for-2026-39m1 |
| **Socket** | free 1K scans | **$25/dev/mo** Team (per 2026 buyer research — **UNCERTAIN**, vendor page 403'd to automated clients) | $50/dev/mo+ | https://github.com/anoblescm/mcp-zero-trust-proxy/blob/HEAD/docs/research/BUYER-BEHAVIOR.md |
| **Burp Suite Pro** | Community free | **$449/user/yr ≈ $37/mo** single tier | $6,995–$29,450/yr plans | §1c sources |
| **GitHub Advanced Security** | — | **$49/committer/mo** | — | https://dev.to/rahulxsingh/8-best-snyk-alternatives-for-developer-security-in-2026-326k |
| **SonarQube** | Community free | ~$170/mo Developer (~$15–20/user/mo band) | ~$20–50k/yr | https://dev.to/rahulxsingh/8-best-snyk-alternatives-for-developer-security-in-2026-326k |
| **DeepSource / CodeRabbit / Codacy** | limited free | **$12–15/user/mo** | Custom | https://dev.to/rahulxsingh/8-best-snyk-alternatives-for-developer-security-in-2026-326k |
| **Nuclei Cloud (Neo)** | free tier | pay-as-you-go from $250 (50 credits/seat) — **UNVERIFIED** | Custom | https://github.com/vulnradar/vulnradar.dev/blob/HEAD/audits/AUDIT-014/research-competitors.md |
| **PTaaS (human-led)** | — | — | **~$30–150k/yr** quoted | https://github.com/evkir/cyberai/blob/HEAD/docs/competitive-landscape-2026.md |
| **AI web-pentest (per-test)** | — | Intruder **$3,500/test**; Corgea from **$4,000/test** (UNVERIFIED) | — | §1b sources |

**Sanity check on BugSeek's planned tiers:**
- **Free $0** (5 scans/mo, passive only): matches the freemium norm (Snyk, Semgrep, Nuclei all have real free tiers). ✅
- **Hunter $29/mo** (50 scans, active testing, full reports): sits right in the individual-tool band — cheaper than Burp Pro ($37/mo), in line with Snyk/Semgrep/Socket per-seat pricing. For a solo hunter, "$29/mo is less than one Burp license" is a clean pitch. ✅
- **Pro $99/mo** (unlimited, API, team sharing): between individual tooling and team SaaS; comparable to a single seat of GitHub Advanced Security. Plausible for freelance consultants expensing tools. ✅
- **Enterprise custom**: standard. ✅
- Watch item: the plan's Pro tier promises "unlimited scans" — with LLM agent calls as the marginal cost, "unlimited" is dangerous pricing; consider fair-use caps or credit-based metering before launch.

---

## 4. Chrome Web Store Policy — Security-Testing Tools

**Bottom line: no explicit, verifiable ban on penetration-testing extensions was found in the published CWS Developer Program Policies; but broad-permission extensions that perform automated testing/data collection face real review risk.** The plan's MEDIUM risk rating is appropriate — neither dismissible nor fatal.

Verified policy facts:
- CWS Developer Program Policies require extensions to be safe, transparent, high-quality, with a **single narrow purpose** and justified permissions (tabs, cookies, `<all_urls>`, webRequest, debugger all need written justification).
  - Source: https://developer.chrome.com/docs/webstore/program-policies/ (program policies index; fetched 2026-10-01)
- **Manifest V3 remotely-hosted-code (RHC) rules** are the binding architectural constraint: all logic must be discernible from the submitted package. Prohibited: remote `<script>` tags, `eval()` of fetched strings, building an interpreter for remotely-fetched commands. Explicitly allowed: syncing user data, fetching remote *config* (feature flags), server-side operations on data.
  - Source (quoting the policy): https://github.com/nnnkit/totem/blob/HEAD/plans/research/premium-monetization/raw/rs-cws-policy-ux.md
  - **Implication for BugSeek:** the Phase 2 agent cannot download "test plans" as executable code into the extension. The compliant architecture is what the plan already describes: the extension does browser-level sensing; the **backend API** does agent orchestration and returns *data* (findings), which is explicitly allowed ("performing server-side operations with data"). Keep this separation clean and review-proof.
- **New policy effective 2026-08-01:** Google added a rule prohibiting extensions "specifically designed to bypass security protections, usage restrictions, or other safeguards implemented by AI platforms." (Enforcement started Aug 1, 2026; non-compliant extensions face removal.)
  - Source: https://www.androidauthority.com/chrome-web-store-extension-stricter-rules-3684115/
  - Relevance: not aimed at pentesting, but shows Google's willingness to ban *categories* of security-adjacent tooling — a precedent the plan's risk section should cite.

Known cases / community knowledge (**all UNCERTAIN / UNVERIFIED at official level**):
- A Chrome-extension distribution guide states: "Google's content policies block some powerful tools (scrapers, automation)" and "Some of the most powerful SEO, scraping, and penetration testing tools are banned from the Chrome Web Store… sideloading is your only option." This is a third-party claim, not Google text — treat as directional, not authoritative.
  - Source: https://github.com/bankacem/chrome-extension-booster/blob/HEAD/public/content/articles/h/o/w/how-to-install-pro-chrome-extensions-the-definitive-guide.md
- Passive-recon extensions (Wappalyzer, Retire.js) **do** exist on CWS — so passive analysis tooling is demonstrably publishable. Active testing (sending attack payloads from an extension) is the grey zone; no verified published case of approval or rejection was found in this research.
- **Gap / recommendation:** before Phase 2 active-testing ships in a store-listed build, get a definitive read — e.g., submit the passive-only Phase 1 to CWS first (low risk), then test active features behind a clearly-consented, authorization-gated flow, and keep the self-sideload path (plan §8/§10 already proposes this fallback).

---

## 5. Bug Bounty Platform Integrations

### HackerOne
- **Public Hacker API v1**, documented at https://api.hackerone.com (docs site referenced across community tooling). Personal API token via HTTP Basic Auth.
- Verified-working endpoints per a community MCP client (third-party, tested against the API): programs list/details/scope, accepted weaknesses (CWE), own reports + activities, earnings/balance, hacktivity search, and **report submission** (`submit_report`).
- Typical submission fields: program handle, title, severity/CVSS vector, weakness (CWE), description, steps to reproduce, impact, attachments (PoC screenshots/video).
- **Policy caution:** automated *bulk* report submission is against platform expectations — one community policy summary (third-party, not HackerOne's own text) states bulk automated submission risks account blocks and that reports require verifiable PoC steps. **BugSeek should auto-generate the formatted report; the human submits.** This is a liability-relevant design decision.
- Sources: https://github.com/xtofuub/hackerone-mcp ; https://github.com/ruvnet/hackerone/blob/HEAD/docs/HACKERONE_POLICY.md (community policy summary — not official) ; https://github.com/izaurogabriel-hash/seguranca/blob/HEAD/09_bug_bounty/hackerone/README.md

### Bugcrowd
- **Bugcrowd API v1 (JSON:API 1.1.0) exists but access is restricted** — per a researcher skill doc (third-party): "restricted to paying enterprise customers and high-reputation researchers; no public researcher API" (secondhand — **UNCERTAIN**, but consistent with Bugcrowd's enterprise-first posture).
- Report severity uses **Bugcrowd VRT (Vulnerability Rating Taxonomy)**, not raw CVSS — BugSeek's report templates must map CVSS → VRT categories for Bugcrowd.
- Community tooling: `bbscope` pulls program scope via token; arkadiyt/bounty-targets-data mirrors public scopes.
- Typical draft fields: title, VRT category, description, steps to reproduce, impact, redacted PoC, remediation.
- Integration path for BugSeek: **no reliable programmatic submission** — generate a VRT-mapped, copy-paste-ready report; scope ingestion via public program pages/`bbscope`-style scraping (respecting ToS).
- Sources: https://github.com/julioxus/julius/blob/HEAD/.claude/skills/bugcrowd/SKILL.md ; https://github.com/0x1b3nc/ophackbot/blob/HEAD/bounty_knowledge/BUGCROWD.md ; https://docs.brinqa.com/docs/connectors/bugcrowd/

### Immunefi
- **No documented public API** (one research doc, Jun 2026: "No documented public API was found for bulk program data" — program pages are client-rendered). Unofficial community mirror exists (github.com/infosec-us-team/immunefi-bug-bounty-programs-unofficial) exposing program/policy/asset JSON via raw.githubusercontent.com — usable for **scope ingestion**, but unofficial and could break.
- Submission requirements are strict: **PoC required for ALL severity levels**; reports match findings to the program's "Impacts in Scope" list; KYC required for payout.
- Target: smart-contract / Web3 programs — mostly out of BugSeek's web-app scope, but "Impacts in Scope" matching is a good report-format lesson: BugSeek reports should explicitly map each finding to the target program's in-scope impact classes.
- Sources: https://github.com/infosec-us-team/immunefi-bug-bounty-programs-unofficial/blob/HEAD/README.md ; https://github.com/ssentaai/vaultdiligence/blob/HEAD/knowledge/external-sources/immunefi-bug-bounty-programs.md ; https://github.com/abhishek1kr/skillhub/blob/HEAD/library/reporting/web3-triage-report/SKILL.md ; https://github.com/stableexo/thewarden/blob/HEAD/github/2025-12-15/ssv_network_immunefi_exploration_2025-12-15.md

### What BugSeek needs to build (integration checklist)
1. **Scope ingestion:** HackerOne structured scopes via public API; Bugcrowd via program pages/`bbscope`; Immunefi via unofficial JSON mirror (UNVERIFIED stability).
2. **Report templates:** HackerOne (CVSS + CWE + steps/impact/attachments), Bugcrowd (VRT-mapped), Immunefi (impact-class mapping + mandatory PoC).
3. **No auto-submission:** all three platforms penalize automated report pipelines; BugSeek = "one-click formatted report export," human clicks submit.
4. Researcher identity headers (e.g., `X-HackerOne-*`-style headers some programs require) — per-program config in scope setup.

---

## 6. Strix — Deep Dive (flagged by Peer, Oct 2026)

All facts below verified against the Strix GitHub README + repo metadata, fetched **2026-10-01** from https://github.com/usestrix/strix.

**Snapshot (verified):**
- **65,894 stars, 7,221 forks, 836 commits**, repo created **2025-08-05**, **Apache 2.0** license, 29 releases.
- Tagline: *"The open-source AI pentesting tool. Autonomous AI hackers that find and fix your app's vulnerabilities."*
- GitHub topics include: `bug-bounty`, `ai-penetration-testing`, `ethical-hacking`, `offensive-security`, `security-automation`.
- Business site: strix.ai; docs at docs.strix.ai; managed cloud at app.strix.ai; PyPI package `strix-agent`.

**What it does (verified from README):** multi-agent ("Graph of Agents") autonomous pentesting — specialized agents for recon, exploitation, post-exploitation run in parallel, share discoveries, chain vulnerabilities. Real exploit validation via working PoCs (not scanner-style signature hits). Tooling: Caido HTTP interception proxy, automated browser exploitation (XSS/CSRF/clickjacking/auth bypass), shell/command execution, Python sandbox for custom PoC exploits, SAST + DAST, recon/OSINT (subdomain enumeration, fingerprinting), vulnerability knowledge base with **CVSS scoring and OWASP classification**. One-click **auto-fix via ready-to-merge pull requests**; compliance-ready pentest reports. Targets: local codebases, GitHub repos, black-box web apps, APIs via OpenAPI/Swagger/Postman. Headless mode, GitHub Actions CI/CD integration, local web viewer (`strix view`), and agent-ready skills installable via `npx skills add usestrix/strix` for Claude Code/Cursor/Codex.

**Use cases (verbatim from README):** Application Security Testing · Rapid Penetration Testing · **Bug Bounty Automation — "Automate bug bounty research and generate PoCs for faster reporting"** · CI/CD Integration.

**Business model — three tiers (verified from README):**
1. **Open Source** — free; runs locally with Docker + your own LLM key (any provider: OpenAI, Anthropic, Google…; even a ChatGPT subscription login is supported).
2. **Strix Cloud** — managed; "sign up for free," validated findings with PoCs, one-click autofix, continuous pentesting, DevSecOps integrations (GitHub, GitLab, Bitbucket, Slack, Jira, Linear, CI/CD).
3. **Enterprise** — SSO (SAML/OIDC), compliance-ready reports (SOC 2, ISO 27001, PCI DSS), dedicated support + SLA, VPC or self-hosted deployment, BYOK, tailored agents.

**What the open-source playbook buys them (analysis, grounded in the facts above):**
- **Distribution:** ~66k stars in ~14 months makes it the most-starred AI pentest agent on GitHub — far ahead of PentestGPT (~14.7k) and PentAGI (~21.7k). Stars → developers → the tool shows up in every "AI pentest" search and agent-skill install path.
- **Trust:** Apache 2.0 + runs locally with your own LLM key = no data leaves your machine (their `strix view` docs explicitly note "Nothing leaves your machine"). For security tooling, local-first open source is the trust shortcut.
- **Funnel:** free OSS → Cloud free signup → Enterprise. The OSS tier is a customer-acquisition engine, not just goodwill.
- **Ecosystem lock-in risk for BugSeek:** `npx skills add usestrix/strix` puts Strix *inside* Claude Code/Cursor/Codex workflows — the exact environment where BugSeek's planned "AI mentor" users live. BugSeek should assume a chunk of its target audience has already tried Strix.

### 6.1 Feature-by-feature comparison: Strix vs BugSeek's planned scope

| Capability (per BugSeek plan) | Strix status (verified) | BugSeek edge? |
|---|---|---|
| Passive recon (fingerprinting, headers, cookies, JS secrets, subdomain enum) | ✅ Has recon/OSINT agents (attack-surface mapping, subdomain enum, fingerprinting) | Partial — Strix covers this via agents; BugSeek's in-browser sensing may catch client-side detail (cookies, DOM, live JS) more natively |
| Active testing (XSS, SQLi, SSRF, SSTI, IDOR, CORS, auth, GraphQL, file upload, WS) | ✅ Comprehensive: OWASP Top 10+ (injection, SSRF, XXE, RCE, XSS, CSRF, IDOR/priv-esc, business logic, JWT, API security) + real PoC validation | ⚠️ Roughly at parity on paper; BugSeek's plan adds structure (context-aware mutation, attack-chain reasoning) but Strix *validates with working PoCs* — the highest-evidence bar |
| Exploit validation (false-positive reduction) | ✅ **Core strength** — "working PoCs, not false positives"; independent exploit runtime | ❌ BugSeek must match this; unverified exploit claims are exactly what platforms penalize |
| Honeypot/trap detection | ❌ Not claimed anywhere in README/features | ✅ **Real differentiator** — Strix has no canary/honeypot concept; BugSeek's trap-probability scoring is genuinely novel vs Strix |
| Contextual reasoning / business-context severity | ⚠️ "Continuous learning… adapts to your codebase" (Cloud) — developer context, not target-business context | ✅ BugSeek's contextual severity (is this a payment endpoint? a demo site?) is a different axis — hunter-relevant, not developer-relevant |
| CVSS + report for bounty submission | ✅ CVSS + OWASP classification; compliance reports (SOC 2/ISO/PCI) — **audit-oriented, not bounty-platform-oriented** | ✅ HackerOne/Bugcrowd/Immunefi submission templates (VRT mapping, PoC-attachment guidance) is BugSeek territory Strix ignores |
| Auto-fix via PRs | ✅ One-click autofix (Cloud) | N/A — BugSeek is hunter-side (findings), not defender-side (fixes); don't compete here |
| Chrome-extension / in-browser UX | ❌ None — developer-first CLI + local web viewer + cloud dashboard | ✅ **Strongest wedge** — BugSeek meets the hunter *in the browser where the target is open*; zero setup vs Docker+LLM-key |
| Bug bounty workflow | ⚠️ Listed as a use case ("Bug Bounty Automation") but the product shape is dev-tool-shaped (scan repo → fix PR) | ✅ BugSeek is hunter-workflow-shaped (scope confirmation → scan → platform-ready report) |
| Cost to the individual | OSS free (own LLM key) / Cloud free signup | BugSeek $29/mo must beat "Strix OSS free" on **convenience + hunter-specific output**, not on raw capability |

### 6.2 Honest assessment: where Strix wins

1. **Distribution and trust:** 66k stars + Apache 2.0 + local-first is a moat a closed-source newcomer can't buy. BugSeek cannot out-open-source Strix.
2. **Validation rigor:** working-PoC-everything is the exact bar BugSeek's agent must clear; Strix set it publicly.
3. **Ecosystem position:** inside coding agents (Claude Code/Cursor/Codex) via skills; BugSeek's planned audience (security students, hunters who code) overlaps heavily.
4. **Defensive completeness:** SAST+DAST, auto-fix PRs, CI/CD, compliance reports — BugSeek should not chase these; they're developer-workflow features with no hunter payoff.

### 6.3 Strategic implications for BugSeek's positioning

- **Do not position as "autonomous pentesting agent" in the abstract** — that sentence now belongs to Strix, XBOW, Corgea, and PentestGPT. BugSeek's positioning sentence should be: *"the AI security researcher that lives in your browser"* — Chrome-extension UX, one click, no Docker, no LLM keys, no CLI.
- **Double down on the two things Strix verifiably doesn't do:** (a) **honeypot/trap detection** (no Strix feature mentions it), and (b) **bounty-platform-native reporting** (Strix's reports are compliance-shaped; BugSeek's are HackerOne/Bugcrowd/Immunefi-shaped with VRT mapping and submission-ready PoC evidence).
- **Consider compatibility, not just competition:** BugSeek's backend could run Strix (or Nuclei) as one of the agent's tools — "bring the best open-source engines, add the browser UX and the hunter judgment layer." That turns Strix's moat into BugSeek's supply chain.
- **Pricing note:** Strix OSS is free (bring your own LLM key ≈ $5–20/mo in model costs for moderate use). BugSeek's $29/mo Hunter tier must be justified by **zero-setup UX + honeypot detection + platform-ready reports** — i.e., sell time saved and report quality, not scanning capability.

---

## 7. Cross-Cutting Implications for BugSeek

1. **Fix the market number before it reaches investors.** Replace "$300M+ paid in 2025" with: "HackerOne paid $81M in the last year (+13% YoY) and $300M+ lifetime; the verifiable 2025 platform total is ~$130–150M." (§2)
2. **The wedge is real but narrower than the plan implies.** The plan's core claim — "no tool combines autonomous active testing + contextual AI reasoning + honeypot detection + Chrome-extension UX for individual hunters" — survives: Strix covers the first two as a CLI, XBOW/Corgea as enterprise engines, PentestGPT as research. **Nobody owns the browser-native hunter workflow.** Guard that phrasing.
3. **Pricing is defensible; "unlimited scans" is not.** Benchmarks support $29/$99. Cap or meter Pro-tier agent usage (LLM calls are the marginal cost). (§3)
4. **Ship Phase 1 (passive) to CWS; gate Phase 2 (active).** Passive recon is demonstrably publishable (Wappalyzer/Retire.js precedent); active testing is the grey zone. Keep the sideload fallback the plan already names. (§4)
5. **Integration strategy: format, don't submit.** HackerOne API supports programmatic submission but platform norms punish automation; Bugcrowd's API is gated; Immunefi has none. Build best-in-class export (H1 fields/CVSS/CWE, Bugcrowd VRT mapping, Immunefi PoC-mandatory format); let the human click submit. (§5)
6. **Treat Strix as the benchmark, not the enemy.** Match its PoC-validation bar; beat it on browser UX, hunter workflow, honeypot detection, and platform-native reports; optionally integrate it as an engine. (§6)

---

## 8. What's UNVERIFIED / needs follow-up

- Burp Suite's exact 2026 AI feature set and any price changes since $449/yr.
- Nuclei Cloud ("Neo") pay-as-you-go pricing ($250/50 credits) — not confirmed on vendor page.
- Corgea per-pentest pricing ($4,000) — secondhand citation only.
- MindFort, BugDazz — watch-list names, no verified pricing/details.
- Bugcrowd API access restrictions ("enterprise + high-rep researchers only") — community claim, not vendor-confirmed.
- Immunefi total payouts — no authoritative figure found.
- Any *specific* CWS rejection/approval case for a pentesting extension — none found; needs direct testing or developer-forum research.
- HackerGPT/HackGPT commercial status — no independent verification of current product/pricing.

---
*End of brief. Research by Worker 1, 2026-10-01.*

---

## AI backend strategy — key conclusions (see docs/ai-strategy.md)

*Added 2026-10-01 by the AI-strategy research worker. Full analysis: `docs/ai-strategy.md`.*

**How Strix does it (verified from the repo, https://github.com/usestrix/strix):** provider-agnostic routing through **LiteLLM** (`STRIX_LLM="openrouter/z-ai/glm-5.3"` — a cheap OpenRouter default, ~$0.22/$3.39 per 1M tokens). **Two-tier model routing**: a main agent model plus a separate, cheaper dedupe-judge model (`STRIX_DEDUPE_MODEL`) on its own endpoint/credentials. Cost controls worth copying: per-scan budget caps with **real** provider-reported cost capture (OpenRouter `usage.cost`, not estimates), prompt caching, context compaction, per-turn tool-call caps (32), reasoning-effort dial. Local models (Ollama) supported but Strix is candid that <70B models struggle with agentic tool use — local is for privacy, not for the agent loop.

**Price landscape (verified 2026-10-01):** Anthropic official — Haiku 4.5 **$1/$5**, Sonnet 5/5.5 **$2/$10**, Sonnet 4.6 $3/$15, Opus 5.5 **$4/$20** (new), Opus 4.5–5 $5/$25, Fable $10/$50 (batch = 50% off). OpenAI current line — gpt-6-luna **$0.10/$0.50**, gpt-6.1-sol $2/$10, plus a security-specialized **gpt-5.6-cyber ("Daybreak") at $12.50/$75**. OpenRouter live — deepseek-v4-pro **$0.21/$0.42**, glm-5.3-flash $0.15/$0.50, qwen3.8-flash $0.15/$0.47, gemini-3.1-flash-lite $0.25/$1.50.

**Recommendation for BugSeek (student budget, must actually find bugs):**
1. **Tiered routing by task difficulty**: Tier 0 = deterministic (headers, cookies, TLS, regexes, CVE lookups — no LLM); Tier 1 = cheap models for high-volume triage/classification/dedup (~$0.03–0.50/1M); Tier 2 = strong models (Sonnet-5-class) only for attack-chain reasoning, honeypot judgment, exploit validation — escalate on low confidence only.
2. **Default gateway: OpenRouter** (single key, exact per-call cost capture) with cheap defaults — `deepseek/deepseek-v4-pro` for the agent, `z-ai/glm-5.3-flash` for triage. **Estimated ~$0.10–0.25 per deep scan, ~$0.01 per passive scan** (token assumptions stated in the full doc; instrument and measure).
3. **Free tier** = metered credits (~10 deep scans/month ≈ $1–2/user) + BYO-key unlimited (the Strix playbook). **Hunter $29** = Sonnet-5-class escalation, ~$4–6/mo AI budget; **Pro $99** = stronger Tier-2 default, longer agent horizons, ~$15–25/mo AI budget.
4. **Local Ollama/LM Studio** for Tier-1 triage (free, privacy) but keep the plan→act→observe→reflect loop on hosted APIs.
5. Guardrails to build from day one: per-call cost caps by tier, per-user monthly budgets with alerts, fallback chains that never silently upgrade tiers, batch API for offline re-triage.

### Provider decision update (Google AI/Gemini, Oct 2026)

*Added 2026-10-01. The OpenRouter-default recommendation above is SUPERSEDED as the default; retained as a fallback-provider reference.*

**Gemini chosen as BugSeek's primary LLM provider** — verified from Google's official docs (model IDs: https://ai.google.dev/gemini-api/docs/models; pricing: https://ai.google.dev/gemini-api/docs/pricing, both current as of 2026-10-01 UTC). Tiering maps onto Google's own lines: **Flash-class for routine/high-volume work** (`gemini-3.8-flash` as the default agent model at **$0.75/$3.75** per 1M input/output through Dec 31, 2026 — then $1.50/$7.50 from Jan 1, 2027; `gemini-2.5-flash-lite` at **$0.10/$0.40** for the cheapest Tier-1 triage/dedup/classification work) and **Pro-class for complex reasoning** (`gemini-3.1-pro-preview` at $2.00/$12.00 for attack-chain analysis, honeypot judgment, exploit validation — escalate on low confidence only; `gemini-2.5-pro` at $1.25/$10.00 as cheaper fallback). Discounts: Batch/Flex API = 50% off (good for offline re-triage); context caching ≈ 10% of input price + $1.00/1M/hr storage; free tier available for dev/beta (content used to improve Google's products — not for production).

**Headline per-scan costs (estimates, token assumptions stated in docs/ai-strategy.md):** passive scan **≈ $0.01**, deep scan on Flash-class **≈ $0.25–0.50**, deep scan with Pro-class escalation **≈ $0.45–0.75**; expect roughly double after the Jan-1-2027 pricing cliff on 3.x intro rates. Fallback on errors/rate limits: backoff → cascade within Flash tier (`3.8` → `3.7` → `3.6`) → degrade to Tier-1 with "reduced confidence" labels; BYO-key retained per the Strix playbook. Full updated analysis in `docs/ai-strategy.md` §0; deterministic-first guidance (§B.5) is unchanged.
