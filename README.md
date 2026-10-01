# BugSeek AI

AI-powered security reconnaissance for bug bounty hunters. A Chrome extension (Manifest V3) that passively maps a target's attack surface, plus an optional backend that runs an autonomous AI agent swarm for deeper active testing.

## What it does

**Passive recon** — runs entirely in the extension, no backend needed:

- DOM analysis: forms, inputs, hidden fields, iframes, HTML comments, inline event handlers, DOM XSS sinks
- Secret scanning: hardcoded AWS keys, Stripe keys, API tokens, private keys, JWTs and more in page JavaScript
- Cookie audit: missing `Secure` / `HttpOnly` / `SameSite` flags, overly broad domain scoping
- Security headers: CSP, HSTS, X-Frame-Options and friends checked against OWASP best practices
- Tech fingerprinting: frameworks, CMS and server software from headers, meta tags and script URLs
- One-click Markdown report with severity-grouped findings and remediation advice

**Active testing** — locked until you confirm authorization (bug bounty program, pentest contract, or ownership) and define the scope:

- CORS misconfigurations, GraphQL introspection, reflected XSS, IDOR, auth posture, API endpoint discovery
- Every request goes through scope checks and a rate limiter — nothing fires outside what you authorized
- CVSS v3.1 scoring on every finding, honeypot/trap detection, and attack-chain narratives that link findings into bigger stories
- Deep Inspect mode: opt-in capture of response bodies via the Chrome DevTools protocol, for hunting secrets and debug output leaked in API responses

**AI agent swarm** (backend) — a head agent deploys specialist worker agents (recon, secrets, headers, CORS, XSS, IDOR, auth, GraphQL) that probe the target autonomously and report back. The head agent dedupes their findings, chains them, and writes the summary.

```bash
cd backend && npx tsx src/multiagent/cli.ts --target https://example.com
```

## Project layout

```
bugseek/
├── manifest.json
├── src/
│   ├── background.ts      # service worker: header capture + scan orchestration
│   ├── content.ts         # content script: passive DOM collection
│   ├── scanners/          # passive scanners (DOM, secrets, cookies, headers)
│   ├── active/            # active testing (HTTP client, probes, CVSS, chains)
│   ├── lib/               # shared: types, rate limiter, authorization, reporting
│   └── popup/             # extension UI
├── backend/
│   └── src/
│       ├── agent/         # single-agent recon loop
│       ├── multiagent/    # head agent + specialist worker swarm
│       ├── routes/        # API (scans, swarm, reports, auth)
│       └── guardrails/    # scope checks, SSRF guards, redaction, rate limits
├── docs/                  # business plan, pitch deck, schemas, terms
├── landing/               # landing page
└── brand/                 # identity, icons
```

## Build the extension

```bash
npm install
npm run build   # output goes to dist/
```

Then in Chrome: `chrome://extensions` → enable Developer mode → Load unpacked → select `dist/`. Reload any tabs that were already open, open the popup on a target you're authorized to test, and hit **Scan this page**.

## Run the backend

```bash
cd backend
npm install
cp .env.example .env   # add your GEMINI_API_KEY
npm run dev
```

The extension works fully standalone — the backend just adds AI deepening and the agent swarm. Save your backend API key in the extension popup (Active tab) to connect them.

## Try it on something safe

Only ever scan targets you own or are authorized to test. [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) is the classic practice target:

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
# then scan http://localhost:3000
```

## Pricing

Scout (free, 50 credits/month), Hunter ($29/mo, 300 credits), Pro ($99/mo, 1500 credits). Passive scans cost 1 credit, agent scans cost 25. See `docs/business-plan.md` for the full model.
