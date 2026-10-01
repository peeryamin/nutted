# BugSeek AI — Responsible Disclosure Policy

> **DRAFT — requires review by a qualified lawyer before publication.** This policy covers (a) how *users of BugSeek AI* should disclose vulnerabilities they find, and (b) how *external researchers* can report vulnerabilities in BugSeek AI itself.

---

## Part A — For BugSeek AI users: disclosing what you find

If BugSeek AI helps you discover a vulnerability in a third-party system:

1. **Check authorization first.** Only test and report within a scope you are authorized for (bug bounty program, contract, or your own systems). See Terms of Service §2.
2. **Do not exploit beyond proof.** Validate with the minimum proof-of-concept needed to demonstrate impact. Do not access, modify, or delete data beyond what the program rules allow. Do not pivot to out-of-scope systems.
3. **Report through the owner's channel.** Use the bug bounty platform's submission flow (HackerOne, Bugcrowd, Immunefi) or the vendor's published security contact. BugSeek AI formats the draft — **you** review and submit it.
4. **Protect sensitive data.** Redact credentials, tokens, and personal data from reports and evidence. Findings describe the vulnerability; they don't reproduce the loot.
5. **Give the owner time.** Follow the program's disclosure timeline. Do not publicly disclose before the owner has had a reasonable opportunity to remediate (programs typically specify 30–90 days).
6. **Traps are not trophies.** If BugSeek flags a finding as a likely honeypot, do not submit it as a genuine vulnerability — and do not attempt to "test" the trap operator's infrastructure in retaliation.

**Safe-harbor commitment to our users:** BugSeek AI will not terminate your account or share your scan data with third parties *solely* because you conducted authorized testing in good faith and complied with this policy and our Terms. (This is a policy commitment, not legal immunity — only the target owner or a court can grant that.)

---

## Part B — For external researchers: reporting vulnerabilities in BugSeek AI

Found a security issue in BugSeek AI itself (the extension, the backend API, or our infrastructure)? We want to hear from you.

### Scope

- In scope: `*.bugseek.ai` production hosts, the published Chrome extension (current version), the public API documented for your tier.
- Out of scope: third-party services we integrate with, social engineering of our team or users, denial-of-service testing, spam.

### Rules of engagement

- Test only in-scope systems, with minimal, non-destructive proof-of-concepts.
- Do not access other users' data. If you accidentally do, stop immediately and tell us.
- Do not publicly disclose before we've had **90 days** to remediate (we'll keep you updated on progress).
- No automated bulk scanning that degrades the service.

### Safe harbor

**We will not pursue legal action** against researchers who follow this policy in good faith, and we will advocate to any affected third party that your activity was authorized research under this policy. (Criminal law varies by jurisdiction; this is our commitment, not a guarantee about how authorities act.)

### What to include in your report

Use this template:

```
Title: [short, specific]
Severity: [your assessment + CVSS vector if known]
Scope: [exact host / extension version / endpoint]
Description: [what's wrong and why it matters]
Steps to reproduce:
  1.
  2.
  3.
Impact: [what an attacker could do]
Suggested remediation: [optional]
Contact: [how we reach you — PGP key optional]
Attachments: [screenshots / PoC code — redact any sensitive data]
```

### Contact

- Security reports: **[security@bugseek.ai — TO BE CREATED]**
- Expected response: acknowledgment within **3 business days**; triage update within **10 business days**.
- We do not currently operate a paid bounty program. We will credit researchers (with permission) in release notes and maintain a public hall of thanks.

---

## Part C — Vulnerability handling commitments (our side)

1. Every in-scope report gets a human triage owner.
2. Critical issues in the extension or API: patch target **14 days**; the extension update is pushed through the Chrome Web Store immediately on release.
3. We publish a brief postmortem for critical issues after remediation (no researcher PII without consent).

---

*Draft prepared October 2026. Publish only after legal review and after the security@ contact exists.*
