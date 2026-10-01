# BugSeek AI — Brand Identity

**Status:** v1 direction (Oct 2026). Locked enough to ship icons, landing page, and deck; open to refinement before public launch.

## 1. Name & lockup

- **Product name:** BugSeek AI (never "Bugseek", "bug-seek", or "BugSeekAI").
- **Wordmark lockup:** `BugSeek` in semibold, `AI` in the mint accent — e.g. **BugSeek** *AI*.
- **Tagline (primary):** *The security researcher in your browser.*
- **Tagline (alt, short):** *Find what scanners miss.*
- **Descriptor line (store listings, SEO):** AI-powered security reconnaissance for bug bounty hunters — passive recon today, guided active testing with your authorization.

## 2. Logo

- **Master:** `brand/logo.svg` (512×512 viewBox). Rasterized icons in `brand/icons/`: `icon16.png`, `icon32.png`, `icon48.png`, `icon128.png` (MV3-ready).
- **Concept:** a magnifying glass (the "seek") whose lens contains a stylized beetle (the "bug"). The bug deliberately breaks the lens boundary — the finding escapes the glass. Reads as *investigation that produces results*, not just scanning.
- **Construction:** dark rounded-square tile (gradient `#17233D → #0A0F1E`, radius 116/512), mint gradient ring + handle (`#5EEAD4 → #34D399`), bone-white bug glyph (`#EAF6F0`).
- **Usage rules:**
  - Never redraw, recolor, or add effects (no shadows, no gradients on the glyph).
  - Minimum digital size: 16px (toolbar). Below that, use the ring-only simplification (to be drawn if needed).
  - Clear space: at least the height of the bug glyph on all sides.
  - Works on light and dark backgrounds as-is (the tile carries its own dark field).

## 3. Color palette

| Token | Hex | Usage |
|---|---|---|
| Ink | `#0A0F1E` | Primary dark background |
| Panel | `#131B2E` | Cards, surfaces on dark |
| Mint | `#34D399` | Primary accent — CTAs, active states, the "found something" color |
| Mint light | `#5EEAD4` | Gradient partner, highlights |
| Bone | `#EAF6F0` | Bug glyph, high-contrast marks on dark |
| Paper | `#F8FAFC` | Light-mode background |
| Slate | `#64748B` | Secondary text |
| Amber | `#FBBF24` | Warnings, honeypot-suspicion flags |
| Red | `#F87171` | Critical findings, destructive actions |

Dark-mode-first: the product lives in a browser popup developers keep open at night. All marketing surfaces should look intentional on dark backgrounds. Mint-on-ink passes WCAG AA for large text/UI; body copy on dark uses `#CBD5E1` (slate-300), not pure white.

## 4. Typography

- **Display / headings:** "Space Grotesk", fallback `system-ui, -apple-system, "Segoe UI", sans-serif`. Geometric, technical, distinctive — the "lab instrument" voice.
- **Body / UI:** "Inter", fallback `system-ui, sans-serif`. Neutral and readable at small sizes (extension popup!).
- **Code / findings:** `ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace`.
- **Rule:** webfonts are progressive enhancement only. Every surface (landing page, deck, extension) must render correctly with system fonts if webfonts fail — never a blank or broken layout.

## 5. Tone of voice

BugSeek speaks like a senior hunter mentoring a junior one: direct, precise, allergic to hype.

- **Do:** concrete verbs ("scan", "flag", "explain", "export"), honest scoping ("passive recon — no requests sent"), numbers only when sourced.
- **Don't:** "military-grade", "unhackable", "AI that hacks for you", fake urgency, invented statistics, testimonials we don't have.
- **Security copy rule:** every claim about capability is paired with its boundary ("Active testing runs only on targets you've confirmed you're authorized to test.").
- **Example hero line:** "Passive recon in one click. Guided active testing when you're authorized. Reports your platform will accept."

## 6. Imagery direction

- Dark terminal/browser-chrome mockups, real finding cards (severity chips, CVSS, evidence), never stock-photo hackers in hoodies.
- Screenshots > illustrations for product surfaces. Demos run on intentionally vulnerable apps (OWASP Juice Shop, DVWA) — say so on-screen.
- Honeypot detection gets its own visual language: amber trap/flag motif.

## 7. File map

```
brand/
  identity.md        ← this file
  logo.svg           ← master artwork (edit here, re-rasterize)
  icons/
    icon16.png       ← MV3 toolbar
    icon32.png
    icon48.png       ← extension management page
    icon128.png      ← Chrome Web Store listing
```

Re-rasterize after any logo edit: `cairosvg.svg2png(url='logo.svg', write_to='icons/icon<N>.png', output_width=N, output_height=N)` for N in 16/32/48/128. They are already wired into `manifest.json` under `"icons"` and `"action.default_icon"`.
