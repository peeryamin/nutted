#!/usr/bin/env python3
"""Convert BugSeek markdown docs to styled standalone HTML twins.

Usage: python3 md2html.py in.md out.html "Page Title"
Covers the markdown subset used in our docs: headings, lists, tables,
blockquotes, bold/italic/code/links, hr, fenced code blocks.
"""
import html, re, sys

CSS = """
:root{--ink:#0A0F1E;--panel:#131B2E;--mint:#34D399;--mint-lt:#5EEAD4;
--amber:#FBBF24;--body:#CBD5E1;--slate:#64748B;--red:#F87171}
*{box-sizing:border-box}
body{margin:0;background:var(--ink);color:var(--body);
font-family:"Inter",system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.7;font-size:16.5px}
.wrap{max-width:860px;margin:0 auto;padding:48px 24px 80px}
a{color:var(--mint-lt)}
h1,h2,h3{font-family:"Space Grotesk",system-ui,sans-serif;color:#fff;line-height:1.25;letter-spacing:-.01em}
h1{font-size:2.1rem;border-bottom:2px solid rgba(52,211,153,.35);padding-bottom:.4em}
h2{font-size:1.45rem;margin-top:2.2em}
h3{font-size:1.15rem}
code{font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--mint-lt);font-size:.9em}
pre{background:#070b16;border:1px solid rgba(148,163,184,.2);border-radius:10px;padding:16px;overflow-x:auto}
pre code{color:#a9f5d6}
blockquote{border-left:4px solid var(--amber);background:rgba(251,191,36,.06);
margin:1.5em 0;padding:12px 18px;border-radius:0 10px 10px 0}
blockquote p{margin:.4em 0}
table{width:100%;border-collapse:collapse;margin:1.2em 0;font-size:.95rem;display:block;overflow-x:auto}
th{text-align:left;color:var(--mint-lt);padding:10px 12px;border-bottom:2px solid rgba(52,211,153,.35);white-space:nowrap}
td{padding:10px 12px;border-bottom:1px solid rgba(148,163,184,.15);vertical-align:top}
hr{border:none;border-top:1px solid rgba(148,163,184,.25);margin:2.5em 0}
strong{color:#fff}
.back{display:inline-block;margin-bottom:24px;color:var(--slate);text-decoration:none;font-size:.9rem}
.back:hover{color:#fff}
.docfoot{margin-top:3em;padding-top:1.5em;border-top:1px solid rgba(148,163,184,.2);color:var(--slate);font-size:.85rem}
"""

def inline(t):
    t = html.escape(t)
    t = re.sub(r'`([^`]+)`', r'<code>\1</code>', t)
    t = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', t)
    t = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', t)
    return t

def convert(md):
    lines = md.split('\n')
    out, i = [], 0
    in_code = False
    while i < len(lines):
        ln = lines[i]
        if ln.strip().startswith('```'):
            if not in_code: out.append('<pre><code>'); in_code = True
            else: out.append('</code></pre>'); in_code = False
            i += 1; continue
        if in_code:
            out.append(html.escape(ln)); i += 1; continue
        s = ln.strip()
        if not s:
            i += 1; continue
        if s == '---':
            out.append('<hr>'); i += 1; continue
        m = re.match(r'^(#{1,3})\s+(.*)', s)
        if m:
            out.append(f"<h{len(m.group(1))}>{inline(m.group(2))}</h{len(m.group(1))}>"); i += 1; continue
        if s.startswith('>'):
            buf = []
            while i < len(lines) and lines[i].strip().startswith('>'):
                buf.append(lines[i].strip()[1:].strip()); i += 1
            out.append('<blockquote>' + ''.join(f'<p>{inline(b)}</p>' for b in buf) + '</blockquote>')
            continue
        if re.match(r'^\|.*\|$', s):
            rows = []
            while i < len(lines) and re.match(r'^\|.*\|$', lines[i].strip()):
                rows.append([c.strip() for c in lines[i].strip().strip('|').split('|')]); i += 1
            # drop separator row (---|---)
            rows = [r for r in rows if not all(re.match(r'^:?-{2,}:?$', c) for c in r)]
            thead = '<tr>' + ''.join(f'<th>{inline(c)}</th>' for c in rows[0]) + '</tr>'
            tbody = ''.join('<tr>' + ''.join(f'<td>{inline(c)}</td>' for c in r) + '</tr>' for r in rows[1:])
            out.append(f'<table><thead>{thead}</thead><tbody>{tbody}</tbody></table>')
            continue
        if re.match(r'^[-*]\s+', s):
            buf = []
            while i < len(lines) and re.match(r'^[-*]\s+', lines[i].strip()):
                buf.append(re.sub(r'^[-*]\s+', '', lines[i].strip())); i += 1
            out.append('<ul>' + ''.join(f'<li>{inline(b)}</li>' for b in buf) + '</ul>')
            continue
        if re.match(r'^\d+\.\s+', s):
            buf = []
            while i < len(lines) and re.match(r'^\d+\.\s+', lines[i].strip()):
                buf.append(re.sub(r'^\d+\.\s+', '', lines[i].strip())); i += 1
            out.append('<ol>' + ''.join(f'<li>{inline(b)}</li>' for b in buf) + '</ol>')
            continue
        # paragraph: gather continuation lines
        buf = [s]
        i += 1
        while i < len(lines) and lines[i].strip() and not re.match(r'^(#{1,3}\s|>|---|[-*]\s|\d+\.\s|\|.*\||```)', lines[i].strip()):
            buf.append(lines[i].strip()); i += 1
        out.append('<p>' + inline(' '.join(buf)) + '</p>')
    return '\n'.join(out)

def main():
    src, dst, title = sys.argv[1], sys.argv[2], sys.argv[3]
    md = open(src).read()
    body = convert(md)
    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} — BugSeek AI</title>
<style>{CSS}</style></head>
<body><div class="wrap">
<a class="back" href="../landing/index.html">← BugSeek AI</a>
{body}
<p class="docfoot">BugSeek AI · Draft document — the Markdown source is canonical. Requires review before public use where noted.</p>
</div></body></html>"""
    open(dst, 'w').write(page)
    print(f'wrote {dst} ({len(page)} chars)')

if __name__ == '__main__':
    main()
