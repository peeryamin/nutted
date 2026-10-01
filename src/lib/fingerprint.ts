/**
 * Technology fingerprinting from passive signals: response headers,
 * meta tags, script URLs, DOM markers, and page JS globals.
 */
import type { DomScanData, TechFingerprint } from './types';

function extractVersion(text: string): string | undefined {
  const m = text.match(/(\d+\.\d+(?:\.\d+)?)/);
  return m ? m[1] : undefined;
}

export function fingerprintTech(
  headers: Record<string, string>,
  dom: DomScanData,
): TechFingerprint[] {
  const tech: TechFingerprint[] = [];
  const add = (
    name: string,
    version: string | undefined,
    source: TechFingerprint['source'],
  ): void => {
    const clean = name.trim();
    if (!clean) return;
    if (!tech.some((t) => t.name.toLowerCase() === clean.toLowerCase())) {
      tech.push({ name: clean, version, source });
    }
  };

  const h = (name: string): string | undefined => headers[name.toLowerCase()];

  // --- Response headers ---
  const server = h('server');
  if (server) {
    const name = server.split('/')[0].split(' ')[0];
    add(name, extractVersion(server), 'header');
  }
  const poweredBy = h('x-powered-by');
  if (poweredBy) add(poweredBy.split('/')[0], extractVersion(poweredBy), 'header');
  const aspnet = h('x-aspnet-version');
  if (aspnet) add('ASP.NET', aspnet, 'header');
  if (h('x-generator')) add(h('x-generator') as string, extractVersion(h('x-generator') as string), 'header');

  // --- Meta tags ---
  for (const meta of dom.metaTags) {
    const name = meta.name.toLowerCase();
    if (name === 'generator' && meta.content) {
      add(meta.content.split(' ')[0], extractVersion(meta.content), 'meta');
    }
  }

  // --- Script URLs ---
  for (const src of dom.externalScripts) {
    const s = src.toLowerCase();
    if (s.includes('wp-content') || s.includes('wp-includes')) add('WordPress', undefined, 'script');
    if (s.includes('/_next/')) add('Next.js', undefined, 'script');
    if (s.includes('drupal')) add('Drupal', undefined, 'script');
    if (s.includes('joomla')) add('Joomla', undefined, 'script');
    const jq = s.match(/jquery[.-](\d+\.\d+(?:\.\d+)?)/);
    if (jq) add('jQuery', jq[1], 'script');
    const ng = s.match(/angular[.-](\d+\.\d+(?:\.\d+)?)/);
    if (ng) add('AngularJS', ng[1], 'script');
    if (s.includes('react') && s.includes('.js')) add('React', extractVersion(s), 'script');
    const bs = s.match(/bootstrap[.-](\d+\.\d+(?:\.\d+)?)/);
    if (bs) add('Bootstrap', bs[1], 'script');
    if (s.includes('vue')) add('Vue.js', extractVersion(s), 'script');
    if (s.includes('shopify')) add('Shopify', undefined, 'script');
    if (s.includes('googletagmanager') || s.includes('google-analytics')) add('Google Analytics', undefined, 'script');
  }

  // --- Page JS globals (collected via MAIN-world probe) ---
  for (const g of dom.globals) {
    const m = g.match(/^(.+?)\s+([\d.]+)$/);
    if (m) add(m[1], m[2], 'global');
    else add(g, undefined, 'global');
  }

  return tech;
}
