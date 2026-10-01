/**
 * CORS misconfiguration testing (active testing).
 *
 * Probes the target with varied Origin headers and classifies the response:
 *  - wildcard (`*`) + Access-Control-Allow-Credentials → high
 *  - reflected arbitrary origin + credentials → high
 *  - `null` origin accepted + credentials → medium
 *  - reflected origin without credentials → low
 *
 * Browsers forbid setting the Origin header via fetch(), so the probe uses
 * chrome.declarativeNetRequest session rules (temporary, removed after each
 * probe) to rewrite the header. When DNR is unavailable the tester falls
 * back to a single observational GET.
 */
import { scoreFinding } from '../lib/cvss';
import type { Finding } from '../lib/types';
import type { ActiveHttpClient } from './httpClient';

let findingSeq = 0;

function nextId(): string {
  findingSeq++;
  return `cors-${findingSeq}`;
}

function cvssFields(presetKey: string): Pick<
  Finding, 'cvssScore' | 'cvssVector' | 'cvssJustification' | 'references'
> {
  const s = scoreFinding(presetKey);
  return {
    cvssScore: s.score,
    cvssVector: s.vector,
    cvssJustification: s.justification,
    references: s.references,
  };
}

const DNR_RULE_ID = 9001;
const EVIL_ORIGIN = 'https://evil-bugseek.example';
const EVIL_ORIGIN_2 = 'https://sub.evil-bugseek.example';

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function setProbeOrigin(host: string, origin: string): Promise<boolean> {
  try {
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: [DNR_RULE_ID],
      addRules: [
        {
          id: DNR_RULE_ID,
          priority: 1,
          action: {
            type: chrome.declarativeNetRequest.RuleActionType.MODIFY_HEADERS,
            requestHeaders: [
              {
                header: 'Origin',
                operation: chrome.declarativeNetRequest.HeaderOperation.SET,
                value: origin,
              },
            ],
          },
          condition: {
            regexFilter: `^https?://([^/]*\\.)?${escapeRegex(host)}/`,
            resourceTypes: [
              chrome.declarativeNetRequest.ResourceType.XMLHTTPREQUEST,
              chrome.declarativeNetRequest.ResourceType.OTHER,
            ],
          },
        },
      ],
    });
    return true;
  } catch {
    return false;
  }
}

async function clearProbeOrigin(): Promise<void> {
  try {
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: [DNR_RULE_ID],
    });
  } catch {
    /* best effort */
  }
}

interface OriginProbeResult {
  origin: string;
  allowOrigin: string;
  allowCredentials: boolean;
  status: number;
}

/**
 * Probe one URL with several origins. Returns findings (at most a few — the
 * worst misconfiguration wins) and the number of requests spent.
 */
export async function testCors(
  http: ActiveHttpClient,
  targetUrl: string,
  extraUrls: string[] = [],
): Promise<{ findings: Finding[]; requestsMade: number }> {
  const findings: Finding[] = [];
  const before = http.limiter.getStats().requestsMade;
  const targets = [targetUrl, ...extraUrls.slice(0, 2)];

  const dnrAvailable =
    typeof chrome !== 'undefined' &&
    !!chrome.declarativeNetRequest?.updateSessionRules;

  for (const url of targets) {
    const host = new URL(url).hostname;
    const probes: OriginProbeResult[] = [];

    if (dnrAvailable) {
      const origins = [EVIL_ORIGIN, 'null', EVIL_ORIGIN_2];
      for (const origin of origins) {
        const ruleSet = await setProbeOrigin(host, origin);
        try {
          const res = await http.get(url);
          probes.push({
            origin,
            allowOrigin: res.headers['access-control-allow-origin'] ?? '',
            allowCredentials:
              (res.headers['access-control-allow-credentials'] ?? '').toLowerCase() === 'true',
            status: res.status,
          });
        } catch {
          /* probe failed — move on */
        } finally {
          if (ruleSet) await clearProbeOrigin();
        }
        if (probes.length >= origins.length) break;
      }
    } else {
      // Fallback: observe the server's default CORS stance without varying Origin.
      try {
        const res = await http.get(url);
        probes.push({
          origin: '(unvaried)',
          allowOrigin: res.headers['access-control-allow-origin'] ?? '',
          allowCredentials:
            (res.headers['access-control-allow-credentials'] ?? '').toLowerCase() === 'true',
          status: res.status,
        });
      } catch {
        /* ignore */
      }
    }

    const finding = classifyProbes(url, probes, !dnrAvailable);
    if (finding) findings.push(finding);
    // One URL's verdict is enough if it's the worst kind; otherwise keep looking.
    if (findings.some((f) => f.severity === 'high')) break;
  }

  const requestsMade = http.limiter.getStats().requestsMade - before;
  for (const f of findings) f.requestCount = Math.max(1, Math.round(requestsMade / Math.max(1, findings.length)));
  return { findings, requestsMade };
}

function classifyProbes(
  url: string,
  probes: OriginProbeResult[],
  unvaried: boolean,
): Finding | null {
  if (probes.length === 0) return null;

  const withCreds = (p: OriginProbeResult): boolean => p.allowCredentials;

  // Wildcard + credentials — the classic critical misconfiguration.
  const wildcard = probes.find(
    (p) => p.allowOrigin === '*' && withCreds(p),
  );
  if (wildcard) {
    return {
      id: nextId(),
      category: 'cors',
      mode: 'active',
      tags: ['cors-creds', 'cors-wildcard'],
      title: 'CORS allows any origin with credentials (Access-Control-Allow-Origin: *)',
      description:
        `${url} responds with Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true. ` +
        'Any website can make credentialed cross-origin requests and read the responses, exposing session-bound data.',
      severity: 'high',
      confidence: 'high',
      confirmed: true,
      location: url,
      evidence: `Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true`,
      remediation:
        'Never combine a wildcard origin with credentials. Maintain an explicit allow-list of trusted origins and echo only those, with Vary: Origin.',
      ...cvssFields('cors:wildcard-credentials'),
      reproSteps: [
        `Send GET ${url} with Origin: ${EVIL_ORIGIN}.`,
        'Observe Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true in the response.',
      ],
    };
  }

  // Reflected arbitrary origin + credentials.
  const reflected = probes.find(
    (p) =>
      p.origin.startsWith('https://') &&
      p.allowOrigin === p.origin &&
      withCreds(p),
  );
  if (reflected) {
    return {
      id: nextId(),
      category: 'cors',
      mode: 'active',
      tags: ['cors-creds', 'cors-reflected'],
      title: 'CORS reflects arbitrary origins with credentials allowed',
      description:
        `${url} echoes the request Origin (${reflected.origin}) in Access-Control-Allow-Origin with credentials allowed. ` +
        'An attacker site can read credentialed responses as the victim.',
      severity: 'high',
      confidence: 'high',
      confirmed: true,
      location: url,
      evidence:
        `Request Origin: ${reflected.origin}\n` +
        `Access-Control-Allow-Origin: ${reflected.allowOrigin}\n` +
        `Access-Control-Allow-Credentials: true`,
      remediation:
        'Validate the Origin against an explicit allow-list instead of reflecting it; only allow credentials for trusted origins.',
      ...cvssFields('cors:reflected-credentials'),
      reproSteps: [
        `Send GET ${url} with Origin: ${reflected.origin}.`,
        'Observe the origin reflected with Access-Control-Allow-Credentials: true.',
      ],
    };
  }

  // Null origin trusted.
  const nullOrigin = probes.find(
    (p) => p.origin === 'null' && p.allowOrigin === 'null' && withCreds(p),
  );
  if (nullOrigin) {
    return {
      id: nextId(),
      category: 'cors',
      mode: 'active',
      tags: ['cors-null'],
      title: 'CORS trusts the "null" origin with credentials',
      description:
        `${url} accepts Origin: null with credentials allowed. Sandboxed iframes and redirects can obtain the null origin, making this a known bypass primitive.`,
      severity: 'medium',
      confidence: 'high',
      confirmed: true,
      location: url,
      evidence:
        'Request Origin: null\nAccess-Control-Allow-Origin: null\nAccess-Control-Allow-Credentials: true',
      remediation:
        'Do not allow-list the null origin. Use an explicit list of trusted origins.',
      ...cvssFields('cors:null-origin'),
      reproSteps: [
        `Send GET ${url} with Origin: null.`,
        'Observe Access-Control-Allow-Origin: null with credentials allowed.',
      ],
    };
  }

  // Reflected without credentials — weaker, still worth noting.
  const reflectedOpen = probes.find(
    (p) =>
      p.origin.startsWith('https://') &&
      p.allowOrigin === p.origin &&
      !withCreds(p),
  );
  if (reflectedOpen && !unvaried) {
    return {
      id: nextId(),
      category: 'cors',
      mode: 'active',
      tags: ['cors-reflected-open'],
      title: 'CORS reflects arbitrary origins (no credentials)',
      description:
        `${url} reflects arbitrary origins but does not allow credentials, so only public resources are readable cross-origin. ` +
        'Lower impact, but reflection often coexists with credential support on sibling endpoints — verify them too.',
      severity: 'low',
      confidence: 'high',
      confirmed: true,
      location: url,
      evidence:
        `Request Origin: ${reflectedOpen.origin}\n` +
        `Access-Control-Allow-Origin: ${reflectedOpen.allowOrigin}`,
      remediation:
        'Prefer an explicit origin allow-list over reflection, even without credentials.',
      ...cvssFields('cors:reflected-no-credentials'),
      reproSteps: [
        `Send GET ${url} with Origin: ${reflectedOpen.origin}.`,
        'Observe the origin reflected without Access-Control-Allow-Credentials.',
      ],
    };
  }

  // Fallback observation when Origin could not be varied.
  if (unvaried) {
    const star = probes.find((p) => p.allowOrigin === '*');
    if (star) {
      return {
        id: nextId(),
        category: 'cors',
        mode: 'active',
        tags: ['cors-wildcard-observed'],
        title: 'CORS wildcard observed (Access-Control-Allow-Origin: *)',
        description:
          `${url} sends Access-Control-Allow-Origin: *. The Origin header could not be varied in this environment, ` +
          'so credentialed impact is unconfirmed — verify manually whether credentials are also allowed.',
        severity: 'info',
        confidence: 'medium',
        confirmed: false,
        location: url,
        evidence: 'Access-Control-Allow-Origin: *',
        remediation:
          'Confirm whether Access-Control-Allow-Credentials is also sent; if so, replace the wildcard with an explicit allow-list.',
        ...cvssFields('cors:reflected-no-credentials'),
        reproSteps: [
          `Send GET ${url} with varied Origin headers (browser DevTools or curl).`,
          'Check for Access-Control-Allow-Credentials: true alongside the wildcard.',
        ],
      };
    }
  }

  return null;
}
