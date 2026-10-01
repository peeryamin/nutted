/**
 * BugSeek AI popup UI — two panes:
 *  - "Passive recon": always available (Phase 1 behavior, unchanged).
 *  - "Active testing": locked behind the authorization confirmation flow
 *    (see active.ts); visually distinct and clearly marked.
 */
import type { ScanMessage, ScanResult, Severity } from '../lib/types';
import { buildMarkdownReport, reportFilename } from '../lib/report';
import { renderFindings, renderSummary } from './render';
import { getActiveResult, handleActiveMessage, initActivePane } from './active';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const el = {
  targetUrl: document.getElementById('target-url') as HTMLElement,
  scanBtn: document.getElementById('scan-btn') as HTMLButtonElement,
  downloadBtn: document.getElementById('download-btn') as HTMLButtonElement,
  status: document.getElementById('status') as HTMLElement,
  error: document.getElementById('error') as HTMLElement,
  results: document.getElementById('results') as HTMLElement,
  summary: document.getElementById('summary') as HTMLElement,
  tech: document.getElementById('tech') as HTMLElement,
  findings: document.getElementById('findings') as HTMLElement,
  tabPassive: document.getElementById('tab-passive') as HTMLButtonElement,
  tabActive: document.getElementById('tab-active') as HTMLButtonElement,
  panePassive: document.getElementById('pane-passive') as HTMLElement,
  paneActive: document.getElementById('pane-active') as HTMLElement,
};

let currentTabId: number | null = null;
let currentResult: ScanResult | null = null;

init().catch((err) => showError(err instanceof Error ? err.message : String(err)));

async function init(): Promise<void> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) {
    showError('Could not identify the active tab.');
    el.scanBtn.disabled = true;
    return;
  }
  currentTabId = tab.id;
  el.targetUrl.textContent = tab.url ?? '(unknown page)';
  el.targetUrl.title = tab.url ?? '';

  // Restore the last passive scan for this tab, if any.
  const stored = await chrome.storage.local.get(`scan:${tab.id}`);
  const prev = stored[`scan:${tab.id}`] as ScanResult | undefined;
  if (prev) {
    currentResult = prev;
    renderResult(prev);
    setStatus(`Last scan: ${new Date(prev.scannedAt).toLocaleString()}`);
  }

  el.scanBtn.addEventListener('click', startScan);
  el.downloadBtn.addEventListener('click', () => downloadReport(currentResult));
  el.tabPassive.addEventListener('click', () => selectTab('passive'));
  el.tabActive.addEventListener('click', () => selectTab('active'));
  document.addEventListener('bugseek:download-active', () => {
    downloadReport(getActiveResult());
  });
  chrome.runtime.onMessage.addListener(handleMessage);

  await initActivePane(tab.id, tab.url ?? '');
}

function selectTab(which: 'passive' | 'active'): void {
  const passive = which === 'passive';
  el.tabPassive.classList.toggle('tab-selected', passive);
  el.tabPassive.setAttribute('aria-selected', String(passive));
  el.tabActive.classList.toggle('tab-selected', !passive);
  el.tabActive.setAttribute('aria-selected', String(!passive));
  el.panePassive.hidden = !passive;
  el.paneActive.hidden = passive;
}

function handleMessage(msg: ScanMessage): void {
  // Active-testing messages are owned by the active pane.
  if (
    msg.type === 'ACTIVE_PROGRESS' ||
    msg.type === 'ACTIVE_DONE' ||
    msg.type === 'ACTIVE_ERROR'
  ) {
    if (handleActiveMessage(msg)) {
      // Make sure the user sees active results even if they switched panes.
      if (msg.type === 'ACTIVE_DONE') selectTab('active');
    }
    return;
  }
  if (msg.type === 'SCAN_PROGRESS') {
    setStatus(msg.step);
    hideError();
  } else if (msg.type === 'SCAN_DONE') {
    currentResult = msg.result;
    renderResult(msg.result);
    setStatus(
      `Scan complete in ${(msg.result.durationMs / 1000).toFixed(1)}s — ` +
        `${msg.result.findings.length} finding(s).`,
    );
    setScanning(false);
  } else if (msg.type === 'SCAN_ERROR') {
    showError(msg.error);
    setScanning(false);
    setStatus('');
  }
}

function startScan(): void {
  if (currentTabId === null) return;
  hideError();
  setScanning(true);
  setStatus('Starting scan…');
  chrome.runtime.sendMessage({ type: 'RUN_SCAN', tabId: currentTabId } satisfies ScanMessage);
}

function setScanning(scanning: boolean): void {
  el.scanBtn.disabled = scanning;
  el.scanBtn.textContent = scanning ? 'Scanning…' : 'Scan this page';
}

function setStatus(text: string): void {
  el.status.textContent = text;
}

function showError(text: string): void {
  el.error.textContent = text;
  el.error.hidden = false;
}

function hideError(): void {
  el.error.hidden = true;
  el.error.textContent = '';
}

function renderResult(result: ScanResult): void {
  el.results.hidden = false;
  el.downloadBtn.disabled = false;

  renderSummary(el.summary, result.findings);

  // Tech badges.
  el.tech.innerHTML = '';
  if (result.tech.length === 0) {
    const none = document.createElement('span');
    none.className = 'tech-empty';
    none.textContent = 'No technologies fingerprinted';
    el.tech.appendChild(none);
  } else {
    for (const t of result.tech) {
      const badge = document.createElement('span');
      badge.className = 'tech-badge';
      badge.textContent = t.version ? `${t.name} ${t.version}` : t.name;
      badge.title = `Detected via ${t.source}`;
      el.tech.appendChild(badge);
    }
  }

  renderFindings(
    el.findings,
    result.findings,
    SEVERITIES,
    'No findings — the passive checks came back clean.',
  );
}

function downloadReport(result: ScanResult | null): void {
  if (!result) return;
  const markdown = buildMarkdownReport(result);
  const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = reportFilename(result.targetUrl, result.scannedAt);
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}
