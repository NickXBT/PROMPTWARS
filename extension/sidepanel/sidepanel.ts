/**
 * Chrome Sidepanel Logic for Phishing Shield AI.
 * Displays historical scan entries, forensic breakdowns, and signal telemetry.
 */

import { getScanHistory, clearScanHistory } from '../../lib/storage.js';
import { AnalysisResult } from '../../lib/types.js';

async function renderHistory() {
  const container = document.getElementById('historyList');
  if (!container) return;

  const history = await getScanHistory();

  while (container.firstChild) {
    container.removeChild(container.firstChild);
  }

  if (history.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.textContent = 'No past scans recorded. Browse web pages to see live forensic analysis.';
    container.appendChild(empty);
    return;
  }

  history.forEach((scan: AnalysisResult) => {
    const card = document.createElement('div');
    card.className = 'history-card';

    // Top
    const top = document.createElement('div');
    top.className = 'card-top';

    const host = document.createElement('span');
    host.className = 'host-tag';
    host.textContent = scan.hostname;

    const badge = document.createElement('span');
    badge.className = `badge-tag tag-${scan.verdict.toLowerCase().replace('-looking', '')}`;
    badge.textContent = `${scan.verdict} (${scan.score}/100)`;

    top.appendChild(host);
    top.appendChild(badge);

    // Detail row
    const detailRow = document.createElement('div');
    detailRow.className = 'detail-row';

    const dateStr = new Date(scan.timestamp).toLocaleTimeString();
    const timeSpan = document.createElement('span');
    timeSpan.textContent = dateStr;

    const latencySpan = document.createElement('span');
    latencySpan.textContent = `${scan.metrics?.latencyMs || 0}ms latency`;

    detailRow.appendChild(timeSpan);
    detailRow.appendChild(latencySpan);

    // Bullets of reasons
    const ul = document.createElement('ul');
    ul.className = 'reason-bullets';
    scan.reasons.slice(0, 3).forEach((r) => {
      const li = document.createElement('li');
      li.textContent = `[${r.severity.toUpperCase()}] ${r.evidence}`;
      ul.appendChild(li);
    });

    card.appendChild(top);
    card.appendChild(detailRow);
    card.appendChild(ul);
    container.appendChild(card);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  renderHistory();

  const clearBtn = document.getElementById('clearHistoryBtn');
  if (clearBtn) {
    clearBtn.addEventListener('click', async () => {
      await clearScanHistory();
      renderHistory();
    });
  }
});
