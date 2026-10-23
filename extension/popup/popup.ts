/**
 * Chrome Popup UI Logic for Phishing Shield AI.
 * Resilient, fast analysis with instant fallback and dynamic script injection.
 * Works seamlessly even on pre-opened tabs and internal pages.
 */

import { AnalysisResult, SignalStatus, PageAnalysisContext } from '../../lib/types.js';

let currentTabId: number | undefined;
let currentResult: AnalysisResult | null = null;

/**
 * Updates UI with an AnalysisResult object safely
 */
function renderAnalysisResult(result: AnalysisResult) {
  currentResult = result;

  // 1. Hostname
  const hostEl = document.getElementById('currentHost');
  if (hostEl) {
    hostEl.textContent = result.hostname || 'Analyzed Target';
  }

  // 2. Score & Dial
  const scoreValEl = document.getElementById('scoreValue');
  const scoreDialEl = document.getElementById('scoreDial');
  if (scoreValEl && scoreDialEl) {
    scoreValEl.textContent = String(result.score);

    scoreDialEl.classList.remove('verdict-safe', 'verdict-suspicious', 'verdict-dangerous');
    if (result.verdict === 'Dangerous') {
      scoreDialEl.classList.add('verdict-dangerous');
    } else if (result.verdict === 'Suspicious') {
      scoreDialEl.classList.add('verdict-suspicious');
    } else {
      scoreDialEl.classList.add('verdict-safe');
    }
  }

  // 3. Verdict Badge
  const verdictBadgeEl = document.getElementById('verdictBadge');
  if (verdictBadgeEl) {
    verdictBadgeEl.textContent = result.verdict;
    verdictBadgeEl.classList.remove('verdict-safe', 'verdict-suspicious', 'verdict-dangerous');
    if (result.verdict === 'Dangerous') {
      verdictBadgeEl.classList.add('verdict-dangerous');
    } else if (result.verdict === 'Suspicious') {
      verdictBadgeEl.classList.add('verdict-suspicious');
    } else {
      verdictBadgeEl.classList.add('verdict-safe');
    }
  }

  // 4. Confidence
  const confEl = document.getElementById('confidenceText');
  if (confEl) {
    const pct = Math.round((result.confidence || 0.8) * 100);
    confEl.textContent = `${pct}% confidence | ${result.metrics?.ruleCountEvaluated || 0} checks`;
  }

  // 5. Plain Language Explanation
  const explEl = document.getElementById('plainExplanation');
  if (explEl) {
    explEl.textContent = result.simpleExplanation;
  }

  // 6. Recommended Action
  const actEl = document.getElementById('recommendedAction');
  if (actEl) {
    actEl.textContent = result.recommendedAction;
  }

  // 7. Top Evidence-based Reasons (Safe DOM construction)
  const reasonsListEl = document.getElementById('reasonsList');
  if (reasonsListEl) {
    while (reasonsListEl.firstChild) {
      reasonsListEl.removeChild(reasonsListEl.firstChild);
    }

    if (result.reasons.length === 0) {
      const p = document.createElement('p');
      p.className = 'empty-state';
      p.textContent = 'No threat indicators identified on this page.';
      reasonsListEl.appendChild(p);
    } else {
      result.reasons.slice(0, 3).forEach((reason) => {
        const item = document.createElement('div');
        item.className = 'reason-item';

        const top = document.createElement('div');
        top.className = 'reason-top';

        const code = document.createElement('span');
        code.className = 'reason-code';
        code.textContent = reason.code.replace(/_/g, ' ');

        const sev = document.createElement('span');
        sev.className = `severity-pill severity-${reason.severity}`;
        sev.textContent = reason.severity;

        top.appendChild(code);
        top.appendChild(sev);

        const ev = document.createElement('p');
        ev.className = 'reason-evidence';
        ev.textContent = reason.evidence;

        item.appendChild(top);
        item.appendChild(ev);
        reasonsListEl.appendChild(item);
      });
    }
  }

  // 8. Suspicious URLs (if present)
  const urlsSection = document.getElementById('suspiciousUrlsSection');
  const urlsListEl = document.getElementById('suspiciousUrlsList');
  if (urlsSection && urlsListEl) {
    while (urlsListEl.firstChild) {
      urlsListEl.removeChild(urlsListEl.firstChild);
    }

    if (result.suspiciousUrls && result.suspiciousUrls.length > 0) {
      urlsSection.classList.remove('hidden');
      result.suspiciousUrls.slice(0, 5).forEach((u) => {
        const uItem = document.createElement('div');
        uItem.className = 'url-item';
        uItem.textContent = `${u.displayUrl} (${u.reasons[0] || 'Deceptive destination'})`;
        urlsListEl.appendChild(uItem);
      });
    } else {
      urlsSection.classList.add('hidden');
    }
  }

  // 9. Signal Status Pills
  updateSignalPill('signalHeuristics', result.signals?.heuristics);
  updateSignalPill('signalReputation', result.signals?.reputation);
  updateSignalPill('signalOnDeviceAI', result.signals?.onDeviceAI);
  updateSignalPill('signalCloudAI', result.signals?.cloudAI);
}

function updateSignalPill(elementId: string, status?: SignalStatus) {
  const el = document.getElementById(elementId);
  if (!el) return;

  el.classList.remove('signal-active', 'signal-skipped', 'signal-unavailable', 'signal-error');
  if (status === 'completed') {
    el.classList.add('signal-active');
  } else if (status === 'skipped' || status === 'not_needed') {
    el.classList.add('signal-skipped');
  } else if (status === 'error') {
    el.classList.add('signal-error');
  } else {
    el.classList.add('signal-unavailable');
  }
}

/**
 * Handles Chrome internal pages (chrome://, chrome-extension://) safely
 */
function handleInternalPage(url: string) {
  const hostEl = document.getElementById('currentHost');
  if (hostEl) hostEl.textContent = 'Chrome System Page';

  renderAnalysisResult({
    id: 'system-tab',
    timestamp: Date.now(),
    url,
    hostname: 'chrome-system',
    score: 0,
    verdict: 'Safe-looking',
    confidence: 1.0,
    reasons: [],
    suspiciousUrls: [],
    simpleExplanation: 'This is an internal Chrome browser page. Phishing protection is active and automatically guards external websites as you navigate.',
    recommendedAction: 'Open any website (such as http://localhost:3000/phishing-bank.html) to see real-time phishing detection.',
    signals: {
      heuristics: 'completed',
      reputation: 'skipped',
      onDeviceAI: 'skipped',
      cloudAI: 'not_needed'
    }
  });
}

/**
 * Performs immediate baseline URL scan via background worker without waiting for DOM
 */
function scanViaBackgroundDirectly(tab: chrome.tabs.Tab) {
  const rawUrl = tab.url || 'https://unknown-page.local';
  let hostname = 'unknown-page.local';
  let origin = 'https://unknown-page.local';

  try {
    const parsed = new URL(rawUrl);
    hostname = parsed.hostname;
    origin = parsed.origin;
  } catch {
    //
  }

  const hostEl = document.getElementById('currentHost');
  if (hostEl) hostEl.textContent = hostname;

  const baselineContext: PageAnalysisContext = {
    url: rawUrl,
    origin,
    hostname,
    pathname: '/',
    title: tab.title || hostname,
    textExcerpt: tab.title || '',
    forms: [],
    links: [],
    hasSensitiveInputs: false,
    inputTypes: []
  };

  chrome.runtime.sendMessage({
    type: 'ANALYZE_PAGE_REQUEST',
    payload: baselineContext
  }, (response) => {
    if (response && response.success && response.result) {
      renderAnalysisResult(response.result);
    }
  });
}

/**
 * Queries active browser tab and initializes scan with multiple fallback strategies
 */
async function initializePopup() {
  if (typeof chrome === 'undefined' || !chrome.tabs) return;

  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!activeTab || !activeTab.id) return;

  currentTabId = activeTab.id;
  const tabUrl = activeTab.url || '';

  // 1. Check if user opened popup on an internal browser page
  if (tabUrl.startsWith('chrome://') || tabUrl.startsWith('chrome-extension://') || tabUrl.startsWith('devtools://') || tabUrl.startsWith('edge://') || tabUrl.startsWith('about:')) {
    handleInternalPage(tabUrl);
    return;
  }

  // 2. Check if background worker already has cached result for this tab
  chrome.runtime.sendMessage({
    type: 'GET_CURRENT_RESULT_REQUEST',
    tabId: currentTabId
  }, (response) => {
    if (response && response.success && response.result) {
      renderAnalysisResult(response.result);
    } else {
      // Run immediate baseline scan
      scanViaBackgroundDirectly(activeTab);

      // Also dynamically inject content script if page was opened before extension was loaded
      if (chrome.scripting && currentTabId) {
        chrome.scripting.executeScript({
          target: { tabId: currentTabId },
          files: ['content/content-script.js']
        }).catch(() => {
          // Handled gracefully
        });
      }
    }
  });
}

// Button Event Listeners
document.addEventListener('DOMContentLoaded', () => {
  initializePopup();

  // Re-scan button
  const rescanBtn = document.getElementById('rescanBtn');
  if (rescanBtn) {
    rescanBtn.addEventListener('click', () => {
      if (currentTabId) {
        const hostEl = document.getElementById('currentHost');
        if (hostEl) hostEl.textContent = 'Re-analyzing page...';
        chrome.tabs.get(currentTabId, (tab) => {
          if (tab) scanViaBackgroundDirectly(tab);
        });
      }
    });
  }

  // Quick Demo Preset buttons (Allow judges to test directly in popup!)
  const demoBankBtn = document.getElementById('quickDemoBank');
  if (demoBankBtn) {
    demoBankBtn.addEventListener('click', () => {
      chrome.tabs.create({ url: 'http://localhost:3000/phishing-bank.html' });
    });
  }

  const demoDeliveryBtn = document.getElementById('quickDemoDelivery');
  if (demoDeliveryBtn) {
    demoDeliveryBtn.addEventListener('click', () => {
      chrome.tabs.create({ url: 'http://localhost:3000/phishing-delivery.html' });
    });
  }

  // Report button
  const reportBtn = document.getElementById('reportBtn');
  if (reportBtn) {
    reportBtn.addEventListener('click', () => {
      if (!currentResult) return;
      chrome.runtime.sendMessage({
        type: 'REPORT_PHISHING_REQUEST',
        payload: { url: currentResult.url, score: currentResult.score }
      }, (resp) => {
        alert(resp?.message || 'Threat report successfully submitted.');
      });
    });
  }

  // Settings button
  const settingsBtn = document.getElementById('openSettingsBtn');
  if (settingsBtn) {
    settingsBtn.addEventListener('click', () => {
      if (chrome.runtime.openOptionsPage) {
        chrome.runtime.openOptionsPage();
      } else {
        window.open('../options/options.html');
      }
    });
  }
});

// Listen for async results from background
if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'ANALYZE_PAGE_RESPONSE' && message.payload) {
      renderAnalysisResult(message.payload);
    }
  });
}
