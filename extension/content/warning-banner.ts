/**
 * Warning banner injected on high-risk/dangerous pages.
 * Constructed exclusively using safe DOM APIs (createElement, textContent).
 * NEVER evaluates or injects untrusted strings via innerHTML.
 */

import { AnalysisResult } from '../../lib/types.js';

let activeBannerElement: HTMLElement | null = null;

/**
 * Creates and injects an isolated security warning banner at the top of the webpage
 */
export function injectWarningBanner(result: AnalysisResult): void {
  // Avoid duplicate injection
  if (activeBannerElement || document.getElementById('phishing-shield-warning-host')) {
    return;
  }

  const host = document.createElement('div');
  host.id = 'phishing-shield-warning-host';
  host.style.position = 'fixed';
  host.style.top = '0';
  host.style.left = '0';
  host.style.width = '100%';
  host.style.zIndex = '2147483647';
  host.style.fontFamily = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';

  // Attach Shadow DOM for complete CSS style encapsulation
  const shadow = host.attachShadow({ mode: 'closed' });

  const style = document.createElement('style');
  style.textContent = `
    .ps-banner {
      background: #D93025;
      color: #FFFFFF;
      padding: 12px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
      font-size: 14px;
      line-height: 1.4;
      animation: psSlideDown 0.3s ease-out;
    }
    @keyframes psSlideDown {
      from { transform: translateY(-100%); }
      to { transform: translateY(0); }
    }
    .ps-content {
      display: flex;
      align-items: center;
      gap: 14px;
      flex: 1;
    }
    .ps-icon {
      font-size: 24px;
      flex-shrink: 0;
    }
    .ps-title {
      font-weight: 700;
      font-size: 15px;
      margin-bottom: 2px;
    }
    .ps-desc {
      opacity: 0.95;
    }
    .ps-actions {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-left: 16px;
    }
    .ps-btn {
      background: #FFFFFF;
      color: #D93025;
      border: none;
      border-radius: 4px;
      padding: 6px 12px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      transition: background 0.15s;
    }
    .ps-btn:hover {
      background: #F1F3F4;
    }
    .ps-btn-dismiss {
      background: transparent;
      color: #FFFFFF;
      border: 1px solid rgba(255, 255, 255, 0.6);
    }
    .ps-btn-dismiss:hover {
      background: rgba(255, 255, 255, 0.15);
    }
  `;
  shadow.appendChild(style);

  const banner = document.createElement('div');
  banner.className = 'ps-banner';
  banner.setAttribute('role', 'alert');

  // Content block
  const content = document.createElement('div');
  content.className = 'ps-content';

  const icon = document.createElement('div');
  icon.className = 'ps-icon';
  icon.textContent = '⚠️';

  const textWrap = document.createElement('div');
  const title = document.createElement('div');
  title.className = 'ps-title';
  title.textContent = `Phishing Shield AI Alert: High-Risk Website (${result.score}/100)`;

  const desc = document.createElement('div');
  desc.className = 'ps-desc';
  desc.textContent = result.simpleExplanation;

  textWrap.appendChild(title);
  textWrap.appendChild(desc);
  content.appendChild(icon);
  content.appendChild(textWrap);

  // Actions block
  const actions = document.createElement('div');
  actions.className = 'ps-actions';

  const inspectBtn = document.createElement('button');
  inspectBtn.className = 'ps-btn';
  inspectBtn.textContent = 'View Evidence';
  inspectBtn.addEventListener('click', () => {
    // Notify runtime to open side panel or trigger popup info
    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({ type: 'OPEN_EVIDENCE_PANEL', result });
    }
    alert(`Phishing Shield AI Findings:\n\nScore: ${result.score}/100\nVerdict: ${result.verdict}\n\nTop Reasons:\n${result.reasons.slice(0, 3).map((r, i) => `${i + 1}. [${r.code}] ${r.evidence}`).join('\n')}\n\nRecommended Action:\n${result.recommendedAction}`);
  });

  const dismissBtn = document.createElement('button');
  dismissBtn.className = 'ps-btn ps-btn-dismiss';
  dismissBtn.textContent = 'Dismiss Warning';
  dismissBtn.addEventListener('click', () => {
    removeWarningBanner();
  });

  actions.appendChild(inspectBtn);
  actions.appendChild(dismissBtn);

  banner.appendChild(content);
  banner.appendChild(actions);
  shadow.appendChild(banner);

  document.body.prepend(host);
  activeBannerElement = host;
}

/**
 * Safely removes the warning banner
 */
export function removeWarningBanner(): void {
  if (activeBannerElement && activeBannerElement.parentNode) {
    activeBannerElement.parentNode.removeChild(activeBannerElement);
    activeBannerElement = null;
  }
}
