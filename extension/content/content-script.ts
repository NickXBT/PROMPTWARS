/**
 * Chrome Content Script for Phishing Shield AI.
 * Extracts DOM security metadata, securely renders risk badges,
 * and highlights suspicious links using safe DOM APIs.
 */

import { FormInfo, LinkInfo, PageAnalysisContext, AnalysisResult } from '../../lib/types.js';
import { injectWarningBanner } from './warning-banner.js';

/**
 * Extracts visible page text excerpt safely without executing scripts
 */
function extractVisiblePageText(): string {
  const elements = document.querySelectorAll('h1, h2, h3, p, label, .alert, .notice, .warning');
  const textChunks: string[] = [];
  let totalLength = 0;

  for (let i = 0; i < elements.length; i++) {
    const el = elements[i];
    // Check if element is visible
    const text = (el.textContent || '').trim().replace(/\s+/g, ' ');
    if (text.length > 5 && text.length < 500) {
      textChunks.push(text);
      totalLength += text.length;
      if (totalLength > 2000) break;
    }
  }

  return textChunks.join('\n');
}

/**
 * Scans DOM forms for sensitive credential inputs
 */
function extractForms(): FormInfo[] {
  const forms: FormInfo[] = [];
  const formElements = document.querySelectorAll('form');

  formElements.forEach((form) => {
    const rawAction = form.getAttribute('action') || window.location.href;
    let isPlainHttp = false;
    let isCrossDomain = false;

    try {
      const parsedAction = new URL(rawAction, window.location.origin);
      isPlainHttp = parsedAction.protocol === 'http:';
      isCrossDomain = parsedAction.hostname !== window.location.hostname;
    } catch {
      // Ignored
    }

    const inputs = form.querySelectorAll('input, select, textarea');
    let hasPassword = false;
    let hasCreditCard = false;
    let hasOtp = false;
    const inputTypes: string[] = [];

    inputs.forEach((inp) => {
      const type = (inp.getAttribute('type') || 'text').toLowerCase();
      const name = (inp.getAttribute('name') || '').toLowerCase();
      const id = (inp.getAttribute('id') || '').toLowerCase();
      const autocomplete = (inp.getAttribute('autocomplete') || '').toLowerCase();
      inputTypes.push(type);

      if (type === 'password' || name.includes('pass') || id.includes('pass')) {
        hasPassword = true;
      }
      if (
        name.includes('card') ||
        name.includes('cc') ||
        name.includes('cvv') ||
        autocomplete.includes('cc-')
      ) {
        hasCreditCard = true;
      }
      if (
        name.includes('otp') ||
        name.includes('2fa') ||
        name.includes('code') ||
        name.includes('token') ||
        id.includes('otp')
      ) {
        hasOtp = true;
      }
    });

    forms.push({
      action: rawAction,
      method: (form.getAttribute('method') || 'GET').toUpperCase(),
      hasPasswordInput: hasPassword,
      hasCreditCardInput: hasCreditCard,
      hasOtpInput: hasOtp,
      inputTypes,
      isCrossDomain,
      isPlainHttp
    });
  });

  return forms;
}

/**
 * Extracts links from DOM with visible text
 */
function extractLinks(): LinkInfo[] {
  const links: LinkInfo[] = [];
  const anchorElements = document.querySelectorAll('a[href]');
  const currentHost = window.location.hostname;

  anchorElements.forEach((a) => {
    const href = a.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;

    try {
      const parsed = new URL(href, window.location.origin);
      const isExternal = parsed.hostname !== currentHost;
      const visibleText = (a.textContent || '').trim();

      links.push({
        href: parsed.href,
        text: visibleText,
        isExternal
      });
    } catch {
      // invalid URL
    }
  });

  // Limit link list to top 40 relevant links
  return links.slice(0, 40);
}

/**
 * Builds the page analysis context payload
 */
export function buildPageAnalysisContext(): PageAnalysisContext {
  const forms = extractForms();
  const links = extractLinks();
  const textExcerpt = extractVisiblePageText();

  const allInputTypes: string[] = [];
  let hasSensitive = false;
  forms.forEach(f => {
    allInputTypes.push(...f.inputTypes);
    if (f.hasPasswordInput || f.hasCreditCardInput || f.hasOtpInput) {
      hasSensitive = true;
    }
  });

  return {
    url: window.location.href,
    origin: window.location.origin,
    hostname: window.location.hostname,
    pathname: window.location.pathname,
    title: document.title || '',
    textExcerpt,
    forms,
    links,
    hasSensitiveInputs: hasSensitive,
    inputTypes: allInputTypes,
    isEmailContext: window.location.hostname.includes('mail.google.com')
  };
}

/**
 * Highlights suspicious links directly on the page safely without modifying anchor behavior
 */
function highlightSuspiciousLinks(suspiciousUrls: AnalysisResult['suspiciousUrls']): void {
  if (!suspiciousUrls || suspiciousUrls.length === 0) return;

  const urlMap = new Map(suspiciousUrls.map(s => [s.url, s]));
  const anchors = document.querySelectorAll('a[href]');

  anchors.forEach((a) => {
    const href = a.getAttribute('href');
    if (!href) return;

    let fullHref: string;
    try {
      fullHref = new URL(href, window.location.origin).href;
    } catch {
      return;
    }

    const match = urlMap.get(fullHref);
    if (match) {
      // Add safe styling highlight
      const anchorEl = a as HTMLElement;
      anchorEl.style.outline = '2px dashed #D93025';
      anchorEl.style.outlineOffset = '2px';
      anchorEl.style.backgroundColor = 'rgba(217, 48, 37, 0.08)';
      
      const badge = document.createElement('span');
      badge.className = 'ps-suspicious-badge';
      badge.textContent = ' ⚠️ [Deceptive Link] ';
      badge.style.fontSize = '11px';
      badge.style.color = '#D93025';
      badge.style.fontWeight = 'bold';
      badge.title = match.reasons.join(' | ');

      anchorEl.appendChild(badge);
    }
  });
}

/**
 * Executes scan and sends context to background worker
 */
function initiatePageScan() {
  const context = buildPageAnalysisContext();

  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'ANALYZE_PAGE_REQUEST',
      payload: context
    }, (response) => {
      if (response && response.success && response.result) {
        handleScanOutcome(response.result);
      }
    });
  }
}

/**
 * Handles scan outcome received from background
 */
function handleScanOutcome(result: AnalysisResult) {
  if (result.score >= 60) {
    injectWarningBanner(result);
  }
  highlightSuspiciousLinks(result.suspiciousUrls);
}

// Listen for updates or manual trigger messages
if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === 'ANALYZE_PAGE_RESPONSE' && message.payload) {
      handleScanOutcome(message.payload);
      sendResponse({ received: true });
    }
    if (message.type === 'TRIGGER_PAGE_SCAN') {
      initiatePageScan();
      sendResponse({ started: true });
    }
  });
}

// Automatically initiate scan once document is interactive
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initiatePageScan);
} else {
  initiatePageScan();
}
