/**
 * Interactive Web Threat Analysis Demo for Phishing Shield AI.
 * Reuses the core deterministic heuristics, reputation checks, and scoring engine.
 * Renders real findings, scores, explanations, and recommended actions.
 */

import { runDetectionPipeline } from '../lib/pipeline.js';
import { PageAnalysisContext, DEFAULT_SETTINGS, AnalysisResult, FormInfo, LinkInfo } from '../lib/types.js';

export const DEMO_PRESETS: Record<string, { label: string; url: string; text: string; formType: 'login' | 'card' | 'otp' | 'none'; links?: LinkInfo[] }> = {
  bank: {
    label: 'Chase Bank Impersonation',
    url: 'https://paypa1-verify.xyz/signin',
    text: 'Security Alert: Your account has been temporarily restricted due to unauthorized activity. Please verify your identity immediately to restore access.',
    formType: 'login',
    links: [
      { href: 'http://secure-chase-update.xyz/login', text: 'https://www.chase.com/privacy-security', isExternal: true }
    ]
  },
  delivery: {
    label: 'Delivery Customs Fee Scam',
    url: 'https://express-parcel-customs.top/pay',
    text: 'Package Delivery Pending: Your parcel cannot be delivered due to an unpaid shipping fee. Within 24 hours to verify and pay $2.95 before return to sender.',
    formType: 'card',
    links: [
      { href: 'https://bit.ly/track-usps', text: 'Track package online', isExternal: true }
    ]
  },
  otp: {
    label: 'Microsoft 365 2FA Interception',
    url: 'http://micros0ft-security-check.xyz/otp',
    text: 'Account Suspended: Immediate action required. Your access has been locked due to suspicious activity. Verify your identity with your two-factor OTP security code.',
    formType: 'otp',
    links: []
  },
  legitimate: {
    label: 'Legitimate Engineering Article',
    url: 'https://techdigest.example.com/guide',
    text: 'Building Resilient Distributed Systems in 2026. Modern cloud engineering demands high availability and graceful degradation. Subscribe to our weekly newsletter.',
    formType: 'none',
    links: [
      { href: 'https://docs.framework.example.com/v2/setup', text: 'Official Documentation', isExternal: true },
      { href: 'https://techdigest.example.com/privacy', text: 'Privacy Policy', isExternal: false }
    ]
  }
};

/**
 * Constructs a synthetic PageAnalysisContext from user input or preset
 */
export function buildContextFromInput(
  inputUrl: string,
  inputText: string,
  formType: 'login' | 'card' | 'otp' | 'none' = 'none',
  customLinks: LinkInfo[] = []
): PageAnalysisContext {
  let hostname = 'unknown-target.com';
  let origin = 'https://unknown-target.com';
  let pathname = '/';

  try {
    const parsed = new URL(inputUrl.startsWith('http') ? inputUrl : `https://${inputUrl}`);
    hostname = parsed.hostname;
    origin = parsed.origin;
    pathname = parsed.pathname;
  } catch {
    // Fallback if raw text
  }

  const forms: FormInfo[] = [];
  const inputTypes: string[] = [];

  if (formType === 'login') {
    forms.push({
      action: `${origin}/auth`,
      method: 'POST',
      hasPasswordInput: true,
      hasCreditCardInput: false,
      hasOtpInput: false,
      inputTypes: ['text', 'password'],
      isCrossDomain: false,
      isPlainHttp: origin.startsWith('http:')
    });
    inputTypes.push('password');
  } else if (formType === 'card') {
    forms.push({
      action: `${origin}/pay`,
      method: 'POST',
      hasPasswordInput: false,
      hasCreditCardInput: true,
      hasOtpInput: false,
      inputTypes: ['text', 'text', 'text'],
      isCrossDomain: false,
      isPlainHttp: origin.startsWith('http:')
    });
    inputTypes.push('credit_card');
  } else if (formType === 'otp') {
    forms.push({
      action: `${origin}/verify-otp`,
      method: 'POST',
      hasPasswordInput: true,
      hasCreditCardInput: false,
      hasOtpInput: true,
      inputTypes: ['password', 'text'],
      isCrossDomain: false,
      isPlainHttp: origin.startsWith('http:')
    });
    inputTypes.push('password', 'otp');
  }

  // Extract embedded URLs from text if no explicit links provided
  const links: LinkInfo[] = [...customLinks];
  if (links.length === 0) {
    const urlMatches = inputText.match(/https?:\/\/[^\s]+/g);
    if (urlMatches) {
      urlMatches.forEach((m) => {
        links.push({
          href: m,
          text: m,
          isExternal: true
        });
      });
    }
  }

  return {
    url: inputUrl.startsWith('http') ? inputUrl : `https://${inputUrl}`,
    origin,
    hostname,
    pathname,
    title: `Threat Inspection: ${hostname}`,
    textExcerpt: inputText,
    forms,
    links,
    hasSensitiveInputs: forms.length > 0,
    inputTypes
  };
}

/**
 * Initializes the Web Demo DOM controls
 */
export function initWebDemo() {
  const urlInput = document.getElementById('demoUrlInput') as HTMLInputElement;
  const textInput = document.getElementById('demoTextInput') as HTMLTextAreaElement;
  const analyzeBtn = document.getElementById('demoAnalyzeBtn') as HTMLButtonElement;
  const resultsCard = document.getElementById('demoResultsCard');
  const emptyState = document.getElementById('demoEmptyState');
  const loadingState = document.getElementById('demoLoadingState');

  let currentFormType: 'login' | 'card' | 'otp' | 'none' = 'none';
  let currentPresetLinks: LinkInfo[] = [];

  // Preset button listeners
  const presetButtons = document.querySelectorAll('.demo-preset-btn');
  presetButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      presetButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const presetKey = btn.getAttribute('data-preset');
      if (presetKey && DEMO_PRESETS[presetKey]) {
        const p = DEMO_PRESETS[presetKey];
        if (urlInput) urlInput.value = p.url;
        if (textInput) textInput.value = p.text;
        currentFormType = p.formType;
        currentPresetLinks = p.links || [];

        // Auto trigger analysis
        executeAnalysis();
      }
    });
  });

  if (analyzeBtn) {
    analyzeBtn.addEventListener('click', () => {
      executeAnalysis();
    });
  }

  async function executeAnalysis() {
    const urlVal = urlInput ? urlInput.value.trim() : '';
    const textVal = textInput ? textInput.value.trim() : '';

    if (!urlVal && !textVal) {
      alert('Please enter a URL or message to analyze.');
      return;
    }

    if (emptyState) emptyState.classList.add('hidden');
    if (resultsCard) resultsCard.classList.add('hidden');
    if (loadingState) loadingState.classList.remove('hidden');

    const effectiveUrl = urlVal || 'https://analyzed-message.local';
    const context = buildContextFromInput(effectiveUrl, textVal, currentFormType, currentPresetLinks);

    try {
      const startTime = performance.now();
      const result = await runDetectionPipeline(context, DEFAULT_SETTINGS);
      const elapsed = Math.round(performance.now() - startTime);

      renderDemoResult(result, elapsed);

      if (loadingState) loadingState.classList.add('hidden');
      if (resultsCard) resultsCard.classList.remove('hidden');
    } catch (err) {
      if (loadingState) loadingState.classList.add('hidden');
      if (emptyState) {
        emptyState.classList.remove('hidden');
        emptyState.textContent = `Analysis error: ${err instanceof Error ? err.message : String(err)}`;
      }
    }
  }

  function renderDemoResult(result: AnalysisResult, latencyMs: number) {
    // 1. Score & Verdict
    const scoreVal = document.getElementById('demoScoreValue');
    const verdictBadge = document.getElementById('demoVerdictBadge');
    const scoreDial = document.getElementById('demoScoreDial');

    if (scoreVal) scoreVal.textContent = String(result.score);
    if (verdictBadge) {
      verdictBadge.textContent = result.verdict;
      verdictBadge.className = `verdict-badge verdict-${result.verdict.toLowerCase().replace('-looking', '')}`;
    }
    if (scoreDial) {
      scoreDial.className = `score-circle verdict-${result.verdict.toLowerCase().replace('-looking', '')}`;
    }

    // 2. Latency & Confidence
    const metricsEl = document.getElementById('demoMetricsText');
    if (metricsEl) {
      metricsEl.textContent = `${latencyMs}ms analysis latency | ${Math.round(result.confidence * 100)}% confidence`;
    }

    // 3. Plain language explanation
    const explEl = document.getElementById('demoExplanation');
    if (explEl) explEl.textContent = result.simpleExplanation;

    // 4. Recommended action
    const actEl = document.getElementById('demoAction');
    if (actEl) actEl.textContent = result.recommendedAction;

    // 5. Reasons list (safe DOM)
    const reasonsContainer = document.getElementById('demoReasonsList');
    if (reasonsContainer) {
      while (reasonsContainer.firstChild) reasonsContainer.removeChild(reasonsContainer.firstChild);

      if (result.reasons.length === 0) {
        const emptyP = document.createElement('p');
        emptyP.className = 'empty-reason';
        emptyP.textContent = 'No critical threat indicators found on this page.';
        reasonsContainer.appendChild(emptyP);
      } else {
        result.reasons.slice(0, 3).forEach((r) => {
          const item = document.createElement('div');
          item.className = 'demo-reason-item';

          const top = document.createElement('div');
          top.className = 'reason-header';

          const code = document.createElement('span');
          code.className = 'reason-code';
          code.textContent = r.code.replace(/_/g, ' ');

          const sev = document.createElement('span');
          sev.className = `severity-tag severity-${r.severity}`;
          sev.textContent = r.severity.toUpperCase();

          top.appendChild(code);
          top.appendChild(sev);

          const ev = document.createElement('p');
          ev.className = 'reason-desc';
          ev.textContent = r.evidence;

          item.appendChild(top);
          item.appendChild(ev);
          reasonsContainer.appendChild(item);
        });
      }
    }

    // 6. Suspicious links
    const linksSection = document.getElementById('demoSuspiciousUrlsSection');
    const linksContainer = document.getElementById('demoSuspiciousUrlsList');

    if (linksSection && linksContainer) {
      while (linksContainer.firstChild) linksContainer.removeChild(linksContainer.firstChild);

      if (result.suspiciousUrls && result.suspiciousUrls.length > 0) {
        linksSection.classList.remove('hidden');
        result.suspiciousUrls.forEach((u) => {
          const uDiv = document.createElement('div');
          uDiv.className = 'demo-url-item';
          uDiv.textContent = `${u.displayUrl} — ${u.reasons[0] || 'Deceptive destination'}`;
          linksContainer.appendChild(uDiv);
        });
      } else {
        linksSection.classList.add('hidden');
      }
    }
  }

  // Load first preset by default
  const defaultBtn = document.querySelector('.demo-preset-btn[data-preset="bank"]') as HTMLButtonElement;
  if (defaultBtn) {
    defaultBtn.click();
  }
}
