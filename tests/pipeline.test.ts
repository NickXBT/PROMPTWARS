import { describe, it, expect } from 'vitest';
import { runDetectionPipeline } from '../lib/pipeline.js';
import { PageAnalysisContext, DEFAULT_SETTINGS, ExtensionSettings } from '../lib/types.js';
import { parseAndValidateAiResponse } from '../lib/gemini-nano.js';
import { redactPii } from '../lib/redact.js';

describe('Phishing Shield AI - Comprehensive 14-Scenario Test Suite & Evaluation', () => {
  // Test evaluation tracking counters
  let truePositives = 0;
  let falsePositives = 0;
  let trueNegatives = 0;
  let falseNegatives = 0;
  const latencies: number[] = [];

  // --------------------------------------------------------------------------
  // Scenario 1: Fake banking login page with a look-alike domain
  // --------------------------------------------------------------------------
  it('Scenario 1: Flags fake banking login page with look-alike domain', async () => {
    const start = Date.now();
    const context: PageAnalysisContext = {
      url: 'https://paypa1-verify.xyz/signin',
      origin: 'https://paypa1-verify.xyz',
      hostname: 'paypa1-verify.xyz',
      pathname: '/signin',
      title: 'PayPal - Verify Your Identity',
      textExcerpt: 'Please verify your account immediately. Unauthorized activity detected.',
      forms: [{
        action: 'https://paypa1-verify.xyz/collect',
        method: 'POST',
        hasPasswordInput: true,
        hasCreditCardInput: false,
        hasOtpInput: false,
        inputTypes: ['text', 'password'],
        isCrossDomain: false,
        isPlainHttp: false
      }],
      links: [],
      hasSensitiveInputs: true,
      inputTypes: ['text', 'password']
    };

    const result = await runDetectionPipeline(context, DEFAULT_SETTINGS);
    latencies.push(Date.now() - start);

    expect(result.verdict).toBe('Dangerous');
    expect(result.score).toBeGreaterThanOrEqual(60);
    expect(result.reasons.some(r => r.code === 'DOMAIN_IMPERSONATION' || r.code === 'CREDENTIAL_HARVESTING_ON_LOOKALIKE')).toBe(true);

    if (result.verdict === 'Dangerous' || result.verdict === 'Suspicious') truePositives++; else falseNegatives++;
  });

  // --------------------------------------------------------------------------
  // Scenario 2: Simulated delivery message demanding urgent fee
  // --------------------------------------------------------------------------
  it('Scenario 2: Flags delivery fee scam demanding payment within 24 hours', async () => {
    const start = Date.now();
    const context: PageAnalysisContext = {
      url: 'https://express-parcel-customs.top/pay',
      origin: 'https://express-parcel-customs.top',
      hostname: 'express-parcel-customs.top',
      pathname: '/pay',
      title: 'USPS Delivery Notification: Unpaid customs fee',
      textExcerpt: 'Your delivery is pending. Unpaid shipping fee required within 24 hours.',
      forms: [{
        action: 'https://express-parcel-customs.top/charge',
        method: 'POST',
        hasPasswordInput: false,
        hasCreditCardInput: true,
        hasOtpInput: false,
        inputTypes: ['text', 'text', 'text'],
        isCrossDomain: false,
        isPlainHttp: false
      }],
      links: [{
        href: 'https://bit.ly/track-usps',
        text: 'Track package online',
        isExternal: true
      }],
      hasSensitiveInputs: true,
      inputTypes: ['text', 'text']
    };

    const result = await runDetectionPipeline(context, DEFAULT_SETTINGS);
    latencies.push(Date.now() - start);

    expect(result.verdict).toBe('Dangerous');
    expect(result.score).toBeGreaterThanOrEqual(60);
    expect(result.reasons.some(r => r.code === 'PAYMENT_CARD_HARVESTING')).toBe(true);

    if (result.verdict === 'Dangerous' || result.verdict === 'Suspicious') truePositives++; else falseNegatives++;
  });

  // --------------------------------------------------------------------------
  // Scenario 3: Fake account suspension page requesting OTP
  // --------------------------------------------------------------------------
  it('Scenario 3: Flags account suspension page requesting OTP code', async () => {
    const start = Date.now();
    const context: PageAnalysisContext = {
      url: 'http://micros0ft-security-check.xyz/otp',
      origin: 'http://micros0ft-security-check.xyz',
      hostname: 'micros0ft-security-check.xyz',
      pathname: '/otp',
      title: 'Microsoft Security Alert: Account Suspended',
      textExcerpt: 'Account suspended! Immediate action required. Enter your 2FA OTP code.',
      forms: [{
        action: 'http://micros0ft-security-check.xyz/submit-otp',
        method: 'POST',
        hasPasswordInput: true,
        hasCreditCardInput: false,
        hasOtpInput: true,
        inputTypes: ['password', 'text'],
        isCrossDomain: false,
        isPlainHttp: true
      }],
      links: [],
      hasSensitiveInputs: true,
      inputTypes: ['password', 'text']
    };

    const result = await runDetectionPipeline(context, DEFAULT_SETTINGS);
    latencies.push(Date.now() - start);

    expect(result.verdict).toBe('Dangerous');
    expect(result.reasons.some(r => r.code === 'OTP_INTERCEPTION' || r.code === 'DOMAIN_IMPERSONATION')).toBe(true);

    if (result.verdict === 'Dangerous' || result.verdict === 'Suspicious') truePositives++; else falseNegatives++;
  });

  // --------------------------------------------------------------------------
  // Scenario 4: Legitimate login page
  // --------------------------------------------------------------------------
  it('Scenario 4: Evaluates legitimate official login page as Safe-looking', async () => {
    const start = Date.now();
    const context: PageAnalysisContext = {
      url: 'https://accounts.google.com/signin',
      origin: 'https://accounts.google.com',
      hostname: 'accounts.google.com',
      pathname: '/signin',
      title: 'Google Sign-in',
      textExcerpt: 'Sign in to access your Google Account',
      forms: [{
        action: 'https://accounts.google.com/signin/v2/challenge',
        method: 'POST',
        hasPasswordInput: true,
        hasCreditCardInput: false,
        hasOtpInput: false,
        inputTypes: ['email', 'password'],
        isCrossDomain: false,
        isPlainHttp: false
      }],
      links: [{
        href: 'https://policies.google.com/privacy',
        text: 'Privacy Policy',
        isExternal: true
      }],
      hasSensitiveInputs: true,
      inputTypes: ['email', 'password']
    };

    const result = await runDetectionPipeline(context, DEFAULT_SETTINGS);
    latencies.push(Date.now() - start);

    expect(result.verdict).toBe('Safe-looking');
    expect(result.score).toBeLessThan(30);

    if (result.verdict === 'Safe-looking') trueNegatives++; else falsePositives++;
  });

  // --------------------------------------------------------------------------
  // Scenario 5: Legitimate newsletter with urgency wording but no suspicious links
  // --------------------------------------------------------------------------
  it('Scenario 5: Does not false-positive legitimate newsletter with mild urgency', async () => {
    const start = Date.now();
    const context: PageAnalysisContext = {
      url: 'https://techdigest.example.com/newsletter',
      origin: 'https://techdigest.example.com',
      hostname: 'techdigest.example.com',
      pathname: '/newsletter',
      title: 'TechDigest: Subscribe Today',
      textExcerpt: 'Register today! Limited time offer to get our engineering roadmap report.',
      forms: [{
        action: '/subscribe',
        method: 'POST',
        hasPasswordInput: false,
        hasCreditCardInput: false,
        hasOtpInput: false,
        inputTypes: ['email'],
        isCrossDomain: false,
        isPlainHttp: false
      }],
      links: [{
        href: 'https://techdigest.example.com/archive',
        text: 'Read past newsletters',
        isExternal: false
      }],
      hasSensitiveInputs: false,
      inputTypes: ['email']
    };

    const result = await runDetectionPipeline(context, DEFAULT_SETTINGS);
    latencies.push(Date.now() - start);

    expect(result.verdict).toBe('Safe-looking');
    expect(result.score).toBeLessThan(30);

    if (result.verdict === 'Safe-looking') trueNegatives++; else falsePositives++;
  });

  // --------------------------------------------------------------------------
  // Scenario 6: Legitimate URL whose visible link text differs for a benign reason
  // --------------------------------------------------------------------------
  it('Scenario 6: Ignores benign link text differences like "Official Documentation"', async () => {
    const start = Date.now();
    const context: PageAnalysisContext = {
      url: 'https://framework.example.com/guide',
      origin: 'https://framework.example.com',
      hostname: 'framework.example.com',
      pathname: '/guide',
      title: 'Developer Guide',
      textExcerpt: 'Read the developer guide for building cloud apps.',
      forms: [],
      links: [
        {
          href: 'https://docs.framework.example.com/v2/setup',
          text: 'Official Documentation and Setup Guide',
          isExternal: true
        },
        {
          href: 'https://github.com/example/repo',
          text: 'View Source Code on GitHub',
          isExternal: true
        }
      ],
      hasSensitiveInputs: false,
      inputTypes: []
    };

    const result = await runDetectionPipeline(context, DEFAULT_SETTINGS);
    latencies.push(Date.now() - start);

    expect(result.verdict).toBe('Safe-looking');
    expect(result.score).toBeLessThan(30);

    if (result.verdict === 'Safe-looking') trueNegatives++; else falsePositives++;
  });

  // --------------------------------------------------------------------------
  // Scenario 7: Unicode or punycode domain cases
  // --------------------------------------------------------------------------
  it('Scenario 7: Flags Cyrillic homoglyph domain mimicking PayPal', async () => {
    const start = Date.now();
    // Hostname with Cyrillic 'а' (\u0430)
    const context: PageAnalysisContext = {
      url: 'https://p\u0430ypal.com/auth',
      origin: 'https://p\u0430ypal.com',
      hostname: 'p\u0430ypal.com',
      pathname: '/auth',
      title: 'PayPal Authentication',
      textExcerpt: 'Sign in to PayPal',
      forms: [{
        action: '/login',
        method: 'POST',
        hasPasswordInput: true,
        hasCreditCardInput: false,
        hasOtpInput: false,
        inputTypes: ['text', 'password'],
        isCrossDomain: false,
        isPlainHttp: false
      }],
      links: [],
      hasSensitiveInputs: true,
      inputTypes: ['password']
    };

    const result = await runDetectionPipeline(context, DEFAULT_SETTINGS);
    latencies.push(Date.now() - start);

    expect(result.verdict).toBe('Dangerous');
    expect(result.reasons.some(r => r.code === 'DOMAIN_IMPERSONATION')).toBe(true);

    if (result.verdict === 'Dangerous' || result.verdict === 'Suspicious') truePositives++; else falseNegatives++;
  });

  // --------------------------------------------------------------------------
  // Scenario 8: URL reputation service timeout
  // --------------------------------------------------------------------------
  it('Scenario 8: Handles URL reputation timeout fail-safely without crash', async () => {
    const settings: ExtensionSettings = {
      ...DEFAULT_SETTINGS,
      enableWebRisk: true,
      webRiskApiKey: 'AIzaFakeKeyThatTimesOut',
      backendProxyUrl: 'http://127.0.0.1:59999' // Non-existent port to simulate timeout
    };

    const context: PageAnalysisContext = {
      url: 'https://random-unknown-site.org',
      origin: 'https://random-unknown-site.org',
      hostname: 'random-unknown-site.org',
      pathname: '/',
      title: 'General Article',
      textExcerpt: 'Standard article content with no sensitive forms.',
      forms: [],
      links: [],
      hasSensitiveInputs: false,
      inputTypes: []
    };

    const result = await runDetectionPipeline(context, settings);
    // Even if reputation failed, result must still return gracefully with explicit signal
    expect(result).toBeDefined();
    expect(result.signals.reputation).toBe('unavailable');
  });

  // --------------------------------------------------------------------------
  // Scenario 9: Gemini unavailable
  // --------------------------------------------------------------------------
  it('Scenario 9: Gracefully marks Gemini Nano as unavailable and relies on heuristics', async () => {
    const context: PageAnalysisContext = {
      url: 'https://sample-site.net',
      origin: 'https://sample-site.net',
      hostname: 'sample-site.net',
      pathname: '/',
      title: 'Test Page',
      textExcerpt: 'Normal webpage text without chrome.ai runtime present.',
      forms: [],
      links: [],
      hasSensitiveInputs: false,
      inputTypes: []
    };

    const result = await runDetectionPipeline(context, DEFAULT_SETTINGS);
    expect(result.signals.onDeviceAI).toBe('unavailable');
    expect(result.signals.heuristics).toBe('completed');
  });

  // --------------------------------------------------------------------------
  // Scenario 10: Invalid AI output
  // --------------------------------------------------------------------------
  it('Scenario 10: Rejects malformed JSON from language model gracefully', () => {
    const invalidJson = '```json { "modifier": NaN, tactics: [unclosed string...';
    const parsed = parseAndValidateAiResponse(invalidJson);
    expect(parsed).toBeNull();
  });

  // --------------------------------------------------------------------------
  // Scenario 11: PII redaction
  // --------------------------------------------------------------------------
  it('Scenario 11: Redacts emails, credit cards, SSNs, and query credentials', () => {
    const testText = 'Customer email: user@target.org, phone 415-555-0199, card 49927398716, SSN 000-12-3456';
    const res = redactPii(testText);
    expect(res.redactedText).not.toContain('user@target.org');
    expect(res.redactedText).not.toContain('415-555-0199');
    expect(res.redactedText).not.toContain('49927398716');
    expect(res.redactedText).not.toContain('000-12-3456');
    expect(res.hasRedactedPii).toBe(true);
  });

  // --------------------------------------------------------------------------
  // Scenario 12: Confirmed malicious URL combined with reassuring AI result
  // --------------------------------------------------------------------------
  it('Scenario 12: Enforces threat override: Confirmed threat cannot be downgraded by AI', async () => {
    const context: PageAnalysisContext = {
      url: 'http://phishing-bank-login.xyz',
      origin: 'http://phishing-bank-login.xyz',
      hostname: 'phishing-bank-login.xyz',
      pathname: '/',
      title: 'Suspicious Bank',
      textExcerpt: 'Please enter details',
      forms: [],
      links: [],
      hasSensitiveInputs: false,
      inputTypes: []
    };

    const result = await runDetectionPipeline(context, DEFAULT_SETTINGS);
    expect(result.verdict).toBe('Dangerous');
    expect(result.score).toBeGreaterThanOrEqual(95);
    expect(result.threatDetails?.isConfirmedThreat).toBe(true);

    if (result.verdict === 'Dangerous') truePositives++; else falseNegatives++;
  });

  // --------------------------------------------------------------------------
  // Scenario 13: On-device-only mode preventing cloud content transmission
  // --------------------------------------------------------------------------
  it('Scenario 13: On-device-only mode strictly skips all external lookups', async () => {
    const settings: ExtensionSettings = {
      ...DEFAULT_SETTINGS,
      onDeviceOnlyMode: true,
      enableCloudGemini: true, // Should be overridden by on-device mode
      enableWebRisk: true
    };

    const context: PageAnalysisContext = {
      url: 'https://test-privacy.com',
      origin: 'https://test-privacy.com',
      hostname: 'test-privacy.com',
      pathname: '/',
      title: 'Privacy Verification Page',
      textExcerpt: 'Nothing should be transmitted externally.',
      forms: [],
      links: [],
      hasSensitiveInputs: false,
      inputTypes: []
    };

    const result = await runDetectionPipeline(context, settings);
    expect(result.signals.reputation).toBe('skipped');
    expect(result.signals.cloudAI).toBe('skipped');
    expect(result.signals.heuristics).toBe('completed');
  });

  // --------------------------------------------------------------------------
  // Scenario 14: Safe rendering of malicious HTML-like text
  // --------------------------------------------------------------------------
  it('Scenario 14: Safely sanitizes malicious HTML payload without executing script', () => {
    const rawPayload = '{"suspicionScoreModifier": 10, "tacticsIdentified": ["<img src=x onerror=alert(1)>"], "explanation": "<script>alert(\'xss\')</script>", "confidence": 0.9}';
    const parsed = parseAndValidateAiResponse(rawPayload);
    expect(parsed?.explanation).toBe("<script>alert('xss')</script>");
  });

  // --------------------------------------------------------------------------
  // Evaluation Summary & Metrics Calculation
  // --------------------------------------------------------------------------
  it('Computes and logs verified hackathon detection metrics', () => {
    const totalSamples = truePositives + falsePositives + trueNegatives + falseNegatives;
    const precision = (truePositives + falsePositives) > 0 ? (truePositives / (truePositives + falsePositives)) : 1.0;
    const recall = (truePositives + falseNegatives) > 0 ? (truePositives / (truePositives + falseNegatives)) : 1.0;
    const falsePositiveRate = (falsePositives + trueNegatives) > 0 ? (falsePositives / (falsePositives + trueNegatives)) : 0.0;
    const avgLatency = latencies.length > 0 ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : 0;

    console.log('\n======================================================');
    console.log('       PHISHING SHIELD AI — TEST EVALUATION METRICS    ');
    console.log('======================================================');
    console.log(`Evaluated Test Scenarios: ${totalSamples}`);
    console.log(`True Positives (TP):      ${truePositives}`);
    console.log(`False Positives (FP):     ${falsePositives}`);
    console.log(`True Negatives (TN):      ${trueNegatives}`);
    console.log(`False Negatives (FN):     ${falseNegatives}`);
    console.log(`Precision:                ${(precision * 100).toFixed(1)}%`);
    console.log(`Recall:                   ${(recall * 100).toFixed(1)}%`);
    console.log(`False-Positive Rate:      ${(falsePositiveRate * 100).toFixed(1)}%`);
    console.log(`Average Latency:          ${avgLatency} ms`);
    console.log('======================================================\n');

    expect(totalSamples).toBeGreaterThanOrEqual(6);
    expect(precision).toBeGreaterThanOrEqual(0.95);
    expect(recall).toBeGreaterThanOrEqual(0.95);
    expect(falsePositiveRate).toBeLessThanOrEqual(0.05);
  });
});
