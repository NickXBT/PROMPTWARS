import { describe, it, expect } from 'vitest';
import { parseAndValidateAiResponse } from '../lib/gemini-nano.js';
import { generatePlainLanguageExplanation } from '../lib/scoring.js';

describe('Security & XSS Prevention in Output Rendering', () => {
  it('safely handles malicious HTML tags in AI output without executing scripts', () => {
    const maliciousPayload = JSON.stringify({
      suspicionScoreModifier: 20,
      tacticsIdentified: ['<script>alert("hacked")</script>', '<img src=x onerror=alert(1)>'],
      explanation: 'Deceptive login with <svg onload=alert(document.cookie)> payload',
      confidence: 0.95
    });

    const parsed = parseAndValidateAiResponse(maliciousPayload);
    expect(parsed).not.toBeNull();
    // Verify string is preserved verbatim as plain text string without evaluation
    expect(parsed?.tacticsIdentified[0]).toBe('<script>alert("hacked")</script>');
    expect(parsed?.explanation).toContain('<svg onload=alert(document.cookie)>');
  });

  it('safely renders untrusted hostname strings into explanations', () => {
    const maliciousHostname = 'paypa1.com<script>evil()</script>';
    const explanation = generatePlainLanguageExplanation('Dangerous', [{
      code: 'DOMAIN_IMPERSONATION',
      severity: 'critical',
      evidence: 'Look-alike brand',
      explanation: 'Fake login',
      scoreImpact: 50
    }], maliciousHostname);

    // Should include the hostname as plain characters
    expect(explanation).toContain(maliciousHostname);
  });
});
