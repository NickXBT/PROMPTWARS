import { describe, it, expect } from 'vitest';
import { calculateRiskScore, getVerdictFromScore } from '../lib/scoring.js';

describe('Evidence-Based Risk Scoring Engine', () => {
  it('correctly maps score boundaries to verdicts', () => {
    expect(getVerdictFromScore(15)).toBe('Safe-looking');
    expect(getVerdictFromScore(29)).toBe('Safe-looking');
    expect(getVerdictFromScore(30)).toBe('Suspicious');
    expect(getVerdictFromScore(59)).toBe('Suspicious');
    expect(getVerdictFromScore(60)).toBe('Dangerous');
    expect(getVerdictFromScore(95)).toBe('Dangerous');
  });

  it('ENFORCES HARD OVERRIDE: Confirmed malicious reputation match cannot be downgraded by reassuring AI', () => {
    const result = calculateRiskScore({
      url: 'https://malicious-confirmed.xyz',
      hostname: 'malicious-confirmed.xyz',
      reasons: [],
      suspiciousUrls: [],
      reputation: {
        isThreat: true,
        threatType: 'SOCIAL_ENGINEERING',
        provider: 'google-web-risk',
        cached: false,
        checkedAt: Date.now()
      },
      // Simulated reassuring AI attempting to lower score by 15 points
      onDeviceAiScoreModifier: -15,
      cloudAiScoreModifier: -15,
      signals: {
        heuristics: 'completed',
        reputation: 'completed',
        onDeviceAI: 'completed',
        cloudAI: 'completed'
      }
    });

    expect(result.verdict).toBe('Dangerous');
    expect(result.score).toBeGreaterThanOrEqual(95);
    expect(result.threatDetails?.isConfirmedThreat).toBe(true);
    expect(result.reasons[0].code).toBe('CONFIRMED_THREAT_INTELLIGENCE');
  });

  it('produces honest "Safe-looking" verdict for clean page without claiming guaranteed safety', () => {
    const result = calculateRiskScore({
      url: 'https://example.com/blog',
      hostname: 'example.com',
      reasons: [],
      suspiciousUrls: [],
      signals: {
        heuristics: 'completed',
        reputation: 'unavailable',
        onDeviceAI: 'unavailable',
        cloudAI: 'not_needed'
      }
    });

    expect(result.verdict).toBe('Safe-looking');
    expect(result.score).toBeLessThan(30);
    expect(result.simpleExplanation).toContain('does not trigger known phishing');
    expect(result.simpleExplanation).toContain('verify the web address');
  });
});
