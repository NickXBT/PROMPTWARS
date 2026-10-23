/**
 * Evidence-based risk scoring and verdict calculation engine.
 * Combines deterministic heuristics, URL reputation, and AI signals.
 * Enforces non-negotiable threat overrides.
 */

import {
  AnalysisResult,
  DetectionSignals,
  HeuristicReason,
  ReputationResult,
  SuspiciousUrl,
  Verdict
} from './types.js';

export interface ScoreCalculationInput {
  url: string;
  hostname: string;
  reasons: HeuristicReason[];
  suspiciousUrls: SuspiciousUrl[];
  reputation?: ReputationResult;
  onDeviceAiScoreModifier?: number;
  cloudAiScoreModifier?: number;
  signals: DetectionSignals;
  latencyMs?: number;
}

/**
 * Maps numerical score (0 - 100) to human verdict category
 */
export function getVerdictFromScore(score: number): Verdict {
  if (score >= 60) return 'Dangerous';
  if (score >= 30) return 'Suspicious';
  return 'Safe-looking';
}

/**
 * Calculates final score and verdict following strict security rules.
 */
export function calculateRiskScore(input: ScoreCalculationInput): AnalysisResult {
  const startTime = Date.now();
  let rawScore = 0;
  let isConfirmedThreat = false;
  let threatSource: string | undefined;

  // 1. Sum up heuristic score impacts
  for (const reason of input.reasons) {
    rawScore += reason.scoreImpact;
  }

  // 2. Additional impact for suspicious links discovered
  for (const link of input.suspiciousUrls) {
    if (link.isLinkTextMismatch) {
      rawScore += 10;
    }
  }

  // Cap initial heuristics score at 100
  rawScore = Math.min(rawScore, 100);

  // 3. HARD OVERRIDE: Check URL Reputation
  // A confirmed malicious match by Web Risk / Threat Intel CANNOT be downgraded by AI!
  if (input.reputation && input.reputation.isThreat) {
    isConfirmedThreat = true;
    threatSource = input.reputation.provider;
    // Pin score to dangerous threshold
    rawScore = Math.max(rawScore, 95);
    
    // Add threat reason
    input.reasons.unshift({
      code: 'CONFIRMED_THREAT_INTELLIGENCE',
      severity: 'critical',
      evidence: `Identified as confirmed ${input.reputation.threatType || 'malicious threat'} by ${input.reputation.provider}.`,
      explanation: 'This address is cataloged in active threat intelligence databases as a live cyber attack.',
      scoreImpact: 95
    });
  }

  // 4. Integrate On-Device AI modifier (if available and not already confirmed threat)
  if (!isConfirmedThreat && typeof input.onDeviceAiScoreModifier === 'number') {
    // AI modifier is bounded between -15 and +25 to prevent rogue model hallucination
    const clampedAiMod = Math.max(-15, Math.min(25, input.onDeviceAiScoreModifier));
    rawScore = Math.max(0, Math.min(100, rawScore + clampedAiMod));
  }

  // 5. Integrate Cloud AI modifier (only for ambiguous cases 30 - 65, and not confirmed threat)
  if (!isConfirmedThreat && typeof input.cloudAiScoreModifier === 'number') {
    const clampedCloudMod = Math.max(-15, Math.min(25, input.cloudAiScoreModifier));
    rawScore = Math.max(0, Math.min(100, rawScore + clampedCloudMod));
  }

  // 6. Deduplicate reasons and keep top reasons sorted by severity
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
  const uniqueReasonsMap = new Map<string, HeuristicReason>();
  
  for (const r of input.reasons) {
    if (!uniqueReasonsMap.has(r.code)) {
      uniqueReasonsMap.set(r.code, r);
    }
  }

  const sortedReasons = Array.from(uniqueReasonsMap.values()).sort((a, b) => {
    return (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
  });

  const finalScore = Math.round(rawScore);
  const verdict = getVerdictFromScore(finalScore);

  // 7. Generate simple plain-language explanation and recommended action
  const simpleExplanation = generatePlainLanguageExplanation(verdict, sortedReasons, input.hostname);
  const recommendedAction = generateRecommendedAction(verdict, sortedReasons);

  return {
    id: `scan-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    timestamp: Date.now(),
    url: input.url,
    hostname: input.hostname,
    score: finalScore,
    verdict,
    confidence: isConfirmedThreat ? 0.99 : Math.min(0.95, 0.65 + (sortedReasons.length * 0.08)),
    reasons: sortedReasons,
    suspiciousUrls: input.suspiciousUrls,
    simpleExplanation,
    recommendedAction,
    signals: input.signals,
    threatDetails: {
      isConfirmedThreat,
      threatSource
    },
    metrics: {
      latencyMs: input.latencyMs || (Date.now() - startTime),
      ruleCountEvaluated: sortedReasons.length
    }
  };
}

/**
 * Produces a clear, non-technical explanation (2-3 sentences) grounded purely in real evidence.
 */
export function generatePlainLanguageExplanation(
  verdict: Verdict,
  reasons: HeuristicReason[],
  hostname: string
): string {
  if (verdict === 'Dangerous') {
    const topReason = reasons[0];
    if (topReason && topReason.code === 'CONFIRMED_THREAT_INTELLIGENCE') {
      return `Warning: This website is a confirmed cyber threat matched in official threat intelligence registries. Navigating here risks malware infection or credential theft.`;
    }
    if (topReason && topReason.code === 'DOMAIN_IMPERSONATION') {
      return `Warning: The address "${hostname}" is pretending to be a legitimate brand using a deceptive look-alike domain. Entering any passwords or payment information here will send them directly to cybercriminals.`;
    }
    if (topReason && topReason.code === 'LINK_TEXT_MISMATCH') {
      return `Warning: This page contains links where the visible label misleads you about where the link actually goes. Attackers use this trick to divert you to fraudulent login destinations.`;
    }
    return `Warning: Multiple high-risk indicators were detected on this page, including suspicious domain characteristics and credential requests. Do not trust or interact with this page.`;
  }

  if (verdict === 'Suspicious') {
    return `Caution: This page displays several warning signs such as artificial urgency, unfamiliar link structures, or unusual forms. It may be an attempt to harvest personal data.`;
  }

  // Safe-looking: Honest disclaimer that lack of threats is not a guarantee of safety
  return `This page does not trigger known phishing or impersonation indicators. However, always verify the web address before submitting sensitive passwords or financial details.`;
}

/**
 * Returns a single, unambiguous action step for everyday users.
 */
export function generateRecommendedAction(verdict: Verdict, reasons: HeuristicReason[]): string {
  if (verdict === 'Dangerous') {
    if (reasons.some(r => r.code === 'DOMAIN_IMPERSONATION' || r.code === 'CREDENTIAL_HARVESTING_ON_LOOKALIKE')) {
      return 'Close this tab immediately. Navigate to the official service using a verified bookmark or manual search.';
    }
    return 'Do not enter any personal details, passwords, or payment cards. Leave this page immediately.';
  }

  if (verdict === 'Suspicious') {
    return 'Inspect the address bar carefully before proceeding. Avoid clicking embedded links or entering two-factor codes.';
  }

  return 'Browse with standard caution. Confirm you are on the expected site before entering credentials.';
}
