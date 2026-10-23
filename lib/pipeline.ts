/**
 * End-to-end multi-stage Phishing Detection Pipeline.
 * Orchestrates:
 * Stage A: Local Deterministic Heuristics
 * Stage B: Threat Intelligence & URL Reputation
 * Stage C: Chrome Built-in AI (Gemini Nano Prompt API)
 * Stage D: Cloud Gemini (Ambiguous range only, privacy-redacted)
 * Stage E: Score Consolidation & Plain-Language Explanation
 */

import { AnalysisResult, DetectionSignals, PageAnalysisContext, ExtensionSettings } from './types.js';
import { runLocalHeuristics } from './heuristics.js';
import { checkUrlReputation } from './reputation.js';
import { analyzeWithGeminiNano, checkBuiltInAiAvailability } from './gemini-nano.js';
import { analyzeWithCloudGemini } from './gemini-api.js';
import { calculateRiskScore } from './scoring.js';
import { saveScanResult } from './storage.js';

export async function runDetectionPipeline(
  context: PageAnalysisContext,
  settings: ExtensionSettings
): Promise<AnalysisResult> {
  const startTime = Date.now();

  const signals: DetectionSignals = {
    heuristics: 'completed',
    reputation: 'unavailable',
    onDeviceAI: 'unavailable',
    cloudAI: 'not_needed'
  };

  // -------------------------------------------------------------------------
  // Stage A: Local Deterministic Heuristics (Always runs, zero external calls)
  // -------------------------------------------------------------------------
  const heuristicResult = runLocalHeuristics(context);
  signals.heuristics = 'completed';

  // Preliminary score calculation from local heuristics
  let provisionalScore = Math.min(100, heuristicResult.scoreImpact);

  // -------------------------------------------------------------------------
  // Stage B: Threat Intelligence / URL Reputation
  // -------------------------------------------------------------------------
  let reputationResult = undefined;
  if (settings.onDeviceOnlyMode) {
    signals.reputation = 'skipped';
  } else {
    try {
      reputationResult = await checkUrlReputation(context.url, {
        apiKey: settings.webRiskApiKey,
        proxyUrl: settings.backendProxyUrl,
        skipNetwork: settings.onDeviceOnlyMode
      });

      signals.reputation = reputationResult.provider !== 'none' ? 'completed' : 'unavailable';
    } catch {
      signals.reputation = 'error';
    }
  }

  // -------------------------------------------------------------------------
  // Stage C: Chrome Built-in AI Prompt API / Gemini Nano (Local on-device)
  // -------------------------------------------------------------------------
  let onDeviceAiModifier = 0;
  if (settings.enableGeminiNano) {
    const aiCapabilities = await checkBuiltInAiAvailability();
    if (aiCapabilities.available) {
      try {
        const nanoResp = await analyzeWithGeminiNano(
          context.textExcerpt,
          context.hostname,
          heuristicResult.reasons.map(r => r.code)
        );

        if (nanoResp) {
          onDeviceAiModifier = nanoResp.suspicionScoreModifier;
          signals.onDeviceAI = 'completed';
        } else {
          signals.onDeviceAI = 'error';
        }
      } catch {
        signals.onDeviceAI = 'error';
      }
    } else {
      signals.onDeviceAI = 'unavailable';
    }
  } else {
    signals.onDeviceAI = 'skipped';
  }

  // Calculate interim score to see if it qualifies as ambiguous
  const interimScore = Math.max(0, Math.min(100, provisionalScore + onDeviceAiModifier));

  // -------------------------------------------------------------------------
  // Stage D: Optional Cloud Gemini Analysis (Ambiguous range only)
  // -------------------------------------------------------------------------
  let cloudAiModifier = 0;
  const isAmbiguous = interimScore >= settings.ambiguousScoreMin && interimScore <= settings.ambiguousScoreMax;

  if (settings.onDeviceOnlyMode || !settings.enableCloudGemini) {
    signals.cloudAI = settings.onDeviceOnlyMode ? 'skipped' : 'not_needed';
  } else if (isAmbiguous) {
    try {
      const cloudResp = await analyzeWithCloudGemini(
        context.textExcerpt,
        context.url,
        heuristicResult.reasons.map(r => r.code),
        {
          apiKey: settings.geminiApiKey,
          proxyUrl: settings.backendProxyUrl
        }
      );

      if (cloudResp) {
        cloudAiModifier = cloudResp.suspicionScoreModifier;
        signals.cloudAI = 'completed';
      } else {
        signals.cloudAI = 'error';
      }
    } catch {
      signals.cloudAI = 'error';
    }
  } else {
    signals.cloudAI = 'not_needed';
  }

  // -------------------------------------------------------------------------
  // Stage E: Final Score & Verdict Calculation
  // -------------------------------------------------------------------------
  const finalResult = calculateRiskScore({
    url: context.url,
    hostname: context.hostname,
    reasons: [...heuristicResult.reasons],
    suspiciousUrls: heuristicResult.suspiciousUrls,
    reputation: reputationResult,
    onDeviceAiScoreModifier: onDeviceAiModifier,
    cloudAiScoreModifier: cloudAiModifier,
    signals,
    latencyMs: Date.now() - startTime
  });

  // Persist result into local history
  await saveScanResult(finalResult);

  return finalResult;
}
