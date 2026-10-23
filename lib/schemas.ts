/**
 * Runtime schema validation and boundary checks.
 * Validates extension messages and input objects to prevent code execution or state corruption.
 */

import { PageAnalysisContext, AnalysisResult } from './types.js';

export type ExtensionMessageType =
  | 'ANALYZE_PAGE_REQUEST'
  | 'ANALYZE_PAGE_RESPONSE'
  | 'GET_CURRENT_RESULT_REQUEST'
  | 'GET_CURRENT_RESULT_RESPONSE'
  | 'SCAN_SELECTION_REQUEST'
  | 'REPORT_PHISHING_REQUEST'
  | 'REPORT_PHISHING_RESPONSE';

export interface ExtensionMessage<T = unknown> {
  type: ExtensionMessageType;
  payload?: T;
  tabId?: number;
}

/**
 * Validates whether an incoming object is a valid PageAnalysisContext
 */
export function validatePageAnalysisContext(obj: unknown): obj is PageAnalysisContext {
  if (!obj || typeof obj !== 'object') return false;
  const ctx = obj as Partial<PageAnalysisContext>;

  if (typeof ctx.url !== 'string' || !ctx.url) return false;
  if (typeof ctx.hostname !== 'string') return false;
  if (typeof ctx.title !== 'string') return false;
  if (!Array.isArray(ctx.forms)) return false;
  if (!Array.isArray(ctx.links)) return false;

  return true;
}

/**
 * Validates whether an incoming object conforms to AnalysisResult
 */
export function validateAnalysisResult(obj: unknown): obj is AnalysisResult {
  if (!obj || typeof obj !== 'object') return false;
  const res = obj as Partial<AnalysisResult>;

  if (typeof res.id !== 'string') return false;
  if (typeof res.url !== 'string') return false;
  if (typeof res.score !== 'number' || res.score < 0 || res.score > 100) return false;
  if (res.verdict !== 'Safe-looking' && res.verdict !== 'Suspicious' && res.verdict !== 'Dangerous') return false;
  if (!Array.isArray(res.reasons)) return false;
  if (!Array.isArray(res.suspiciousUrls)) return false;
  if (typeof res.simpleExplanation !== 'string') return false;
  if (typeof res.recommendedAction !== 'string') return false;

  return true;
}

/**
 * Validates an extension message envelope
 */
export function validateExtensionMessage(msg: unknown): msg is ExtensionMessage {
  if (!msg || typeof msg !== 'object') return false;
  const m = msg as Partial<ExtensionMessage>;
  return typeof m.type === 'string';
}
