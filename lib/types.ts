/**
 * Phishing Shield AI - Core Type Definitions
 * Strict types for cross-component security analysis
 */

export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';

export type Verdict = 'Safe-looking' | 'Suspicious' | 'Dangerous';

export type SignalStatus = 'completed' | 'skipped' | 'unavailable' | 'error' | 'not_needed';

export interface DetectionSignals {
  heuristics: SignalStatus;
  reputation: SignalStatus;
  onDeviceAI: SignalStatus;
  cloudAI: SignalStatus;
}

export interface HeuristicReason {
  code: string;
  severity: SeverityLevel;
  evidence: string;
  explanation: string;
  scoreImpact: number;
}

export interface SuspiciousUrl {
  url: string;
  displayUrl: string;
  reasons: string[];
  severity: SeverityLevel;
  targetDomain?: string;
  isLinkTextMismatch?: boolean;
}

export interface FormInfo {
  action: string;
  method: string;
  hasPasswordInput: boolean;
  hasCreditCardInput: boolean;
  hasOtpInput: boolean;
  inputTypes: string[];
  isCrossDomain: boolean;
  isPlainHttp: boolean;
}

export interface LinkInfo {
  href: string;
  text: string;
  isExternal: boolean;
  isShortener?: boolean;
  hasRedirectParam?: boolean;
  textMismatchesHref?: boolean;
}

export interface EmailMetadata {
  sender?: string;
  replyTo?: string;
  senderDomain?: string;
  replyToDomain?: string;
  subject?: string;
  senderReplyToMismatch?: boolean;
}

export interface PageAnalysisContext {
  url: string;
  origin: string;
  hostname: string;
  pathname: string;
  title: string;
  textExcerpt: string;
  forms: FormInfo[];
  links: LinkInfo[];
  hasSensitiveInputs: boolean;
  inputTypes: string[];
  isEmailContext?: boolean;
  emailMeta?: EmailMetadata;
}

export interface ReputationResult {
  isThreat: boolean;
  threatType?: 'MALWARE' | 'SOCIAL_ENGINEERING' | 'UNWANTED_SOFTWARE' | 'THREAT_TYPE_UNSPECIFIED';
  provider: 'google-web-risk' | 'community' | 'local-cache' | 'none';
  cached: boolean;
  checkedAt: number;
}

export interface AIAnalysisResult {
  scoreModifier?: number;
  reasoning?: string;
  detectedTactics?: string[];
  confidence: number;
  provider: 'gemini-nano' | 'gemini-cloud' | 'mock-simulation';
}

export interface AnalysisResult {
  id: string;
  timestamp: number;
  url: string;
  hostname: string;
  score: number; // 0 - 100
  verdict: Verdict;
  confidence: number;
  reasons: HeuristicReason[];
  suspiciousUrls: SuspiciousUrl[];
  simpleExplanation: string;
  recommendedAction: string;
  signals: DetectionSignals;
  threatDetails?: {
    isConfirmedThreat: boolean;
    threatSource?: string;
  };
  metrics?: {
    latencyMs: number;
    ruleCountEvaluated: number;
  };
}

export interface ExtensionSettings {
  onDeviceOnlyMode: boolean;
  enableGeminiNano: boolean;
  enableCloudGemini: boolean;
  geminiApiKey: string;
  enableWebRisk: boolean;
  webRiskApiKey: string;
  backendProxyUrl: string;
  enableGmailScanning: boolean;
  enableCommunityReporting: boolean;
  ambiguousScoreMin: number; // e.g. 30
  ambiguousScoreMax: number; // e.g. 70
}

export const DEFAULT_SETTINGS: ExtensionSettings = {
  onDeviceOnlyMode: false,
  enableGeminiNano: true,
  enableCloudGemini: false,
  geminiApiKey: '',
  enableWebRisk: false,
  webRiskApiKey: '',
  backendProxyUrl: 'http://localhost:8080',
  enableGmailScanning: true,
  enableCommunityReporting: true,
  ambiguousScoreMin: 30,
  ambiguousScoreMax: 65
};
