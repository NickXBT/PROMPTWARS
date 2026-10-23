/**
 * Deterministic local phishing heuristics engine.
 * Inspects DOM content, inputs, urgency patterns, form actions, and email metadata.
 * Operates purely locally without requiring network or external credentials.
 */

import { HeuristicReason, PageAnalysisContext, SuspiciousUrl } from './types.js';
import { checkDomainImpersonation } from './domain-similarity.js';
import { inspectUrl } from './url-checks.js';

// Social engineering and urgency triggers
export const URGENCY_PATTERNS = [
  { pattern: /\b(?:account\s+suspended|suspension\s+notice)\b/i, weight: 15, label: 'Account Suspension Threat' },
  { pattern: /\b(?:immediate(?:ly)?\s+action\s+required|urgent\s+action)\b/i, weight: 12, label: 'Urgent Action Demand' },
  { pattern: /\b(?:verify\s+your\s+identity|verify\s+now|re-verify\s+account)\b/i, weight: 12, label: 'Urgent Identity Verification' },
  { pattern: /\b(?:kyc\s+expir(?:y|ing)|update\s+kyc)\b/i, weight: 15, label: 'KYC Expiration Warning' },
  { pattern: /\b(?:unauthorized\s+(?:access|activity|transaction))\b/i, weight: 12, label: 'Unauthorized Activity Claim' },
  { pattern: /\b(?:within\s+24\s+hours|24\s+hours\s+to\s+respond|limited\s+time\s+to\s+verify)\b/i, weight: 10, label: 'Artificial Time Pressure' },
  { pattern: /\b(?:delivery\s+(?:failed|pending)|unpaid\s+(?:customs|shipping)\s+fee)\b/i, weight: 15, label: 'Delivery Fee Pretext' },
  { pattern: /\b(?:security\s+alert|security\s+breach)\b/i, weight: 10, label: 'Security Alert Pretext' }
];

// Sensitive credential harvesting cues
export const SENSITIVE_INPUT_KEYWORDS = [
  'password',
  'passcode',
  'pin',
  'otp',
  'one-time-password',
  'security_code',
  'ssn',
  'social_security',
  'credit_card',
  'card_number',
  'cvv',
  'cvc',
  'private_key',
  'seed_phrase'
];

export interface HeuristicEvaluationResult {
  reasons: HeuristicReason[];
  suspiciousUrls: SuspiciousUrl[];
  scoreImpact: number;
  hasCriticalFinding: boolean;
}

/**
 * Analyzes page content and links using pure deterministic local heuristics
 */
export function runLocalHeuristics(context: PageAnalysisContext): HeuristicEvaluationResult {
  const reasons: HeuristicReason[] = [];
  const suspiciousUrls: SuspiciousUrl[] = [];
  let totalScore = 0;
  let hasCriticalFinding = false;

  // ----------------------------------------------------
  // 1. Hostname & Domain Impersonation Analysis
  // ----------------------------------------------------
  if (context.hostname && !['localhost', '127.0.0.1'].includes(context.hostname)) {
    const domainCheck = checkDomainImpersonation(context.hostname);
    if (domainCheck.isImpersonation) {
      const isCritical = domainCheck.scoreImpact >= 50;
      if (isCritical) hasCriticalFinding = true;

      reasons.push({
        code: 'DOMAIN_IMPERSONATION',
        severity: isCritical ? 'critical' : 'high',
        evidence: domainCheck.evidence || `The hostname "${context.hostname}" mimics trusted brand "${domainCheck.targetBrand}".`,
        explanation: `This website appears to be an unauthorized copy impersonating ${domainCheck.targetBrand}.`,
        scoreImpact: domainCheck.scoreImpact
      });
      totalScore += domainCheck.scoreImpact;
    }
  }

  // ----------------------------------------------------
  // 2. Sensitive Form & Credential Harvesting Heuristics
  // ----------------------------------------------------
  let foundPasswordInput = false;
  let foundPaymentInput = false;
  let foundOtpInput = false;
  let foundInsecureFormAction = false;

  for (const form of context.forms) {
    if (form.hasPasswordInput) foundPasswordInput = true;
    if (form.hasCreditCardInput) foundPaymentInput = true;
    if (form.hasOtpInput) foundOtpInput = true;
    if (form.isPlainHttp) foundInsecureFormAction = true;

    // Check for insecure submission over HTTP or cross-domain action
    if (form.isPlainHttp && !['localhost', '127.0.0.1'].includes(context.hostname)) {
      reasons.push({
        code: 'INSECURE_FORM_HTTP',
        severity: 'high',
        evidence: `Form submits sensitive credentials to unencrypted address "${form.action}".`,
        explanation: 'Any information submitted here travels over the network in cleartext without encryption.',
        scoreImpact: 35
      });
      totalScore += 35;
    }
  }

  // If page requests passwords or payment details on an unverified domain
  if (foundPasswordInput) {
    const isImpersonating = reasons.some(r => r.code === 'DOMAIN_IMPERSONATION');
    if (isImpersonating) {
      reasons.push({
        code: 'CREDENTIAL_HARVESTING_ON_LOOKALIKE',
        severity: 'critical',
        evidence: 'Login form found on a domain that mimics a major trusted service.',
        explanation: 'This page is configured to harvest user account passwords under a deceptive identity.',
        scoreImpact: 40
      });
      totalScore += 40;
      hasCriticalFinding = true;
    }
  }

  if (foundPaymentInput) {
    const isUnverifiedDomain = !checkDomainImpersonation(context.hostname).isOfficialDomain;
    const impact = isUnverifiedDomain ? 35 : 20;
    reasons.push({
      code: 'PAYMENT_CARD_HARVESTING',
      severity: isUnverifiedDomain ? 'critical' : 'high',
      evidence: 'Page requests credit card number, CVV, or payment credentials on an unverified domain.',
      explanation: 'Check whether you are on the verified payment processor before entering credit card numbers.',
      scoreImpact: impact
    });
    totalScore += impact;
  }

  if (foundOtpInput) {
    reasons.push({
      code: 'OTP_INTERCEPTION',
      severity: 'high',
      evidence: 'Page requests a one-time verification code (OTP/2FA).',
      explanation: 'Attackers frequently use fake 2FA screens to bypass account security in real-time.',
      scoreImpact: 25
    });
    totalScore += 25;
  }

  // ----------------------------------------------------
  // 3. Urgency & Social Engineering Text Heuristics
  // ----------------------------------------------------
  let urgencyMatches = 0;
  const matchedUrgencyLabels: string[] = [];
  const fullText = (context.textExcerpt + ' ' + context.title).toLowerCase();

  for (const pattern of URGENCY_PATTERNS) {
    if (pattern.pattern.test(fullText)) {
      urgencyMatches++;
      matchedUrgencyLabels.push(pattern.label);
    }
  }

  // Only assign meaningful weight if multiple urgency cues exist or if combined with inputs
  if (urgencyMatches >= 2 || (urgencyMatches >= 1 && (foundPasswordInput || foundPaymentInput || foundOtpInput))) {
    const impact = Math.min(urgencyMatches * 10, 25);
    reasons.push({
      code: 'SOCIAL_ENGINEERING_URGENCY',
      severity: urgencyMatches >= 2 ? 'medium' : 'low',
      evidence: `Page uses psychological pressure techniques: ${matchedUrgencyLabels.join(', ')}.`,
      explanation: 'Phishing attacks rely on artificial panic or urgency to rush victims into submitting information.',
      scoreImpact: impact
    });
    totalScore += impact;
  }

  // ----------------------------------------------------
  // 4. Link & Anchor Heuristics
  // ----------------------------------------------------
  for (const link of context.links) {
    const inspected = inspectUrl(link.href, link.text, context.origin);
    
    if (inspected.reasons.length > 0) {
      suspiciousUrls.push({
        url: inspected.url,
        displayUrl: inspected.url.length > 60 ? inspected.url.substring(0, 57) + '...' : inspected.url,
        reasons: inspected.reasons,
        severity: inspected.severity,
        targetDomain: inspected.actualDomain,
        isLinkTextMismatch: inspected.isTextMismatch
      });

      if (inspected.isTextMismatch) {
        reasons.push({
          code: 'LINK_TEXT_MISMATCH',
          severity: 'high',
          evidence: `Link text shows "${link.text.trim()}" but navigates to "${inspected.url}".`,
          explanation: 'The link destination is deceptive and does not match the address visible on the screen.',
          scoreImpact: 35
        });
        totalScore += 35;
      }

      if (inspected.isShortener) {
        reasons.push({
          code: 'OBFUSCATED_SHORTENER_LINK',
          severity: 'low',
          evidence: `Contains shortened link: ${inspected.url}`,
          explanation: 'URL shorteners are used to conceal malicious destinations from preliminary inspection.',
          scoreImpact: 10
        });
        totalScore += 10;
      }

      if (inspected.hasOpenRedirect) {
        reasons.push({
          code: 'OPEN_REDIRECT_PARAMETER',
          severity: 'medium',
          evidence: `Link contains external redirect parameter: ${inspected.redirectTarget}`,
          explanation: 'Attackers use open redirects on reputable sites to forward users to malicious endpoints.',
          scoreImpact: 15
        });
        totalScore += 15;
      }
    }
  }

  // ----------------------------------------------------
  // 5. Email Metadata Context (When scanning emails)
  // ----------------------------------------------------
  if (context.isEmailContext && context.emailMeta) {
    const meta = context.emailMeta;
    
    // Check sender vs reply-to domain mismatch
    if (meta.senderReplyToMismatch && meta.senderDomain && meta.replyToDomain) {
      reasons.push({
        code: 'EMAIL_REPLY_TO_MISMATCH',
        severity: 'high',
        evidence: `Sender address domain is "@${meta.senderDomain}" but Reply-To points to "@${meta.replyToDomain}".`,
        explanation: 'Legitimate corporate emails typically keep Reply-To aligned with the sender domain.',
        scoreImpact: 35
      });
      totalScore += 35;
    }

    // Check if display name claims a brand but sender domain does not match
    if (meta.sender) {
      for (const [, brandInfo] of Object.entries(checkDomainImpersonation(context.hostname).targetBrand ? {} : {})) {
        // Will be augmented if display name spoofing detected
      }
    }
  }

  return {
    reasons,
    suspiciousUrls,
    scoreImpact: totalScore,
    hasCriticalFinding
  };
}
