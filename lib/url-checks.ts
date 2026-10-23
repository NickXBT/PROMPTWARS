/**
 * URL validation, link text mismatch, shortener, and open-redirect analysis.
 */

import { getRegistrableDomain } from './domain-similarity.js';

export const KNOWN_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'is.gd',
  'buff.ly',
  'ow.ly',
  'cutt.ly',
  'goo.gl',
  'rebrand.ly',
  'shorturl.at',
  'tiny.cc'
]);

export const REDIRECT_PARAM_KEYS = new Set([
  'url',
  'redirect',
  'redirect_url',
  'redirect_uri',
  'dest',
  'destination',
  'next',
  'target',
  'continue',
  'r',
  'out',
  'link',
  'to'
]);

export interface UrlCheckResult {
  url: string;
  isValid: boolean;
  isShortener: boolean;
  hasOpenRedirect: boolean;
  redirectTarget?: string;
  isIpAddress: boolean;
  isInsecureHttp: boolean;
  hasSuspiciousPort: boolean;
  port?: string;
  isTextMismatch: boolean;
  textDomain?: string;
  actualDomain?: string;
  reasons: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  scoreImpact: number;
}

/**
 * Validates and parses a URL safely without throwing
 */
export function safeParseUrl(input: string, baseOrigin?: string): URL | null {
  if (!input || typeof input !== 'string') return null;
  const trimmed = input.trim();
  if (trimmed.startsWith('javascript:') || trimmed.startsWith('data:') || trimmed.startsWith('vbscript:')) {
    return null;
  }
  try {
    return new URL(trimmed, baseOrigin || 'https://example.com');
  } catch {
    return null;
  }
}

/**
 * Checks if a string looks like an IPv4 or IPv6 address
 */
export function isIpAddressHostname(hostname: string): boolean {
  // IPv4 regex
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(hostname)) {
    const parts = hostname.split('.').map(p => parseInt(p, 10));
    return parts.every(p => p >= 0 && p <= 255);
  }
  // IPv6 check
  return hostname.includes(':') && /^\[?[a-fA-F0-9:]+\]?$/.test(hostname);
}

/**
 * Checks if an anchor's visible text pretends to be a specific domain or URL
 * that differs significantly from the actual href destination.
 * 
 * Handles benign text like "Click here", "Privacy Policy", or short domain previews.
 */
export function checkLinkTextMismatch(visibleText: string, destinationHref: string): {
  isMismatch: boolean;
  textDomain?: string;
  actualDomain?: string;
  reason?: string;
} {
  if (!visibleText || !destinationHref) {
    return { isMismatch: false };
  }

  const cleanText = visibleText.trim().toLowerCase();
  
  // Extract potential domain or URL mentioned inside the text
  // Matches e.g. "https://paypal.com/login", "www.chase.com", "bankofamerica.com"
  const urlInTextMatch = cleanText.match(/(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+\.[a-z]{2,}(?:\.[a-z]{2,})?)/i);

  if (!urlInTextMatch) {
    // Normal button or label text (e.g. "Submit", "Sign In", "Click here")
    return { isMismatch: false };
  }

  const parsedDest = safeParseUrl(destinationHref);
  if (!parsedDest) {
    return { isMismatch: false };
  }

  const textClaimedHost = urlInTextMatch[1];
  const destHost = parsedDest.hostname.toLowerCase();

  const textRegistrable = getRegistrableDomain(textClaimedHost).registrableDomain;
  const destRegistrable = getRegistrableDomain(destHost).registrableDomain;

  // If the text claimed a specific recognizable domain (e.g. paypal.com),
  // but destination points to a completely different registrable domain (e.g. attacker.com)
  if (textRegistrable && destRegistrable && textRegistrable !== destRegistrable) {
    return {
      isMismatch: true,
      textDomain: textRegistrable,
      actualDomain: destRegistrable,
      reason: `Link displays text pointing to "${textRegistrable}" but navigates to "${destRegistrable}".`
    };
  }

  return { isMismatch: false };
}

/**
 * Comprehensive inspection of an individual URL
 */
export function inspectUrl(urlStr: string, visibleText?: string, baseOrigin?: string): UrlCheckResult {
  const reasons: string[] = [];
  let scoreImpact = 0;
  let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';

  const parsed = safeParseUrl(urlStr, baseOrigin);
  if (!parsed) {
    return {
      url: urlStr,
      isValid: false,
      isShortener: false,
      hasOpenRedirect: false,
      isIpAddress: false,
      isInsecureHttp: false,
      hasSuspiciousPort: false,
      isTextMismatch: false,
      reasons: ['Malformed or invalid URL scheme'],
      severity: 'medium',
      scoreImpact: 15
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const { registrableDomain } = getRegistrableDomain(hostname);

  // 1. IP Address Hostname
  const isIp = isIpAddressHostname(hostname);
  if (isIp) {
    reasons.push(`URL uses raw numeric IP address (${hostname}) instead of a trusted domain name.`);
    scoreImpact += 35;
    severity = 'high';
  }

  // 2. URL Shortener
  const isShortener = KNOWN_SHORTENERS.has(registrableDomain) || KNOWN_SHORTENERS.has(hostname);
  if (isShortener) {
    reasons.push(`URL uses shortening service "${hostname}" which obscures the true destination.`);
    scoreImpact += 20;
    if (severity === 'low') severity = 'medium';
  }

  // 3. Open Redirect Parameters
  let hasOpenRedirect = false;
  let redirectTarget: string | undefined;

  for (const [key, val] of parsed.searchParams.entries()) {
    if (REDIRECT_PARAM_KEYS.has(key.toLowerCase()) && (val.startsWith('http://') || val.startsWith('https://') || val.startsWith('//'))) {
      hasOpenRedirect = true;
      redirectTarget = val;
      reasons.push(`URL contains an embedded redirect target parameter ("${key}=${val}").`);
      scoreImpact += 25;
      if (severity === 'low') severity = 'medium';
      break;
    }
  }

  // 4. Insecure HTTP
  const isInsecureHttp = parsed.protocol === 'http:';
  if (isInsecureHttp && !['localhost', '127.0.0.1'].includes(hostname)) {
    reasons.push('URL transmits unencrypted data over plain HTTP.');
    scoreImpact += 15;
  }

  // 5. Suspicious Port
  const nonStandardPorts = ['8080', '8888', '2082', '2083', '8443', '10000'];
  const hasSuspiciousPort = parsed.port !== '' && nonStandardPorts.includes(parsed.port);
  if (hasSuspiciousPort) {
    reasons.push(`URL specifies unusual port :${parsed.port}.`);
    scoreImpact += 15;
  }

  // 6. Link Text Mismatch
  let isTextMismatch = false;
  let textDomain: string | undefined;
  let actualDomain: string | undefined;

  if (visibleText) {
    const mismatch = checkLinkTextMismatch(visibleText, parsed.href);
    if (mismatch.isMismatch) {
      isTextMismatch = true;
      textDomain = mismatch.textDomain;
      actualDomain = mismatch.actualDomain;
      reasons.push(mismatch.reason || 'Visible link text misrepresents the actual web destination.');
      scoreImpact += 45;
      severity = 'high';
    }
  }

  if (scoreImpact >= 50) {
    severity = 'high';
  } else if (scoreImpact >= 25) {
    severity = 'medium';
  }

  return {
    url: parsed.href,
    isValid: true,
    isShortener,
    hasOpenRedirect,
    redirectTarget,
    isIpAddress: isIp,
    isInsecureHttp,
    hasSuspiciousPort,
    port: parsed.port || undefined,
    isTextMismatch,
    textDomain,
    actualDomain,
    reasons,
    severity,
    scoreImpact
  };
}
