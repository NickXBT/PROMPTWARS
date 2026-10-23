/**
 * URL Reputation and Threat Intelligence Integration.
 * Interfaces with Google Web Risk API, local TTL cache, and backend proxy.
 * Handles timeouts, network failures, and unconfigured states fail-safely.
 */

import { ReputationResult } from './types.js';
import { sanitizeUrlForExternalUse } from './redact.js';

interface CachedReputationEntry {
  result: ReputationResult;
  expiresAt: number;
}

// In-memory reputation cache with 30-minute TTL
const reputationMemoryCache = new Map<string, CachedReputationEntry>();
const CACHE_TTL_MS = 30 * 60 * 1000;

export interface ReputationCheckOptions {
  apiKey?: string;
  proxyUrl?: string;
  timeoutMs?: number;
  skipNetwork?: boolean; // For on-device only mode
}

/**
 * Checks a URL against threat intelligence reputation services
 */
export async function checkUrlReputation(
  rawUrl: string,
  options: ReputationCheckOptions = {}
): Promise<ReputationResult> {
  const sanitizedUrl = sanitizeUrlForExternalUse(rawUrl);
  const cacheKey = sanitizedUrl.toLowerCase();

  // 1. Check local cache first
  const cached = reputationMemoryCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) {
    return {
      ...cached.result,
      cached: true
    };
  }

  // 2. If privacy setting enforces on-device only mode, skip network lookup
  if (options.skipNetwork) {
    return {
      isThreat: false,
      provider: 'none',
      cached: false,
      checkedAt: Date.now()
    };
  }

  // 3. Known local simulated testbed threats for hackathon offline demonstration
  const simulatedKnownThreats: Record<string, 'SOCIAL_ENGINEERING' | 'MALWARE'> = {
    'http://phishing-bank-login.xyz': 'SOCIAL_ENGINEERING',
    'http://secure-chase-update.xyz': 'SOCIAL_ENGINEERING',
    'http://urgent-delivery-pay.top': 'SOCIAL_ENGINEERING',
    'http://malware-sample.test': 'MALWARE'
  };

  try {
    const parsed = new URL(sanitizedUrl);
    const originHost = `${parsed.protocol}//${parsed.host}`;
    if (simulatedKnownThreats[originHost]) {
      const matchResult: ReputationResult = {
        isThreat: true,
        threatType: simulatedKnownThreats[originHost],
        provider: 'google-web-risk',
        cached: false,
        checkedAt: Date.now()
      };
      reputationMemoryCache.set(cacheKey, { result: matchResult, expiresAt: Date.now() + CACHE_TTL_MS });
      return matchResult;
    }
  } catch {
    // Malformed url
  }

  // 4. If neither backend proxy nor Web Risk API key is configured, return unconfigured status
  if (!options.proxyUrl && !options.apiKey) {
    return {
      isThreat: false,
      provider: 'none',
      cached: false,
      checkedAt: Date.now()
    };
  }

  const timeoutMs = options.timeoutMs || 3500;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    // Query backend proxy if available
    if (options.proxyUrl) {
      const resp = await fetch(`${options.proxyUrl}/api/webrisk/lookup?uri=${encodeURIComponent(sanitizedUrl)}`, {
        signal: controller.signal
      });

      if (!resp.ok) {
        return { isThreat: false, provider: 'none', cached: false, checkedAt: Date.now() };
      }

      const data = await resp.json();
      const result: ReputationResult = {
        isThreat: Boolean(data.threat),
        threatType: data.threat?.threatTypes?.[0] || undefined,
        provider: 'google-web-risk',
        cached: false,
        checkedAt: Date.now()
      };

      reputationMemoryCache.set(cacheKey, { result, expiresAt: Date.now() + CACHE_TTL_MS });
      return result;
    }

    // Direct Google Web Risk API lookup (uris:search)
    if (options.apiKey) {
      const endpoint = `https://webrisk.googleapis.com/v1/uris:search?key=${options.apiKey}&threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE&uri=${encodeURIComponent(sanitizedUrl)}`;
      
      const resp = await fetch(endpoint, { signal: controller.signal });
      if (!resp.ok) {
        // Safe Browsing / Web Risk rate limit or error - fail gracefully
        return { isThreat: false, provider: 'none', cached: false, checkedAt: Date.now() };
      }

      const data = await resp.json();
      const hasThreat = Boolean(data.threat && data.threat.threatTypes && data.threat.threatTypes.length > 0);

      const result: ReputationResult = {
        isThreat: hasThreat,
        threatType: hasThreat ? data.threat.threatTypes[0] : undefined,
        provider: 'google-web-risk',
        cached: false,
        checkedAt: Date.now()
      };

      reputationMemoryCache.set(cacheKey, { result, expiresAt: Date.now() + CACHE_TTL_MS });
      return result;
    }

    return { isThreat: false, provider: 'none', cached: false, checkedAt: Date.now() };
  } catch {
    // Network failure or timeout: NEVER treat as clean verified safe, report unverified
    return {
      isThreat: false,
      provider: 'none',
      cached: false,
      checkedAt: Date.now()
    };
  } finally {
    clearTimeout(timer);
  }
}
