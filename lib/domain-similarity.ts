/**
 * Domain similarity, typosquatting, homoglyph, and brand impersonation detection.
 * Compares registrable domains and hostnames with strict boundary checking.
 */

// High-value targets commonly spoofed in phishing campaigns
export const TARGET_BRANDS: Record<string, { brand: string; officialDomains: string[]; category: 'finance' | 'tech' | 'shipping' | 'government' | 'crypto' }> = {
  paypal: {
    brand: 'PayPal',
    officialDomains: ['paypal.com', 'paypal-community.com'],
    category: 'finance'
  },
  google: {
    brand: 'Google',
    officialDomains: ['google.com', 'accounts.google.com', 'gmail.com'],
    category: 'tech'
  },
  microsoft: {
    brand: 'Microsoft',
    officialDomains: ['microsoft.com', 'live.com', 'login.microsoftonline.com', 'office.com'],
    category: 'tech'
  },
  apple: {
    brand: 'Apple',
    officialDomains: ['apple.com', 'icloud.com', 'appleid.apple.com'],
    category: 'tech'
  },
  amazon: {
    brand: 'Amazon',
    officialDomains: ['amazon.com', 'aws.amazon.com'],
    category: 'tech'
  },
  chase: {
    brand: 'Chase Bank',
    officialDomains: ['chase.com', 'jpmorganchase.com'],
    category: 'finance'
  },
  wellsfargo: {
    brand: 'Wells Fargo',
    officialDomains: ['wellsfargo.com'],
    category: 'finance'
  },
  bankofamerica: {
    brand: 'Bank of America',
    officialDomains: ['bankofamerica.com', 'bofa.com'],
    category: 'finance'
  },
  dhl: {
    brand: 'DHL Express',
    officialDomains: ['dhl.com'],
    category: 'shipping'
  },
  fedex: {
    brand: 'FedEx',
    officialDomains: ['fedex.com'],
    category: 'shipping'
  },
  usps: {
    brand: 'USPS',
    officialDomains: ['usps.com'],
    category: 'shipping'
  },
  irs: {
    brand: 'Internal Revenue Service (IRS)',
    officialDomains: ['irs.gov'],
    category: 'government'
  },
  netflix: {
    brand: 'Netflix',
    officialDomains: ['netflix.com'],
    category: 'tech'
  }
};

// Common suspicious TLDs frequently abused in cheap bulk-registration phishing
export const HIGH_RISK_TLDS = new Set([
  'xyz', 'top', 'click', 'buzz', 'work', 'loan', 'surf', 'gq', 'cf', 'ml', 'tk', 'zip', 'mov'
]);

// Character homoglyphs and visually identical substitutes
export const HOMOGLYPH_MAP: Record<string, string> = {
  'а': 'a', // Cyrillic Small Letter A
  'с': 'c', // Cyrillic Small Letter Es
  'е': 'e', // Cyrillic Small Letter Ie
  'о': 'o', // Cyrillic Small Letter O
  'р': 'p', // Cyrillic Small Letter Er
  'ѕ': 's', // Cyrillic Small Letter Dze
  'і': 'i', // Cyrillic Small Letter Byelorussian-Ukrainian I
  'ј': 'j', // Cyrillic Small Letter Je
  'ԁ': 'd', // Cyrillic Small Letter Komi De
  'ԛ': 'q', // Cyrillic Small Letter Qa
  'ѵ': 'v', // Cyrillic Small Letter Izhitsa
  'ո': 'n', // Armenian Small Letter Now
  'υ': 'u', // Greek Small Letter Upsilon
  'ο': 'o', // Greek Small Letter Omicron
  '0': 'o', // Number zero spoofing 'o'
  '1': 'l', // Number one spoofing 'l' or 'i'
  'vv': 'w' // Double 'v' spoofing 'w'
};

/**
 * Standard Levenshtein distance between two strings
 */
export function calculateLevenshtein(a: string, b: string): number {
  const matrix: number[][] = [];
  const aLen = a.length;
  const bLen = b.length;

  if (aLen === 0) return bLen;
  if (bLen === 0) return aLen;

  for (let i = 0; i <= aLen; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= bLen; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= aLen; i++) {
    for (let j = 1; j <= bLen; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,      // deletion
        matrix[i][j - 1] + 1,      // insertion
        matrix[i - 1][j - 1] + cost // substitution
      );
    }
  }

  return matrix[aLen][bLen];
}

/**
 * Extracts the registrable domain (e.g. example.com) from a full hostname
 * Handles common 2-level TLDs (.co.uk, .com.au, .gov.uk, etc.)
 */
export function getRegistrableDomain(hostname: string): { registrableDomain: string; subdomains: string; tld: string } {
  const cleanHost = hostname.toLowerCase().trim();
  const parts = cleanHost.split('.');

  if (parts.length <= 1) {
    return { registrableDomain: cleanHost, subdomains: '', tld: '' };
  }

  const multiPartTlds = new Set(['co.uk', 'com.au', 'co.nz', 'co.jp', 'gov.uk', 'com.br', 'org.uk']);
  const lastTwo = parts.slice(-2).join('.');
  let domainPartsCount = 2;

  if (parts.length >= 3 && multiPartTlds.has(lastTwo)) {
    domainPartsCount = 3;
  }

  const registrableParts = parts.slice(-domainPartsCount);
  const subdomainParts = parts.slice(0, -domainPartsCount);

  return {
    registrableDomain: registrableParts.join('.'),
    subdomains: subdomainParts.join('.'),
    tld: registrableParts.slice(1).join('.')
  };
}

/**
 * Normalizes unicode/punycode string to identify hidden homoglyphs
 */
export function normalizeHomoglyphs(text: string): { normalized: string; hadHomoglyphs: boolean; isPunycode: boolean } {
  let isPunycode = false;
  let decodedText = text.toLowerCase();

  if (decodedText.startsWith('xn--')) {
    isPunycode = true;
    try {
      // In browser/node URL parser or modern runtime
      decodedText = new URL(`http://${decodedText}`).hostname;
    } catch {
      // Keep as-is if parsing fails
    }
  }

  let hadHomoglyphs = false;
  let normalized = '';

  for (let i = 0; i < decodedText.length; i++) {
    const char = decodedText[i];
    // Check 2-char sequence e.g. 'vv'
    if (char === 'v' && decodedText[i + 1] === 'v') {
      normalized += 'w';
      hadHomoglyphs = true;
      i++;
      continue;
    }

    if (HOMOGLYPH_MAP[char]) {
      normalized += HOMOGLYPH_MAP[char];
      hadHomoglyphs = true;
    } else {
      normalized += char;
    }
  }

  return { normalized, hadHomoglyphs, isPunycode };
}

export interface DomainCheckResult {
  isImpersonation: boolean;
  isOfficialDomain: boolean;
  targetBrand?: string;
  officialDomain?: string;
  impersonationType?: 'typosquat' | 'homoglyph' | 'subdomain_spoof' | 'keyword_squat';
  evidence?: string;
  scoreImpact: number;
}

/**
 * Checks a hostname against brand profiles for impersonation, typosquatting, or homoglyphs.
 */
export function checkDomainImpersonation(hostname: string): DomainCheckResult {
  const cleanHost = hostname.toLowerCase().trim();
  const { registrableDomain, subdomains, tld } = getRegistrableDomain(cleanHost);
  const domainNameWithoutTld = registrableDomain.split('.')[0];

  // 1. Check if it's already an official domain for a known brand
  for (const [, brandInfo] of Object.entries(TARGET_BRANDS)) {
    for (const official of brandInfo.officialDomains) {
      if (cleanHost === official || cleanHost.endsWith('.' + official)) {
        return {
          isImpersonation: false,
          isOfficialDomain: true,
          targetBrand: brandInfo.brand,
          officialDomain: official,
          scoreImpact: 0
        };
      }
    }
  }

  // 2. Check for Subdomain Masquerading
  // e.g., paypal.com.account-update.xyz where registrable domain is account-update.xyz
  if (subdomains) {
    for (const [, brandInfo] of Object.entries(TARGET_BRANDS)) {
      for (const official of brandInfo.officialDomains) {
        if (subdomains === official || subdomains.endsWith('.' + official) || subdomains.includes(official.replace(/\./g, '-'))) {
          return {
            isImpersonation: true,
            isOfficialDomain: false,
            targetBrand: brandInfo.brand,
            officialDomain: official,
            impersonationType: 'subdomain_spoof',
            evidence: `Domain uses "${official}" inside its subdomain (${subdomains}), but the actual destination domain is "${registrableDomain}".`,
            scoreImpact: 55
          };
        }
      }
    }
  }

  // 3. Check for Homoglyphs & Punycode in Registrable Domain
  const homoglyphResult = normalizeHomoglyphs(domainNameWithoutTld);
  if (homoglyphResult.hadHomoglyphs || homoglyphResult.isPunycode) {
    for (const [, brandInfo] of Object.entries(TARGET_BRANDS)) {
      for (const official of brandInfo.officialDomains) {
        const officialRoot = official.split('.')[0];
        if (homoglyphResult.normalized === officialRoot) {
          return {
            isImpersonation: true,
            isOfficialDomain: false,
            targetBrand: brandInfo.brand,
            officialDomain: official,
            impersonationType: 'homoglyph',
            evidence: `Domain "${cleanHost}" uses deceptive Unicode homoglyphs or Punycode to visually imitate "${official}".`,
            scoreImpact: 60
          };
        }
      }
    }
  }

  // 4. Check for Typosquatting (Levenshtein Distance 1 or 2)
  for (const [, brandInfo] of Object.entries(TARGET_BRANDS)) {
    for (const official of brandInfo.officialDomains) {
      const officialRoot = official.split('.')[0];
      
      // Calculate distance on raw domain root and homoglyph-normalized root
      const distRaw = calculateLevenshtein(domainNameWithoutTld, officialRoot);
      const distNorm = calculateLevenshtein(homoglyphResult.normalized, officialRoot);
      const minDistance = Math.min(distRaw, distNorm);

      // Typosquat rule: length >= 4, distance 1, or distance 2 on longer names
      if ((officialRoot.length >= 4 && minDistance === 1) || (officialRoot.length >= 7 && minDistance === 2)) {
        return {
          isImpersonation: true,
          isOfficialDomain: false,
          targetBrand: brandInfo.brand,
          officialDomain: official,
          impersonationType: 'typosquat',
          evidence: `Domain "${registrableDomain}" has an edit distance of ${minDistance} from official brand domain "${official}".`,
          scoreImpact: 50
        };
      }
    }
  }

  // 5. Check for Keyword Squatting (e.g., paypal-verify, paypa1-verify, chase-online-secure)
  const suspiciousKeywords = ['verify', 'secure', 'login', 'account', 'update', 'banking', 'support', 'auth', 'signin'];
  const normRoot = homoglyphResult.normalized;

  for (const [, brandInfo] of Object.entries(TARGET_BRANDS)) {
    const brandKey = brandInfo.brand.toLowerCase().replace(/\s+/g, '');
    const official = brandInfo.officialDomains[0];
    const officialRoot = official.split('.')[0];

    const containsBrand = 
      domainNameWithoutTld.includes(officialRoot) || 
      domainNameWithoutTld.includes(brandKey) ||
      normRoot.includes(officialRoot) ||
      normRoot.includes(brandKey);

    if (containsBrand) {
      // Must not be the official domain
      const hasSuspiciousKeyword = suspiciousKeywords.some(kw => domainNameWithoutTld.includes(kw) || normRoot.includes(kw));
      const hasHighRiskTld = HIGH_RISK_TLDS.has(tld);

      if (hasSuspiciousKeyword || hasHighRiskTld) {
        return {
          isImpersonation: true,
          isOfficialDomain: false,
          targetBrand: brandInfo.brand,
          officialDomain: official,
          impersonationType: 'keyword_squat',
          evidence: `Domain "${cleanHost}" bundles brand name "${brandInfo.brand}" with security keywords or high-risk TLD (.${tld}).`,
          scoreImpact: 50
        };
      }
    }
  }

  return {
    isImpersonation: false,
    isOfficialDomain: false,
    scoreImpact: 0
  };
}
