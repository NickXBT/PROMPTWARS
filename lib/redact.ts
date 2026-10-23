/**
 * Privacy-preserving PII redaction engine.
 * Ensures zero sensitive user data (passwords, tokens, emails, phone numbers,
 * credit cards, or private session query parameters) leaves the browser.
 */

// Email regex pattern
const EMAIL_REGEX = /[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g;

// Credit card candidate pattern (13-19 digits, optional dashes/spaces)
const CREDIT_CARD_REGEX = /\b(?:\d[ -]*?){13,19}\b/g;

// US SSN pattern
const SSN_REGEX = /\b\d{3}[- ]\d{2}[- ]\d{4}\b/g;

// Phone number pattern (international and domestic formats)
const PHONE_REGEX = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;

// JWT pattern (3 base64url segments separated by dots)
const JWT_REGEX = /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g;

// Common API keys and Bearer tokens
const TOKEN_KEYWORD_REGEX = /(?:bearer\s+[a-zA-Z0-9_\-.~+/]+=*|token[=:]\s*['"]?[a-zA-Z0-9_\-]{16,}['"]?|api[_-]?key[=:]\s*['"]?[a-zA-Z0-9_\-]{16,}['"]?)/gi;

// Sensitive URL query parameter keys to sanitize
const SENSITIVE_QUERY_PARAMS = new Set([
  'token',
  'access_token',
  'auth',
  'apikey',
  'api_key',
  'session',
  'session_id',
  'password',
  'pwd',
  'pass',
  'secret',
  'code',
  'verification_code',
  'otp',
  'card',
  'cvv',
  'ssn'
]);

/**
 * Checks Luhn algorithm validity on a digit string
 */
export function isValidLuhn(numberString: string): boolean {
  const digits = numberString.replace(/\D/g, '');
  if (digits.length < 10 || digits.length > 19) return false;

  let sum = 0;
  let shouldDouble = false;

  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits.charAt(i), 10);

    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }

    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}

/**
 * Redacts all personally identifiable information (PII) and secret credentials from text.
 */
export function redactPii(text: string): {
  redactedText: string;
  hasRedactedPii: boolean;
  redactedCounts: {
    emails: number;
    creditCards: number;
    ssns: number;
    phones: number;
    tokens: number;
  };
} {
  if (!text || typeof text !== 'string') {
    return {
      redactedText: '',
      hasRedactedPii: false,
      redactedCounts: { emails: 0, creditCards: 0, ssns: 0, phones: 0, tokens: 0 }
    };
  }

  let result = text;
  let emails = 0;
  let creditCards = 0;
  let ssns = 0;
  let phones = 0;
  let tokens = 0;

  // 1. Redact JWTs and Tokens
  result = result.replace(JWT_REGEX, () => {
    tokens++;
    return '[REDACTED_JWT_TOKEN]';
  });

  result = result.replace(TOKEN_KEYWORD_REGEX, () => {
    tokens++;
    return '[REDACTED_AUTH_TOKEN]';
  });

  // 2. Redact Emails
  result = result.replace(EMAIL_REGEX, () => {
    emails++;
    return '[REDACTED_EMAIL]';
  });

  // 3. Redact SSNs
  result = result.replace(SSN_REGEX, () => {
    ssns++;
    return '[REDACTED_SSN]';
  });

  // 4. Redact Credit Cards (confirm with Luhn algorithm)
  result = result.replace(CREDIT_CARD_REGEX, (match) => {
    const rawDigits = match.replace(/\D/g, '');
    if (isValidLuhn(rawDigits)) {
      creditCards++;
      return '[REDACTED_CREDIT_CARD]';
    }
    return match;
  });

  // 5. Redact Phone Numbers
  result = result.replace(PHONE_REGEX, (match) => {
    // Avoid redacting simple dates like 2026-10-23
    if (/^\d{4}-\d{2}-\d{2}$/.test(match.trim())) return match;
    phones++;
    return '[REDACTED_PHONE]';
  });

  const hasRedactedPii = emails > 0 || creditCards > 0 || ssns > 0 || phones > 0 || tokens > 0;

  return {
    redactedText: result,
    hasRedactedPii,
    redactedCounts: { emails, creditCards, ssns, phones, tokens }
  };
}

/**
 * Sanitizes URLs before any external transmission by stripping sensitive query parameters
 * and fragment identifiers.
 */
export function sanitizeUrlForExternalUse(urlString: string): string {
  try {
    const parsed = new URL(urlString);
    
    // Strip fragment hash completely
    parsed.hash = '';

    // Strip sensitive parameters
    const keysToDelete: string[] = [];
    for (const [key] of parsed.searchParams.entries()) {
      if (SENSITIVE_QUERY_PARAMS.has(key.toLowerCase())) {
        keysToDelete.push(key);
      }
    }

    for (const key of keysToDelete) {
      parsed.searchParams.set(key, '[REDACTED]');
    }

    return parsed.toString();
  } catch {
    return '[INVALID_URL]';
  }
}
