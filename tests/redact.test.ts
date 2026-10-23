import { describe, it, expect } from 'vitest';
import { redactPii, sanitizeUrlForExternalUse, isValidLuhn } from '../lib/redact.js';

describe('Privacy & PII Redaction Engine', () => {
  it('validates credit card numbers with Luhn algorithm', () => {
    // Standard test Luhn number
    expect(isValidLuhn('49927398716')).toBe(true);
    expect(isValidLuhn('49927398717')).toBe(false);
  });

  it('redacts email addresses, phone numbers, and SSNs', () => {
    const raw = 'Contact user alex.doe@example.com or call 555-234-5678. SSN: 123-45-6789.';
    const res = redactPii(raw);

    expect(res.hasRedactedPii).toBe(true);
    expect(res.redactedText).toContain('[REDACTED_EMAIL]');
    expect(res.redactedText).toContain('[REDACTED_PHONE]');
    expect(res.redactedText).toContain('[REDACTED_SSN]');
    expect(res.redactedText).not.toContain('alex.doe@example.com');
  });

  it('redacts authentication tokens and JWTs', () => {
    const jwt = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature';
    const res = redactPii(jwt);
    expect(res.hasRedactedPii).toBe(true);
    expect(res.redactedText).toContain('[REDACTED_JWT_TOKEN]');
  });

  it('sanitizes sensitive query parameters from URLs before transmission', () => {
    const rawUrl = 'https://bank.example.com/verify?token=SECRET_TOKEN_123&session_id=ABC99&user=john';
    const sanitized = sanitizeUrlForExternalUse(rawUrl);

    expect(sanitized).not.toContain('SECRET_TOKEN_123');
    expect(sanitized).not.toContain('ABC99');
    expect(sanitized).toContain('token=%5BREDACTED%5D');
    expect(sanitized).toContain('session_id=%5BREDACTED%5D');
  });
});
