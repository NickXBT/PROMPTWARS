import { describe, it, expect } from 'vitest';
import {
  checkLinkTextMismatch,
  inspectUrl,
  safeParseUrl,
  isIpAddressHostname
} from '../lib/url-checks.js';

describe('URL Security Inspection', () => {
  it('detects link text mismatch when visible text claims different domain', () => {
    const mismatch = checkLinkTextMismatch(
      'https://www.paypal.com/signin',
      'https://attacker-stealer.xyz/harvest'
    );
    expect(mismatch.isMismatch).toBe(true);
    expect(mismatch.textDomain).toBe('paypal.com');
    expect(mismatch.actualDomain).toBe('attacker-stealer.xyz');
  });

  it('allows benign link text like "Click here" or "Read more" without false positive', () => {
    const benign = checkLinkTextMismatch('Click here to read more', 'https://example.com/blog');
    expect(benign.isMismatch).toBe(false);
  });

  it('detects known URL shorteners', () => {
    const res = inspectUrl('https://bit.ly/claim-prize');
    expect(res.isShortener).toBe(true);
    expect(res.reasons.some(r => r.includes('shortening service'))).toBe(true);
  });

  it('detects open redirect parameters in URLs', () => {
    const res = inspectUrl('https://example.com/login?redirect=https://evil-site.com/steal');
    expect(res.hasOpenRedirect).toBe(true);
    expect(res.redirectTarget).toBe('https://evil-site.com/steal');
  });

  it('identifies raw IP address hostnames', () => {
    expect(isIpAddressHostname('192.168.1.1')).toBe(true);
    expect(isIpAddressHostname('45.33.32.156')).toBe(true);
    expect(isIpAddressHostname('example.com')).toBe(false);

    const res = inspectUrl('http://192.168.1.1/admin');
    expect(res.isIpAddress).toBe(true);
  });

  it('handles malformed URLs safely without crashing', () => {
    const parsed = safeParseUrl('javascript:alert(1)');
    expect(parsed).toBeNull();
  });
});
