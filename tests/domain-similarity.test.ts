import { describe, it, expect } from 'vitest';
import {
  checkDomainImpersonation,
  normalizeHomoglyphs,
  calculateLevenshtein,
  getRegistrableDomain
} from '../lib/domain-similarity.js';

describe('Domain Similarity & Impersonation Engine', () => {
  it('correctly calculates Levenshtein distance', () => {
    expect(calculateLevenshtein('paypal', 'paypa1')).toBe(1);
    expect(calculateLevenshtein('google', 'g00gle')).toBe(2);
    expect(calculateLevenshtein('chase', 'chase')).toBe(0);
  });

  it('correctly extracts registrable domains including multi-level TLDs', () => {
    expect(getRegistrableDomain('login.paypal.com').registrableDomain).toBe('paypal.com');
    expect(getRegistrableDomain('secure.bank.co.uk').registrableDomain).toBe('bank.co.uk');
    expect(getRegistrableDomain('paypal.com.attacker.xyz').registrableDomain).toBe('attacker.xyz');
    expect(getRegistrableDomain('paypal.com.attacker.xyz').subdomains).toBe('paypal.com');
  });

  it('detects Unicode homoglyphs and Cyrillic character spoofing', () => {
    // Cyrillic Small Letter A (\u0430)
    const spoofed = 'p\u0430ypal';
    const norm = normalizeHomoglyphs(spoofed);
    expect(norm.hadHomoglyphs).toBe(true);
    expect(norm.normalized).toBe('paypal');
  });

  it('flags typosquatting look-alike domain: paypa1.com', () => {
    const result = checkDomainImpersonation('paypa1.com');
    expect(result.isImpersonation).toBe(true);
    expect(result.targetBrand).toBe('PayPal');
    expect(result.scoreImpact).toBeGreaterThanOrEqual(40);
  });

  it('flags subdomain masquerading: paypal.com.account-update.xyz', () => {
    const result = checkDomainImpersonation('paypal.com.account-update.xyz');
    expect(result.isImpersonation).toBe(true);
    expect(result.impersonationType).toBe('subdomain_spoof');
    expect(result.targetBrand).toBe('PayPal');
  });

  it('flags brand keyword squatting on suspicious TLD: chase-security-login.xyz', () => {
    const result = checkDomainImpersonation('chase-security-login.xyz');
    expect(result.isImpersonation).toBe(true);
    expect(result.targetBrand).toBe('Chase Bank');
  });

  it('recognizes official legitimate brand domains without flagging', () => {
    const paypal = checkDomainImpersonation('www.paypal.com');
    expect(paypal.isImpersonation).toBe(false);
    expect(paypal.isOfficialDomain).toBe(true);

    const google = checkDomainImpersonation('accounts.google.com');
    expect(google.isImpersonation).toBe(false);
    expect(google.isOfficialDomain).toBe(true);
  });
});
