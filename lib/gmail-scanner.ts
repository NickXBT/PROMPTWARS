/**
 * Gmail Web DOM and Read-Only Email Content Scanner.
 * Operates strictly on user-selected email context in Gmail.
 * Never stores email contents persistently.
 */

import { EmailMetadata, PageAnalysisContext } from './types.js';
import { getRegistrableDomain } from './domain-similarity.js';

export interface GmailScanResult {
  isEmailView: boolean;
  metadata?: EmailMetadata;
  extractedContext?: PageAnalysisContext;
  hasReplyToMismatch?: boolean;
}

/**
 * Parses email domain from an address string (e.g. "Security Team <security@company.com>")
 */
export function extractDomainFromEmail(emailString: string): string | undefined {
  const match = emailString.match(/<([^>]+)>/) || emailString.match(/([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)/);
  if (!match) return undefined;

  const addr = match[1];
  const domain = addr.split('@')[1];
  return domain ? getRegistrableDomain(domain.toLowerCase()).registrableDomain : undefined;
}

/**
 * Inspects open Gmail message container from the DOM
 */
export function scanActiveGmailMessage(): GmailScanResult {
  if (typeof document === 'undefined') {
    return { isEmailView: false };
  }

  // Gmail DOM selectors for open email thread
  const emailBodyEl = document.querySelector('.ii.gt, .a3s.aiL');
  const senderEl = document.querySelector('span.gD');
  const subjectEl = document.querySelector('h2.hP');

  if (!emailBodyEl) {
    return { isEmailView: false };
  }

  const rawSender = senderEl ? (senderEl.getAttribute('email') || senderEl.textContent || '') : '';
  const subject = subjectEl ? (subjectEl.textContent || '') : '';
  const bodyText = (emailBodyEl.textContent || '').trim();

  const senderDomain = extractDomainFromEmail(rawSender);

  // Check for reply-to headers if rendered in message details
  let replyToDomain: string | undefined;
  const replyToEl = document.querySelector('.ajv .gD');
  if (replyToEl) {
    const rawReplyTo = replyToEl.getAttribute('email') || replyToEl.textContent || '';
    replyToDomain = extractDomainFromEmail(rawReplyTo);
  }

  const senderReplyToMismatch = Boolean(
    senderDomain && replyToDomain && senderDomain !== replyToDomain
  );

  const metadata: EmailMetadata = {
    sender: rawSender,
    senderDomain,
    replyToDomain,
    subject,
    senderReplyToMismatch
  };

  return {
    isEmailView: true,
    metadata,
    hasReplyToMismatch: senderReplyToMismatch
  };
}
