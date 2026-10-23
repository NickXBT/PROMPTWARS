# Privacy Policy for Phishing Shield AI

**Effective Date:** October 23, 2026  
**Developer:** Phishing Shield AI Team  
**Extension:** Phishing Shield AI (Manifest V3)

---

## 1. Overview
Phishing Shield AI ("we", "our", or "the extension") provides browser security to protect users against phishing and deceptive websites. We believe security should protect privacy, not compromise it.

## 2. Information We Do NOT Collect
- We **never** collect, transmit, or store user passwords, credit card numbers, or two-factor authentication (OTP) codes.
- We **never** track or log your browsing history.
- We **never** sell, rent, or monetize personal data or browsing activity.
- We **never** execute remote scripts.

## 3. Data Processed Locally on Your Device
- **Page Context:** When an active tab is scanned, the extension content script extracts the hostname, form actions, input field types, and anchor destinations locally.
- **Deterministic Heuristics:** Analysis of typosquatting, homoglyphs, and urgency keywords is performed entirely within your browser in under 15ms.
- **Chrome Built-in AI:** When available, Chrome's on-device Prompt API (Gemini Nano) processes minimal text excerpts locally without transmitting data to cloud servers.

## 4. Optional External Communication
The following communications occur only when enabled by user configuration:
- **Google Web Risk / Threat Intelligence:** If enabled, sanitized URLs (with all query tokens and parameters stripped) are queried against threat databases to identify known malware/phishing. Responses are cached locally for 30 minutes.
- **Cloud Gemini Analysis:** If enabled and a page score is strictly within the ambiguous range (30–65), a minimal excerpt is sent for classification. All email addresses, phone numbers, SSNs, credit cards, and tokens are pre-redacted locally before transmission.
- **On-Device-Only Mode:** Users can activate "On-Device-Only Mode" in Extension Settings. When enabled, all external network requests are strictly bypassed.

## 5. Local Storage
The extension uses `chrome.storage.local` exclusively to store user configuration settings and recent scan scores for your personal review. This data remains on your computer and is never synced to external servers.

## 6. Contact & Open Source
For inquiries or to review the open-source code under the Apache 2.0 License, visit the project repository: https://github.com/NickXBT/NickXBT.
