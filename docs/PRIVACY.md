# Phishing Shield AI — Privacy & Security Architecture

**Tagline:** *Detect the deception. Understand the risk. Browse with confidence.*

---

## 1. Core Privacy Philosophy

Phishing Shield AI was designed from the ground up under a **privacy-first, defense-in-depth architecture**. Traditional security extensions frequently transmit full browsing history, unredacted URLs, and page content to centralized cloud endpoints. 

Phishing Shield AI reverses this paradigm:
1. **Local-First Execution:** 95%+ of scans execute purely inside the browser using deterministic local heuristics and Chrome Built-in AI (Gemini Nano).
2. **Zero Credential Transmission:** Passwords, OTPs, session tokens, and credit card numbers are strictly prevented from leaving the browser.
3. **On-Device-Only Mode:** Users can enforce strict zero-network mode, guaranteeing no external lookups occur.

---

## 2. Privacy Threat Model

### Threats Addressed
- **Browsing History Leaks:** Extensions tracking every website a user visits.
- **Session Token Exfiltration:** URLs containing access tokens (`?token=...`, `?auth=...`, `?session=...`) being transmitted to third-party APIs.
- **Credential Sniffing:** Passwords or 2FA codes typed into forms accidentally sent to cloud LLMs.
- **Prompt Injection & Overrides:** Malicious webpages injecting prompt instructions into AI models attempting to downgrade threats.

### Mitigations Implemented
- **Local PII Redaction Engine (`lib/redact.ts`):** Automatically redacts emails, telephone numbers, credit cards (validated via Luhn algorithm), SSNs, and JWT tokens before any cloud transmission.
- **URL Parameter Sanitization:** Sensitive parameters (`token`, `api_key`, `session_id`, `password`, `code`, `otp`) are stripped before reputation checks.
- **Threat Override Rule:** A confirmed threat from Web Risk or domain impersonation heuristics can **never** be downgraded by reassuring AI responses.
- **Strict Content Security Policy (CSP):** Manifest V3 CSP prevents remote script execution (`script-src 'self'`).
- **DOM Sandboxing:** Warning banners are rendered inside Shadow DOM using `createElement` and `textContent`. Zero `innerHTML` on untrusted strings.

---

## 3. Data Flow Matrix

| Detection Stage | Data Processed | Transmission Destination | Retention Period | Privacy Mode Fallback |
| :--- | :--- | :--- | :--- | :--- |
| **Stage A: Heuristics** | Hostname, DOM links, input types, text keywords | **Local browser memory only** | Deleted when tab closes | Always active |
| **Stage B: Web Risk** | Sanitized hostname / URL (tokens stripped) | Google Web Risk API / Backend proxy | 30-min local TTL cache | Skipped in On-Device Mode |
| **Stage C: Gemini Nano** | Pre-redacted text excerpt (max 800 chars) | **On-device AI Prompt API** | Not retained | Graceful heuristic fallback |
| **Stage D: Cloud Gemini** | Pre-redacted text excerpt (ambiguous cases 30-65 only) | Google Gemini API (1.5 Flash) | Ephemeral inference | Skipped in On-Device Mode |
| **Community Reporting** | Domain name & timestamp | Firestore community database | Aggregated threat count | User-opt-in only |

---

## 4. Permissions Justification

| Permission | Purpose |
| :--- | :--- |
| `activeTab` | Inspects DOM of the active website when user opens extension or navigates. |
| `storage` | Stores user configuration settings and local scan history in `chrome.storage.local`. |
| `scripting` | Coordinates content script injection for real-time warning banners. |
| `sidePanel` | Displays the deep forensic telemetry panel alongside the active webpage. |
| `host_permissions: ["<all_urls>"]` | Required to detect phishing across arbitrary websites across the web. |

---

## 5. Known Limitations

1. **New Zeroday Lookalikes:** Extremely obscure typosquatting variants that do not match brand distance thresholds or known high-risk TLDs may require community reports or cloud threat intelligence.
2. **JavaScript-Rendered SPAs:** Content scripts wait for `document_idle`. Heavily delayed Single Page Apps may require clicking "Analyze Again" once dynamic content finishes rendering.
3. **No Guarantee of Absolute Safety:** A verdict of "Safe-looking" indicates an absence of detected threats, but cannot guarantee a page is free of unknown vulnerabilities.
