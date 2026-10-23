# Phishing Shield AI — 2-Minute Live Demo Script

**Tagline:** *Detect the deception. Understand the risk. Browse with confidence.*

---

## Preparation (30 seconds before presentation)

1. Ensure the demo test pages are running:
   ```bash
   npm run serve:test-pages
   ```
   *(Running at `http://localhost:3000`)*

2. In Google Chrome:
   - Navigate to `chrome://extensions/`
   - Turn on **Developer mode** (top right)
   - Click **Load unpacked** and select the `dist/` directory inside `phishing-shield/`
   - Pin **Phishing Shield AI** to the Chrome toolbar.

---

## Live Demo Walkthrough (120 seconds)

### Part 1: The Hook — Brand Impersonation & Credential Harvesting (0:00 - 0:35)

1. **Action:** Navigate to `http://localhost:3000/phishing-bank.html`.
2. **Observe:** An immediate red warning banner slides down from the top:
   > *"Phishing Shield AI Alert: High-Risk Website (90/100)"*
3. **Point out:**
   - Notice the footer link: on screen it says `https://www.chase.com/privacy-security`, but hovering reveals it points to `http://secure-chase-update.xyz/login`!
   - Phishing Shield automatically outlines the deceptive link with a dashed red border and adds a visible `[Deceptive Link]` indicator.
4. **Click the Extension Icon:**
   - **Score:** `90/100` — **Verdict:** `Dangerous` (Red Dial).
   - **Top Evidence:**
     1. `DOMAIN IMPERSONATION` — Brand keyword spoofing.
     2. `LINK TEXT MISMATCH` — Deceptive destination masquerading as official domain.
     3. `INSECURE FORM HTTP` — Transmits credentials over unencrypted HTTP.
   - **Explain It Simply:** *"The address is pretending to be a legitimate brand using a deceptive look-alike domain. Entering passwords here sends them directly to cybercriminals."*
   - **Action:** *"Close this tab immediately. Navigate using the official verified app."*

---

### Part 2: Social Engineering & Urgency Scam (0:35 - 1:05)

1. **Action:** Navigate to `http://localhost:3000/phishing-delivery.html`.
2. **Explain:**
   - Attackers use delivery package pretexts demanding small fees ($2.95) under artificial 24-hour urgency.
3. **Click the Extension Icon:**
   - **Score:** `75/100` — **Verdict:** `Dangerous`.
   - **Evidence:** `PAYMENT CARD HARVESTING` + `SOCIAL ENGINEERING URGENCY` + `OBFUSCATED SHORTENER LINK (bit.ly)`.
   - Highlight the **Detection Method Pipeline**: Heuristics executed locally in 12ms.

---

### Part 3: Two-Factor Authentication Interception (1:05 - 1:30)

1. **Action:** Navigate to `http://localhost:3000/phishing-account.html`.
2. **Explain:**
   - This simulated page targets Microsoft 365 accounts, requesting both password and a live 6-digit OTP code to bypass 2FA in real-time.
3. **Click the Extension Icon:**
   - **Score:** `85/100` — **Verdict:** `Dangerous`.
   - **Evidence:** `OTP INTERCEPTION` flagged with critical severity.

---

### Part 4: The Legitimate Control — Zero False Positives (1:30 - 1:50)

1. **Action:** Navigate to `http://localhost:3000/legitimate-example.html`.
2. **Observe:** No intrusive warning banners appear. Page functions cleanly.
3. **Click the Extension Icon:**
   - **Score:** `0/100` — **Verdict:** `Safe-looking` (Green Dial).
   - **Honest Security Transparency:**
     > *"This page does not trigger known phishing or impersonation indicators. However, always verify the web address before submitting sensitive passwords or financial details."*
   - Note: We **never** claim a page is "guaranteed safe." A lack of threats does not establish absolute safety.

---

### Part 5: Forensic Feed & Privacy Commitment (1:50 - 2:00)

1. **Action:** Open Chrome Side Panel (`chrome.sidePanel`).
2. **Observe:** The complete real-time forensic feed with timestamps, latency metrics (averaging 13ms), and evidence breakdown.
3. **Close:**
   - *"Phishing Shield AI combines on-device Gemini Nano with deterministic heuristics to deliver sub-15ms threat detection—keeping your private credentials safe without leaking your browsing activity."*

---

## Quick Reference Commands

```bash
# Build the Chrome extension
npm run build

# Run comprehensive test suite (14 scenarios)
npm test

# Launch test demo server
npm run serve:test-pages
```
