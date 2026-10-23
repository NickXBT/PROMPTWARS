# Chrome Web Store Publishing Guide — Phishing Shield AI

Follow this checklist to publish **Phishing Shield AI** to the official Chrome Web Store so that users experience the real 1-click **Add to Chrome** installation flow (like Buyhatke).

---

## Prerequisites
1. A Google Account registered as a Chrome Web Store Developer at [https://chrome.google.com/webstore/devconsole](https://chrome.google.com/webstore/devconsole) (Google charges a one-time \$5 registration fee).
2. The packaged extension ZIP file:
   - **Path:** `dist/phishing-shield-ai-v1.0.0.zip` (also in `store/phishing-shield-ai-v1.0.0.zip`).
   - Size: ~27 KB with `manifest.json` at the root.

---

## Step 1: Upload the Extension Package
1. Log in to the [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole).
2. Click the **+ New Item** button (top right).
3. Drag and drop `dist/phishing-shield-ai-v1.0.0.zip` or click **Browse files**.
4. The dashboard will validate `manifest.json`, icons, and files. Once complete, you will see your new item draft.

---

## Step 2: Fill in the Store Listing Tab
1. **Description:** Copy and paste the entire text from [`store/description.txt`](../store/description.txt).
2. **Category:** Select **Productivity** (or **Tools**).
3. **Language:** Select **English**.
4. **Icons:**
   - Store Icon: Upload `store/icon-128.png` (128x128 px).
5. **Screenshots:**
   - Take 1–3 screenshots of the popup or landing page (1280x800 px or 640x400 px) and upload them under the Screenshots section.

---

## Step 3: Complete the Privacy Practices Tab
Google requires explicit disclosures for extensions using `host_permissions` or `activeTab`:
1. **Single Purpose:** Enter:
   > *"Detect phishing websites, look-alike domains, and social engineering attacks to protect users before credentials are entered."*
2. **Permission Justifications:**
   - `activeTab`: *"Inspects active page hostname, form inputs, and links for phishing cues when the user navigates or opens the popup."*
   - `storage`: *"Stores user preferences and local scan history in local browser storage."*
   - `scripting`: *"Injects the high-risk warning banner into the active tab when a dangerous website is identified."*
   - `sidePanel`: *"Displays the detailed forensic telemetry inspection panel alongside the active webpage."*
   - `host_permissions (<all_urls>)`: *"Required to analyze URLs across arbitrary websites to detect zero-day phishing attacks."*
3. **Data Usage:**
   - Check: *"I do not sell or transfer user data to third parties."*
   - Check: *"I do not use or transfer user data for purposes unrelated to the item's core functionality."*
   - Check: *"I do not use or transfer user data to determine creditworthiness or for lending purposes."*
4. **Privacy Policy Link:**
   Provide the public link to [`store/privacy-policy.md`](../store/privacy-policy.md).

---

## Step 4: Submit for Review
1. Click the **Submit for Review** button in the top-right corner.
2. Review usually takes 24–48 hours for Manifest V3 extensions with standard permissions.

---

## Step 5: Activate 1-Click "Add to Chrome" on the Live Website
Once Google approves your item, the Chrome Web Store generates an Item ID (e.g. `abcdefghijklmnopqrstuvwxyz012345`):
1. Copy the Extension ID from the Developer Dashboard.
2. Open `src/config.ts` in this project.
3. Replace the placeholder:
   ```ts
   export const CHROME_EXTENSION_STORE_ID = 'YOUR_APPROVED_STORE_ID_HERE';
   ```
4. Rebuild the website: `npm run build`.
5. Now, every **Add to Chrome** button across the website will directly launch the live Chrome Web Store listing page (`https://chromewebstore.google.com/detail/phishing-shield-ai/<ID>`) enabling the exact Buyhatke 1-click installation experience!
