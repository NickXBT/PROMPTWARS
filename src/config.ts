/**
 * Global Configuration for Phishing Shield AI
 * Centralized source of truth for Chrome Web Store deployment.
 */

// Once approved on the Chrome Web Store Developer Dashboard,
// populate this ID to immediately activate direct store installations:
export const CHROME_EXTENSION_STORE_ID = ''; 

// Computed Chrome Web Store public URL
export const CHROME_STORE_URL = CHROME_EXTENSION_STORE_ID
  ? `https://chromewebstore.google.com/detail/phishing-shield-ai/${CHROME_EXTENSION_STORE_ID}`
  : '';

export const IS_STORE_PUBLISHED = Boolean(CHROME_STORE_URL);

export const EXTENSION_VERSION = '1.0.0';
export const EXTENSION_ZIP_FILENAME = `phishing-shield-ai-v${EXTENSION_VERSION}.zip`;
