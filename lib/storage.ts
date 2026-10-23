/**
 * Storage abstraction for extension settings, cached verdicts, and scan history.
 * Supports chrome.storage.local with browser/node memory fallback for unit testing.
 */

import { AnalysisResult, DEFAULT_SETTINGS, ExtensionSettings } from './types.js';

const SETTINGS_KEY = 'phishing_shield_settings';
const HISTORY_KEY = 'phishing_shield_history';
const MAX_HISTORY_ITEMS = 50;

// In-memory fallback when chrome.storage is not available
const memoryStorage = new Map<string, string>();

function isChromeStorageAvailable(): boolean {
  return typeof chrome !== 'undefined' && Boolean(chrome.storage?.local);
}

/**
 * Loads extension configuration settings
 */
export async function loadSettings(): Promise<ExtensionSettings> {
  if (isChromeStorageAvailable()) {
    return new Promise((resolve) => {
      chrome.storage.local.get([SETTINGS_KEY], (items) => {
        if (items && items[SETTINGS_KEY]) {
          resolve({ ...DEFAULT_SETTINGS, ...items[SETTINGS_KEY] });
        } else {
          resolve(DEFAULT_SETTINGS);
        }
      });
    });
  }

  const raw = memoryStorage.get(SETTINGS_KEY);
  if (raw) {
    try {
      return { ...DEFAULT_SETTINGS, ...JSON.parse(raw) };
    } catch {
      return DEFAULT_SETTINGS;
    }
  }
  return DEFAULT_SETTINGS;
}

/**
 * Saves extension configuration settings
 */
export async function saveSettings(settings: Partial<ExtensionSettings>): Promise<void> {
  const current = await loadSettings();
  const updated = { ...current, ...settings };

  if (isChromeStorageAvailable()) {
    return new Promise((resolve) => {
      chrome.storage.local.set({ [SETTINGS_KEY]: updated }, () => resolve());
    });
  }

  memoryStorage.set(SETTINGS_KEY, JSON.stringify(updated));
}

/**
 * Appends a scan result to local history
 */
export async function saveScanResult(result: AnalysisResult): Promise<void> {
  const history = await getScanHistory();
  // Filter out duplicates of same URL in recent records
  const filtered = history.filter(item => item.url !== result.url);
  const updated = [result, ...filtered].slice(0, MAX_HISTORY_ITEMS);

  if (isChromeStorageAvailable()) {
    return new Promise((resolve) => {
      chrome.storage.local.set({ [HISTORY_KEY]: updated }, () => resolve());
    });
  }

  memoryStorage.set(HISTORY_KEY, JSON.stringify(updated));
}

/**
 * Retrieves past scan history
 */
export async function getScanHistory(): Promise<AnalysisResult[]> {
  if (isChromeStorageAvailable()) {
    return new Promise((resolve) => {
      chrome.storage.local.get([HISTORY_KEY], (items) => {
        if (items && Array.isArray(items[HISTORY_KEY])) {
          resolve(items[HISTORY_KEY]);
        } else {
          resolve([]);
        }
      });
    });
  }

  const raw = memoryStorage.get(HISTORY_KEY);
  if (raw) {
    try {
      return JSON.parse(raw);
    } catch {
      return [];
    }
  }
  return [];
}

/**
 * Clears local history and statistics
 */
export async function clearScanHistory(): Promise<void> {
  if (isChromeStorageAvailable()) {
    return new Promise((resolve) => {
      chrome.storage.local.remove([HISTORY_KEY], () => resolve());
    });
  }
  memoryStorage.delete(HISTORY_KEY);
}
