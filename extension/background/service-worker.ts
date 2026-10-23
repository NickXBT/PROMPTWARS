/**
 * Manifest V3 Background Service Worker for Phishing Shield AI.
 * Handles lifecycle, message routing, pipeline execution, and badge indicators.
 */

import { AnalysisResult, PageAnalysisContext } from '../../lib/types.js';
import { loadSettings } from '../../lib/storage.js';
import { runDetectionPipeline } from '../../lib/pipeline.js';
import { validatePageAnalysisContext } from '../../lib/schemas.js';

// Cache latest scan results per tab
const tabResults = new Map<number, AnalysisResult>();

/**
 * Updates extension action badge on the browser toolbar
 */
function updateBadge(tabId: number, result: AnalysisResult) {
  if (typeof chrome === 'undefined' || !chrome.action) return;

  const scoreText = String(result.score);
  chrome.action.setBadgeText({ tabId, text: scoreText });

  if (result.verdict === 'Dangerous') {
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#D93025' }); // Red
  } else if (result.verdict === 'Suspicious') {
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#F29900' }); // Amber
  } else {
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#1E8E3E' }); // Green
  }
}

/**
 * Executes security scan for a given page context
 */
async function handlePageAnalysis(
  context: PageAnalysisContext,
  tabId?: number
): Promise<AnalysisResult> {
  const settings = await loadSettings();
  const result = await runDetectionPipeline(context, settings);

  if (typeof tabId === 'number') {
    tabResults.set(tabId, result);
    updateBadge(tabId, result);

    // Send result back to content script for banner display
    chrome.tabs.sendMessage(tabId, {
      type: 'ANALYZE_PAGE_RESPONSE',
      payload: result
    }).catch(() => {
      // Content script may not be ready or page navigated
    });
  }

  return result;
}

// Listen for messages from content scripts and UI panels
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== 'object') return false;

  const senderTabId = sender.tab?.id;

  switch (message.type) {
    case 'ANALYZE_PAGE_REQUEST': {
      if (validatePageAnalysisContext(message.payload)) {
        handlePageAnalysis(message.payload, senderTabId).then((result) => {
          sendResponse({ success: true, result });
        }).catch((err) => {
          sendResponse({ success: false, error: String(err) });
        });
        return true; // Keep message channel open for async response
      }
      sendResponse({ success: false, error: 'Invalid analysis payload' });
      return false;
    }

    case 'GET_CURRENT_RESULT_REQUEST': {
      const targetTabId = message.tabId || senderTabId;
      if (typeof targetTabId === 'number' && tabResults.has(targetTabId)) {
        sendResponse({ success: true, result: tabResults.get(targetTabId) });
      } else {
        sendResponse({ success: false, result: null });
      }
      return false;
    }

    case 'REPORT_PHISHING_REQUEST': {
      // Handle community phishing report
      const reportedUrl = message.payload?.url;
      // Store report locally or forward if enabled
      sendResponse({
        success: true,
        message: `Report received for ${reportedUrl}. Thank you for helping protect the community.`
      });
      return false;
    }

    default:
      return false;
  }
});

// Clean up memory cache when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId);
});
