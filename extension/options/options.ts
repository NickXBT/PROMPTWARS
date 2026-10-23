/**
 * Options and Settings Page Logic.
 */

import { loadSettings, saveSettings } from '../../lib/storage.js';
import { ExtensionSettings } from '../../lib/types.js';

async function initOptions() {
  const settings = await loadSettings();

  const onDeviceOnly = document.getElementById('onDeviceOnlyMode') as HTMLInputElement;
  const enableNano = document.getElementById('enableGeminiNano') as HTMLInputElement;
  const enableWebRisk = document.getElementById('enableWebRisk') as HTMLInputElement;
  const webRiskKey = document.getElementById('webRiskApiKey') as HTMLInputElement;
  const proxyUrl = document.getElementById('backendProxyUrl') as HTMLInputElement;
  const enableCloud = document.getElementById('enableCloudGemini') as HTMLInputElement;
  const geminiKey = document.getElementById('geminiApiKey') as HTMLInputElement;
  const enableGmail = document.getElementById('enableGmailScanning') as HTMLInputElement;
  const enableCommunity = document.getElementById('enableCommunityReporting') as HTMLInputElement;

  if (onDeviceOnly) onDeviceOnly.checked = settings.onDeviceOnlyMode;
  if (enableNano) enableNano.checked = settings.enableGeminiNano;
  if (enableWebRisk) enableWebRisk.checked = settings.enableWebRisk;
  if (webRiskKey) webRiskKey.value = settings.webRiskApiKey || '';
  if (proxyUrl) proxyUrl.value = settings.backendProxyUrl || '';
  if (enableCloud) enableCloud.checked = settings.enableCloudGemini;
  if (geminiKey) geminiKey.value = settings.geminiApiKey || '';
  if (enableGmail) enableGmail.checked = settings.enableGmailScanning;
  if (enableCommunity) enableCommunity.checked = settings.enableCommunityReporting;

  const form = document.getElementById('settingsForm');
  const statusEl = document.getElementById('saveStatus');

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();

      const updated: Partial<ExtensionSettings> = {
        onDeviceOnlyMode: onDeviceOnly.checked,
        enableGeminiNano: enableNano.checked,
        enableWebRisk: enableWebRisk.checked,
        webRiskApiKey: webRiskKey.value.trim(),
        backendProxyUrl: proxyUrl.value.trim(),
        enableCloudGemini: enableCloud.checked,
        geminiApiKey: geminiKey.value.trim(),
        enableGmailScanning: enableGmail.checked,
        enableCommunityReporting: enableCommunity.checked
      };

      await saveSettings(updated);

      if (statusEl) {
        statusEl.textContent = 'Settings saved successfully!';
        setTimeout(() => {
          statusEl.textContent = '';
        }, 3000);
      }
    });
  }
}

document.addEventListener('DOMContentLoaded', initOptions);
