import { normalizeBaseUrl } from './capture.js';

const $ = (id) => document.getElementById(id);

function render(status) {
  const active = Boolean(status?.active);
  $('status').textContent = active ? `Recording tab ${status.tabId} (${status.captureId})` : 'Not recording.';
  $('stats').textContent = status && (status.captured || status.uploaded || status.rejected)
    ? `${status.captured || 0} captured · ${status.uploaded || 0} stored · ${status.rejected || 0} out of scope`
    : '';
  $('error').textContent = status?.lastError || '';
  $('toggle').textContent = active ? 'Stop capture' : 'Start capture on this tab';
  $('toggle').classList.toggle('recording', active);
}

async function send(message) {
  const res = await chrome.runtime.sendMessage(message);
  if (!res?.ok) throw new Error(res?.error || 'Extension error');
  return res.status;
}

async function init() {
  const { settings } = await chrome.storage.local.get('settings');
  $('baseUrl').value = settings?.baseUrl || '';
  $('apiKey').value = settings?.apiKey || '';
  $('allowlist').value = (settings?.allowlist || []).join('\n');
  if (!settings?.baseUrl || !settings?.apiKey) $('settings-section').open = true;
  render(await send({ type: 'status' }));
}

$('save').addEventListener('click', async () => {
  try {
    const baseUrl = normalizeBaseUrl($('baseUrl').value);
    const granted = await chrome.permissions.request({ origins: [`${baseUrl}/*`] });
    if (!granted) throw new Error('Permission to reach the platform was not granted.');
    const allowlist = $('allowlist').value.split('\n').map((s) => s.trim()).filter(Boolean);
    await chrome.storage.local.set({ settings: { baseUrl, apiKey: $('apiKey').value.trim(), allowlist } });
    $('saved').textContent = 'Saved.';
  } catch (err) {
    $('saved').textContent = err.message;
  }
});

$('toggle').addEventListener('click', async () => {
  try {
    const current = await send({ type: 'status' });
    if (current.active) {
      render(await send({ type: 'stop' }));
    } else {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      render(await send({ type: 'start', tabId: tab.id }));
    }
  } catch (err) {
    $('error').textContent = err.message;
  }
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'session' && changes.status) render(changes.status.newValue);
});

init().catch((err) => { $('error').textContent = err.message; });
