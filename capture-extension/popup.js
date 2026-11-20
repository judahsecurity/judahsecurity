const $ = (id) => document.getElementById(id);

function tokenIdentity(token) {
  try {
    const body = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(body + "===".slice((body.length + 3) % 4))).identity || "";
  } catch { return ""; }
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function refresh() {
  const tab = await activeTab();
  const status = await chrome.runtime.sendMessage({ type: "status", tabId: tab.id });
  if (status.active) {
    $("toggle").textContent = "Stop capture";
    $("status").textContent =
      `Capturing as "${status.identity}"\nSent ${status.sent} · queued ${status.queued} · failed ${status.failed}` +
      (status.lastError ? `\n${status.lastError}` : "");
  } else {
    $("toggle").textContent = "Start capture on this tab";
    $("status").textContent = status.lastStopReason ? `Stopped: ${status.lastStopReason}` : "Not capturing.";
  }
}

async function init() {
  const saved = await chrome.storage.local.get(["server", "hosts"]);
  $("server").value = saved.server || "";
  $("hosts").value = saved.hosts || "";
  await refresh();
  setInterval(refresh, 1500);
}

$("toggle").addEventListener("click", async () => {
  const tab = await activeTab();
  const status = await chrome.runtime.sendMessage({ type: "status", tabId: tab.id });
  if (status.active) {
    await chrome.runtime.sendMessage({ type: "stop", tabId: tab.id });
    return refresh();
  }
  const server = $("server").value.trim();
  const token = $("token").value.trim();
  const hosts = $("hosts").value.split(",").map((h) => h.trim().toLowerCase()).filter(Boolean);
  if (!/^https:\/\/|^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(server + "/")) {
    $("status").textContent = "API base URL must be https:// (or http://localhost).";
    return;
  }
  const identity = tokenIdentity(token);
  if (!token.startsWith("jcap.") || !identity) {
    $("status").textContent = "Paste a capture token from the agent page.";
    return;
  }
  await chrome.storage.local.set({ server, hosts: hosts.join(", ") });
  const result = await chrome.runtime.sendMessage({
    type: "start", tabId: tab.id, config: { server, token, hosts, identity },
  });
  if (result && result.ok === false) $("status").textContent = `Could not start: ${result.error}`;
  $("token").value = "";
  refresh();
});

init();
