/* global chrome, ProwlLib */
"use strict";

const MAX_ENTRIES = 300;
const entries = [];
let selected = null;
const $ = (id) => document.getElementById(id);

async function getSettings() {
  const local = await chrome.storage.local.get(["apiBase", "username"]);
  const session = await chrome.storage.session.get(["token"]);
  return { apiBase: local.apiBase || "", username: local.username || "", token: session.token || "" };
}

async function apiFetch(path, init) {
  const { apiBase, token } = await getSettings();
  if (!apiBase || !token) throw new Error("Sign in first (Settings).");
  const response = await fetch(apiBase + path, {
    ...init,
    headers: { ...(init && init.headers), Authorization: "Bearer " + token },
  });
  if (response.status === 401) {
    await chrome.storage.session.remove("token");
    renderAuth(false);
    throw new Error("Session expired. Sign in again.");
  }
  return response;
}

function renderAuth(signedIn, who) {
  $("auth-state").textContent = signedIn ? `Signed in${who ? " as " + who : ""}` : "Not signed in";
}

function setResult(text, ok) {
  const el = $("result");
  el.textContent = text;
  el.className = ok ? "ok" : "err";
}

async function signIn() {
  try {
    const apiBase = ProwlLib.normalizeApiBase($("api-base").value);
    const granted = await chrome.permissions.request({ origins: [ProwlLib.originPattern(apiBase)] });
    if (!granted) throw new Error("Permission to reach the Prowl API was not granted.");
    const username = $("username").value.trim();
    const form = new URLSearchParams({ username, password: $("password").value });
    const response = await fetch(apiBase + "/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.access_token) {
      throw new Error(typeof data.detail === "string" ? data.detail : `Sign-in failed (HTTP ${response.status})`);
    }
    await chrome.storage.local.set({ apiBase, username });
    await chrome.storage.session.set({ token: data.access_token });
    $("password").value = "";
    renderAuth(true, username);
    $("settings").hidden = true;
    await loadChoices();
  } catch (err) {
    renderAuth(false);
    alert(err.message);
  }
}

async function signOut() {
  await chrome.storage.session.remove("token");
  renderAuth(false);
}

function fillSelect(select, items, label, value) {
  select.replaceChildren();
  for (const item of items) {
    const option = document.createElement("option");
    option.value = value(item);
    option.textContent = label(item);
    select.appendChild(option);
  }
}

async function loadChoices() {
  try {
    const [convs, catalog] = await Promise.all([
      apiFetch("/agent/conversations?limit=100").then((r) => r.json()),
      apiFetch("/agent/proof-classes").then((r) => r.json()),
    ]);
    const sessions = ProwlLib.agentSessions(convs);
    fillSelect($("session"), sessions, (c) => `${c.title || c.session_id} (${c.updated_at.slice(0, 16)})`,
               (c) => c.session_id);
    fillSelect($("vclass"), ProwlLib.coverageClasses(catalog), (c) => c, (c) => c);
    if (!sessions.length) setResult("No agent-mode sessions yet. Start a Prowl assessment first.", false);
  } catch (err) {
    setResult(err.message, false);
  }
}

function renderList() {
  const query = $("filter").value.trim().toLowerCase();
  const list = $("request-list");
  list.replaceChildren();
  const shown = entries.filter((e) => !query
    || e.request.url.toLowerCase().includes(query) || e.request.method.toLowerCase().includes(query));
  for (const entry of shown.slice().reverse()) {
    const li = document.createElement("li");
    li.setAttribute("aria-selected", String(entry === selected));
    const method = document.createElement("span");
    method.className = "method";
    method.textContent = entry.request.method;
    const status = document.createElement("span");
    status.className = "status";
    status.textContent = String(entry.response && entry.response.status || "");
    li.append(method, status, document.createTextNode(entry.request.url));
    li.title = entry.request.url;
    li.addEventListener("click", () => select(entry));
    list.appendChild(li);
  }
  $("empty").hidden = entries.length > 0;
}

function updatePreview() {
  if (!selected) return;
  try {
    $("preview").textContent = ProwlLib.formatClaimedRequest(selected, {
      includeCredentials: $("include-creds").checked,
    });
  } catch (err) {
    $("preview").textContent = err.message;
  }
}

function select(entry) {
  selected = entry;
  $("send").hidden = false;
  $("selected-line").textContent = `${entry.request.method} ${entry.request.url}`;
  $("result").textContent = "";
  updatePreview();
  renderList();
}

async function submit() {
  if (!selected) return;
  try {
    const body = ProwlLib.buildCandidate(selected, {
      title: $("title").value,
      vulnerabilityClass: $("vclass").value,
      severity: $("severity").value,
      parameter: $("parameter").value.trim(),
      description: $("description").value,
      note: $("note").value,
    }, { includeCredentials: $("include-creds").checked });
    const session = $("session").value;
    if (!session) throw new Error("Choose a session");
    const response = await apiFetch(`/agent/sessions/${encodeURIComponent(session)}/candidates`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    setResult(ProwlLib.describeResult(response.status, data), response.ok);
  } catch (err) {
    setResult(err.message, false);
  }
}

chrome.devtools.network.onRequestFinished.addListener((entry) => {
  if (!entry.request || !/^https?:/.test(entry.request.url)) return;
  entries.push(entry);
  if (entries.length > MAX_ENTRIES) entries.shift();
  renderList();
});

$("toggle-settings").addEventListener("click", () => { $("settings").hidden = !$("settings").hidden; });
$("sign-in").addEventListener("click", signIn);
$("sign-out").addEventListener("click", signOut);
$("filter").addEventListener("input", renderList);
$("clear").addEventListener("click", () => { entries.length = 0; selected = null; $("send").hidden = true; renderList(); });
$("include-creds").addEventListener("change", updatePreview);
$("submit").addEventListener("click", submit);
$("refresh").addEventListener("click", loadChoices);

(async () => {
  const { apiBase, username, token } = await getSettings();
  $("api-base").value = apiBase;
  $("username").value = username;
  renderAuth(Boolean(token), username);
  if (token) await loadChoices();
  else $("settings").hidden = false;
  renderList();
})();
