// Pure helpers shared by the panel and the Node tests. No DOM, no chrome.*.
(function (root) {
  "use strict";

  const CLAIMED_REQUEST_LIMIT = 2000; // ExternalCandidateRequest.claimed_request max_length
  const SENSITIVE_HEADERS = new Set([
    "authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token",
    "x-csrf-token", "x-xsrf-token",
  ]);
  // Pseudo-headers and hop-by-hop noise that add length without meaning.
  const DROP_HEADERS = new Set([
    ":authority", ":method", ":path", ":scheme", "connection", "content-length",
    "accept-encoding", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    "upgrade-insecure-requests", "priority",
  ]);

  function normalizeApiBase(value) {
    const raw = String(value || "").trim().replace(/\/+$/, "");
    let url;
    try {
      url = new URL(raw);
    } catch (_e) {
      throw new Error("API base must be a full URL, e.g. https://prowl.example.com/api/v1");
    }
    const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
    if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
      throw new Error("API base must use https (http is allowed only for localhost)");
    }
    if (url.username || url.password) throw new Error("API base must not contain credentials");
    return url.origin + url.pathname.replace(/\/+$/, "");
  }

  function originPattern(apiBase) {
    const url = new URL(apiBase);
    return url.protocol + "//" + url.hostname + "/*";
  }

  // HAR entry -> raw HTTP/1.1 text, credentials redacted unless asked.
  function formatClaimedRequest(entry, options) {
    const opts = options || {};
    const req = (entry && entry.request) || {};
    let url;
    try {
      url = new URL(req.url);
    } catch (_e) {
      throw new Error("Request has no valid URL");
    }
    const lines = [`${(req.method || "GET").toUpperCase()} ${url.pathname}${url.search} HTTP/1.1`,
                   `Host: ${url.host}`];
    for (const header of req.headers || []) {
      const name = String(header.name || "");
      const lower = name.toLowerCase();
      if (!name || lower === "host" || DROP_HEADERS.has(lower)) continue;
      const value = SENSITIVE_HEADERS.has(lower) && !opts.includeCredentials
        ? "[redacted]" : String(header.value || "");
      lines.push(`${name}: ${value}`);
    }
    let text = lines.join("\n");
    const body = req.postData && req.postData.text;
    if (body) text += "\n\n" + body;
    if (text.length > CLAIMED_REQUEST_LIMIT) {
      const marker = "\n...[truncated]";
      text = text.slice(0, CLAIMED_REQUEST_LIMIT - marker.length) + marker;
    }
    return text;
  }

  function targetUrl(entry) {
    const url = new URL(entry.request.url);
    return url.origin + url.pathname;
  }

  function buildCandidate(entry, form, options) {
    const title = String(form.title || "").trim();
    if (title.length < 4) throw new Error("Title needs at least 4 characters");
    if (!form.vulnerabilityClass) throw new Error("Choose a vulnerability class");
    const body = {
      title: title.slice(0, 200),
      target: targetUrl(entry).slice(0, 2048),
      vulnerability_class: String(form.vulnerabilityClass).slice(0, 64),
      description: String(form.description || "").slice(0, 2000),
      claimed_request: formatClaimedRequest(entry, options),
      severity: ["info", "low", "medium", "high", "critical"].includes(form.severity)
        ? form.severity : "medium",
    };
    if (form.parameter) body.parameter = String(form.parameter).slice(0, 128);
    if (form.note) body.evidence_note = String(form.note).slice(0, 1000);
    return body;
  }

  function agentSessions(conversations) {
    return (conversations || []).filter((c) => c && c.mode === "agent" && c.session_id);
  }

  function coverageClasses(catalog) {
    return Object.keys((catalog && catalog.coverage_classes) || {}).sort();
  }

  function describeResult(status, data) {
    if (status === 201) return `Added as a pending candidate (${data.candidate_id || "ok"}). Resume the session so its verifier re-tests it.`;
    if (status === 202) return "Queued: the session is running and will pick it up at its next step.";
    const detail = data && data.detail;
    const text = typeof detail === "string" ? detail : JSON.stringify(detail || data || {});
    return `Not accepted (HTTP ${status}): ${text}`;
  }

  const api = { CLAIMED_REQUEST_LIMIT, normalizeApiBase, originPattern, formatClaimedRequest,
                targetUrl, buildCandidate, agentSessions, coverageClasses, describeResult };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.ProwlLib = api;
})(typeof self !== "undefined" ? self : this);
