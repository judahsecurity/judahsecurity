const test = require("node:test");
const assert = require("node:assert/strict");
const lib = require("../lib.js");

const entry = {
  request: {
    method: "POST",
    url: "https://app.example.com/api/items?id=7",
    headers: [
      { name: ":authority", value: "app.example.com" },
      { name: "Host", value: "app.example.com" },
      { name: "Cookie", value: "session=abc" },
      { name: "Authorization", value: "Bearer xyz" },
      { name: "Content-Type", value: "application/json" },
      { name: "Accept-Encoding", value: "gzip" },
    ],
    postData: { text: "{\"id\":7}" },
  },
};

test("raw request redacts credentials by default and drops noise headers", () => {
  const text = lib.formatClaimedRequest(entry);
  assert.equal(text, [
    "POST /api/items?id=7 HTTP/1.1",
    "Host: app.example.com",
    "Cookie: [redacted]",
    "Authorization: [redacted]",
    "Content-Type: application/json",
    "",
    "{\"id\":7}",
  ].join("\n"));
  assert.match(lib.formatClaimedRequest(entry, { includeCredentials: true }), /Cookie: session=abc/);
});

test("raw request is capped to the API limit", () => {
  const big = { request: { ...entry.request, postData: { text: "x".repeat(5000) } } };
  const text = lib.formatClaimedRequest(big);
  assert.equal(text.length, lib.CLAIMED_REQUEST_LIMIT);
  assert.ok(text.endsWith("...[truncated]"));
});

test("candidate body matches ExternalCandidateRequest", () => {
  const body = lib.buildCandidate(entry, {
    title: "IDOR on items", vulnerabilityClass: "idor", severity: "high", parameter: "id", note: "n",
  });
  assert.equal(body.target, "https://app.example.com/api/items");
  assert.equal(body.vulnerability_class, "idor");
  assert.equal(body.severity, "high");
  assert.equal(body.parameter, "id");
  assert.equal(body.evidence_note, "n");
  assert.throws(() => lib.buildCandidate(entry, { title: "x", vulnerabilityClass: "idor" }), /4 characters/);
  assert.equal(lib.buildCandidate(entry, { title: "Long enough", vulnerabilityClass: "xss", severity: "bogus" }).severity, "medium");
});

test("API base must be https unless localhost", () => {
  assert.equal(lib.normalizeApiBase("https://prowl.example.com/api/v1/"), "https://prowl.example.com/api/v1");
  assert.equal(lib.normalizeApiBase("http://localhost:8000/api/v1"), "http://localhost:8000/api/v1");
  assert.throws(() => lib.normalizeApiBase("http://prowl.example.com/api/v1"), /https/);
  assert.throws(() => lib.normalizeApiBase("https://u:p@prowl.example.com"), /credentials/);
  assert.throws(() => lib.normalizeApiBase("not a url"), /full URL/);
  assert.equal(lib.originPattern("https://prowl.example.com:8443/api/v1"), "https://prowl.example.com/*");
});

test("session and class pickers", () => {
  assert.deepEqual(lib.agentSessions([{ session_id: "a", mode: "agent" }, { session_id: "b", mode: "assist" }]).map((s) => s.session_id), ["a"]);
  assert.deepEqual(lib.coverageClasses({ coverage_classes: { xss: {}, idor: {} } }), ["idor", "xss"]);
});

test("result messages", () => {
  assert.match(lib.describeResult(201, { candidate_id: "c1" }), /pending candidate \(c1\)/);
  assert.match(lib.describeResult(202, {}), /Queued/);
  assert.match(lib.describeResult(422, { detail: "target is outside this session's scope" }), /outside/);
});
