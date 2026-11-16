---
name: ssti
description: Server-side template injection on observed inputs. Fingerprint the engine with nonce-bound arithmetic, confirm only through scoped_injection_probe_assigned (scoped_ssti_eval).
---

# SSTI on observed inputs

Template injection lives where user text is composed into a template before
render: name/bio/display-name fields, email/notification templates, invoice and
PDF/report generators, CMS "edit template" previews, search terms echoed in
results, error pages, and headers reflected into rendered views. The render may
land somewhere other than the HTTP response (a confirmation email, a generated
PDF, a preview pane). Keep the captured request shape, identity, and parameter
location for every probe and control.

## Proof rules (override everything below)

* Observed GET query inputs and operator-approved POST bodies (`body_replay_paths`,
  form or JSON) are both supported by `scoped_injection_probe_assigned`.

* Reflection, `{{7*7}}` echoed literally, a 500, a stack trace, or an engine
  name in an error are **leads**, not proof.
* Medium+ needs a deterministic receipt from `scoped_injection_probe_assigned`
  with proof kind `scoped_ssti_eval`: the tool picks nonce-bound random factors,
  the computed product must appear in the probe response and be absent from the
  control and the baseline. The independent verifier replays it with fresh
  factors. Do not hand-build an `{{7*7}}`→`49` claim: `49` occurs naturally.
* Non-destructive only. Do not attempt OS command execution, class-walker /
  `__subclasses__` gadgets, `Execute?new()`, file reads, or SSRF through template
  functions. Computed output is the whole proof for this class.

## Fingerprint matrix (leads for picking the syntax)

| Probe shape | Evaluates in |
|---|---|
| `{{a*b}}` | Jinja2, Twig, Nunjucks, Pebble, Handlebars-with-helpers (rarely) |
| `{{a*'b'}}` | Jinja2 → string repetition; Twig → numeric product (distinguishes them) |
| `${a*b}` | Freemarker, Velocity, Mako, JSP EL, Thymeleaf inline |
| `#{a*b}` | Freemarker (legacy), Ruby string interpolation, JSF EL |
| `<%= a*b %>` | ERB (Ruby), EJS |
| `*{a*b}` / `[[${a*b}]]` | Spring Thymeleaf |
| `{a*b}` / `{$smarty.version}` | Smarty |

Polyglot opener for discovery (one request, then narrow):
`${{<%[%'"}}%\.` — a parse error that differs from the baseline error suggests a
template sink; confirm with the engine-specific arithmetic probe. If `{{…}}`
renders literally but `${…}` evaluates, you are on a Java/`${}` engine: stop
sending double-curly syntax.

## Procedure

1. Pick candidate cells from the parameter inventory (query, form, JSON body,
   path segment, header) whose value is reflected or rendered later.
2. Send the context-appropriate content type. A form endpoint ignores a JSON
   body and returns a normal page, which is a false negative, not a clean result.
3. Run `scoped_injection_probe_assigned` for each engine family the fingerprint
   leaves open. Read `proof_confirmed` and the proof kind; a negative recipe is
   inconclusive for the other engines.
4. When the value is rendered elsewhere (preview, email, PDF), trigger the
   render through the app's own preview action and read that output; keep the
   same nonce factors. Prefer preview over save; never persist a payload you
   cannot remove.
5. If the input is length-capped, a short arithmetic probe still fits; that is
   enough for this class.

## Discipline

* Markers and factors are random, ≥8 characters of entropy, and checked absent
  from the baseline before you claim evaluation.
* Inside an HTML attribute the raw payload may echo back; that is reflection,
  not evaluation. Compare the computed value, not the input.
* A sandboxed engine that only evaluates arithmetic is still SSTI; severity
  follows the verifier receipt, not speculation about RCE.
* Never submit alone: template syntax echoed verbatim, engine version banners,
  generic 500 on `{{`. Chain-required: SSTI → stored XSS in a rendered email
  needs the XSS lane's own proof.

Adapted from elementalsouls/Claude-BugHunter (skills/hunt-ssti), CC BY 4.0; modified.
