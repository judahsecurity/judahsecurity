---
name: command_injection
description: OS command injection on fields that reach a shell (ping, lookup, convert, export, archive). Arithmetic echo only; confirm via scoped_injection_probe_assigned (scoped_cmdi_eval).
---

# OS command injection on observed inputs

Likely sinks wrap a CLI tool around user input: network diagnostics (`host`,
`ip`, `target` → ping/traceroute/nslookup/dig/whois), file conversion and
thumbnailing (ImageMagick, ffmpeg, LibreOffice, wkhtmltopdf), export/backup and
archive features (tar/zip filenames, `format`, `filename`), mail sending,
git/repo import URLs, and admin "test connection" buttons. Field names alone do
not prove a shell; the computed echo does.

## Proof rules (override everything below)

* Status codes, timeouts, error strings (`sh: 1:`, `not found`), and reflected
  input are **leads**.
* Medium+ needs a receipt from `scoped_injection_probe_assigned` with proof kind
  `scoped_cmdi_eval`: the tool injects an arithmetic echo (shell arithmetic of
  nonce-bound random factors); the product must appear in the probe response and
  be absent from the control and baseline. The independent verifier replays it.
* **Arithmetic echo only.** Never run `id`, `whoami`, `cat`, `curl`/`wget`
  downloads, file writes, `rm`, `kill`, `shutdown`, `sleep` loops, fork bombs,
  reverse shells, or anything that changes host state. No persistence.
* `execute_commix` is for a high-signal lead the scoped probe could not close,
  and only in its non-destructive detection mode.

## Separators and contexts (leads for picking the recipe)

| Context | Shapes the tool tries |
|---|---|
| Unquoted argument | `;`  `|`  `||`  `&&`  `&`  newline `%0a` |
| Command substitution | `$(…)`  `` `…` `` |
| Inside double quotes | `"$(…)"` or close quote `";…;"` |
| Inside single quotes | `';…;'` (substitution does not expand inside `'…'`) |
| Windows cmd | `&`  `|`  `&&`  `%0a`; PowerShell `;` |
| Argument injection (no shell) | leading `-`/`--option=` into a CLI that takes flags |

Filter-evasion shapes (`${IFS}` instead of spaces, `{a,b}` brace expansion,
`$'\x..'` quoting, newline when `;` is stripped) are recipe variants; let the
tool select them rather than hand-crafting.

## Procedure

1. Identify the cell and keep its content type: a form endpoint ignores JSON
   bodies and returns a normal 200 (silent false negative).
2. Establish a baseline with the legitimate value (e.g. a valid host).
3. Run `scoped_injection_probe_assigned`; read `proof_confirmed` and the recipe.
   A negative result for one context is inconclusive for the others.
4. Blind sinks (output not returned): use an OOB lead via
   `run_oob_callback_workflow` only when the run authorizes callbacks; a
   correlated DNS hit is a lead toward the scoped probe, not a replacement for
   the medium+ receipt unless the verifier accepts that proof kind.
5. Timing-only signals need the statistical rule below before they count even
   as a lead worth escalation.

## Discipline

* Random factors/markers ≥8 characters, checked absent from the baseline.
* Timing claims: ≥10 interleaved trials per group (control vs probe, randomized
  order), mean ≥2σ above control. One slow response is jitter.
* A response change needs a body difference, not just a status change.
* A 400 on a malformed body is not a sink: retest with a minimal well-formed
  body so validation-layer rejection is not mistaken for execution.
* Never submit alone: "semicolon caused a 500", WAF block page, input echoed in
  an error. Chain-required: path traversal into an exec'd location, or SSTI →
  shell, needs its own lane's proof.

Adapted from elementalsouls/Claude-BugHunter (skills/hunt-rce), CC BY 4.0; modified.
