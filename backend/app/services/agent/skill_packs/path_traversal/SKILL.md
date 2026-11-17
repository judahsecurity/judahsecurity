---
name: path_traversal
description: Path traversal / LFI on file, template, and download parameters. Encoding ladder, absolute paths, known-file signatures; confirm via scoped_injection_probe_assigned (scoped_traversal_read).
---

# Path traversal / LFI on observed inputs

Candidate cells: `file`, `path`, `page`, `template`, `view`, `lang`, `module`,
`include`, `doc`, `load`, `download`, `img`, `pdf`, `report`, `theme`, `layout`,
`dir`, JSON `{"filename"|"path"|"template": …}`, and path segments of static or
download routes (`/files/<name>`). Archive-extraction and image-processing
features are traversal surfaces too, but they require uploads; treat them as
leads to report, not to exploit.

## Proof rules (override everything below)

* Observed GET query inputs and operator-approved POST bodies (`body_replay_paths`,
  form or JSON) are both supported by `scoped_injection_probe_assigned`.

* A different status code, a canned 403/500, or your path **echoed** in an error
  (`failed to open '/var/www/../../etc/passwd'`) is a lead, not a read.
* Medium+ needs a receipt from `scoped_injection_probe_assigned` with proof kind
  `scoped_traversal_read`: the response contains a known world-readable file
  signature that is absent from the control (same traversal depth to a
  non-existent, nonce-named file such as `/etc/prowl-absent-<nonce>`) and the
  probe body differs from the control. Signatures: `/etc/passwd` →
  `root:<pw>:0:0:...:/...`; `win.ini` → both `[fonts]` and `[extensions]`. The verifier replays with a fresh control.
* Read-only, known-file targets only. Do not read secrets (`.env`, keys,
  `/proc/self/environ`, cloud credentials) to "prove impact"; do not write,
  overwrite, or delete files; no log/session poisoning, `php://filter` chains,
  RFI, `data://`/`expect://`/`phar://` execution, or upload-to-include.

## Encoding ladder (the tool's recipe variants)

```
../../../etc/passwd                 plain relative
/etc/passwd   C:\Windows\win.ini    absolute (no base prefix)
....//....//etc/passwd              survives single-pass "../" stripping
..%2f..%2f..%2fetc%2fpasswd         URL-encoded slash
%2e%2e%2f%2e%2e%2fetc%2fpasswd      encoded dots
..%252f..%252fetc%252fpasswd        double-encoded (decoded twice server-side)
..%c0%af / %c0%ae%c0%ae%2f          overlong UTF-8 (legacy stacks)
/etc/passwd%00.png                  null byte (legacy PHP < 5.3.4, old Java)
..\..\..\windows\win.ini  ..%5c..%5c  Windows backslash
/etc/./passwd  /etc//passwd         literal-blocklist evasion
<base>/../../../etc/passwd          app requires a fixed prefix: keep it, then climb
```

If the app appends an extension (`.php`, `.png`), try the null-byte and `?`/`#`
truncation variants; if it prepends a base directory, pad with extra `../`.
Server-level traversal (e.g. `/icons/.%2e/.%2e/…` on Apache 2.4.49/2.4.50)
needs the raw path preserved; mark the request "path as-is".

## Procedure

1. Baseline the cell with its legitimate value; record body length and type.
2. Run `scoped_injection_probe_assigned` with the traversal recipe for the
   platform you have evidence for (Unix vs Windows from headers/paths). A
   negative ladder is inconclusive for other encodings or base depths.
3. Rendered/templated output may HTML-escape or truncate the file; the
   signature still has to appear. Report exactly what was recovered.
4. Blind sinks (file included but not returned): a stable length delta between
   known-existing and non-existent targets is a lead only, triple-confirmed
   with a second known file; it does not reach medium without the receipt.

## Discipline

* Control must be the same request with a non-existent sibling file, so a
  generic "file found" template does not pass as a read.
* Random suffixes ≥8 characters, checked absent from the baseline.
* A bypass needs a body difference, not a status change.
* A 400 on a malformed path parameter is input validation; retest with a
  minimal well-formed value before concluding anything.
* Never submit alone: echoed path, stack trace naming a file, directory listing
  of a public static folder. Chain-required: traversal → secret read → takeover
  is a separate, authorized escalation, not part of this proof.

Adapted from elementalsouls/Claude-BugHunter (skills/hunt-lfi), CC BY 4.0; modified.
