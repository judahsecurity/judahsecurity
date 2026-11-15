# REA pass (code-scan)

[REA](https://github.com/morluto/rea) (`rea` CLI, npm `rea-agents`) covers the
**shipped** side of a checkout that source reading misses: `dist/`, `build/`,
bundled JS, source maps, native binaries, Electron ASARs, APKs. Its commands
used here parse files and never execute them, so they fit the static rule.

## Run

```bash
python3 .claude/skills/_lib/rea_scan.py <target-dir> --out <run_dir>/rea.json
```

It runs `rea audit-release-exposure` on the checkout root (and on each ASAR/APK
found), plus `rea inspect-binary-hardening` on each ELF/PE/Mach-O found. If it
prints `rea not installed`, note that in `tested_clean.json` as not covered and
move on. Install: `npm install -g --ignore-scripts rea-agents@6.9.0` (Node 22.23.4+).

## Read `rea.json`

- `findings[]`: `rule`, `severity`, `file`, `locations`, `evidence`, `remediation`.
- `coverage_gaps[]`: checks REA could not assess. **Not findings.** Do not report.
- `artifacts[]`: what was inspected. Put clean ones in `tested_clean.json`.

## Keep a hit only if

1. The file actually ships: it is served, packaged, or published (check build
   config, `Dockerfile`, static-serving routes, `package.json` `files`, CI
   release steps). A `.map` in a gitignored local `dist/` that never deploys is
   refuted.
2. It instantiates a threat row. Typical mappings:

| REA rule | Usually maps to | Severity guide |
|----------|-----------------|----------------|
| `rea.javascript.source_map_sources` | source disclosure of a client bundle | REA's, drop to low if source is already public |
| `rea.text.credential_markers` | secret in a public artifact | high; critical if the key is live-scoped |
| `rea.native.debug_companions`, `rea.native.pdb_path`, `rea.go.build_paths` | info disclosure | info/low |
| `rea.electron.*` | local code exec via fuses on a desktop app | REA's |
| `rea.native.hardening` | exploit mitigation missing on a shipped binary | low; medium for NX off on a network-facing daemon |

For `text.credential_markers`, REA reports the rule and location only. Read
the file at that location to confirm before writing the finding. Record the
secret redacted (last 4 chars hidden).

Findings from this pass use `category: "release-exposure"` or
`"binary-hardening"` and `location` = shipped file path.
