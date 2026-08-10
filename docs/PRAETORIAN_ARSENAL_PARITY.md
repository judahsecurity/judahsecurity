# Praetorian-style arsenal parity

Comparison of the slide arsenal (**118 capabilities · 8 categories**) against
Judah Security ASM agent / MCP / Docker images.

> We are an ASM + web authz agent, not a CTF box. Full REV / PWN / STEGO / FORENSICS
> coverage is intentionally out of scope unless a customer engagement needs it.

## Summary

| Category | Slide count | Exact HAVE | Partial / substitute | Missing |
|----------|------------:|-----------:|---------------------:|--------:|
| CORE | 21 | ~12 | openssl CLI now on images | nc, socat, file, strings, … |
| REV | 17 | 0 | — | all (out of scope) |
| PWN | 9 | 0 | — | all (out of scope) |
| CRYPTO | 11 | 0 | jwt_tool / pycryptodomex | john, hashcat, sagemath, … |
| FORENSICS | 19 | 0 | — | all (out of scope) |
| STEGO | 6 | 0 | — | all (out of scope) |
| WEB | 9 | 5+ | XSStrike ≈ xsser; Dalfox added | wapiti, requests-html |
| NETWORK | 26 | 16+ | Hydra / Feroxbuster / Commix / Dalfox added | msfvenom, impacket, gobuster, … |
| **Overall** | **118** | **~35** | **~10** | **~73** |

Exact counts drift as Docker builds land; treat WEB+NETWORK as the product focus.

## Agent-callable WEB / NETWORK (priority)

| Arsenal tool | Agent tool | Status |
|--------------|------------|--------|
| nuclei | `execute_nuclei` | HAVE |
| nikto | `execute_nikto` | HAVE |
| sqlmap | `execute_sqlmap` | HAVE |
| arjun | `execute_arjun` | HAVE |
| jwt_tool | `execute_jwt` | HAVE |
| xsser | `execute_xsstrike` (+ `execute_dalfox`) | PARTIAL → stronger with Dalfox |
| dalfox | `execute_dalfox` | **ADDED** |
| commix | `execute_commix` | **ADDED** |
| hydra | `execute_hydra` (+ `test_credential_spray`) | **ADDED** |
| feroxbuster | `execute_feroxbuster` | **ADDED** |
| whatweb | `execute_whatweb` | HAVE (now on backend image too) |
| ffuf / katana / httpx / nmap / … | matching `execute_*` | HAVE |
| wapiti | — | MISSING (Nuclei/Nikto cover much of this) |
| impacket / msfvenom | — | MISSING (AD / payload gen — not ASM default) |

## Praetorian open-source wraps (already named)

| Praetorian | Ours |
|------------|------|
| pius | `execute_atlas` |
| titus | `execute_argus` |
| Guard tool hooks | `aegis_praetorium` (Censor / Lictor / Augur) |

## Specialist lanes (Marcus-style)

Fireteam specialists now get **thin skill packs** (`specialist_skills.py`) and
fixed allowlists (`execute_hermes`, `execute_themis`, new exploit tools).

See [TESTER_PROCESS_AND_ENGAGEMENT_BRAIN.md](./TESTER_PROCESS_AND_ENGAGEMENT_BRAIN.md).

## Intentionally deferred

- Full REV / PWN / FORENSICS / STEGO CTF stacks
- Metasploit / msfvenom
- Unbounded Hydra dictionary attacks (Lictor forces `-f`; skill pack requires tiny lists)

## Related

- [harness/README.md](../harness/README.md) — measure detection quality
- [GUARDIAN_TOOL_PARITY.md](./GUARDIAN_TOOL_PARITY.md) — older Guardian parity notes
