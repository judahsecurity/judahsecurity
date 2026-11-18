# Host evidence for exploitability checks

Aegis Oracle decides whether a CVE is exploitable on a specific server by
checking the conditions the exploit needs. Some of those conditions can only
be seen from inside the server: is sshd running, is `LoginGraceTime` zero, is
the Print Spooler service started, is SMBv1 on. Judah collects that host
evidence in one of three ways and picks the lightest one available for each
asset:

| Order | Method | What the customer provides | Touches the host? |
| --- | --- | --- | --- |
| 1 | **CrowdStrike Falcon sensor** (already installed) | Two switches on the Falcon integration and API scopes | Read-only API; RTR `cat`/`ls` only if enabled |
| 2 | **Credential profile, SSH** (Linux, macOS) | A low-privilege account and the servers it covers | Logs in, runs a fixed read-only command list |
| 2 | **Credential profile, WinRM** (Windows) | A low-privilege account and the servers it covers | Logs in, runs a fixed read-only PowerShell list |
| 3 | **Push** (osquery, scripts) | Sends facts to `POST /api/v1/host-checks/assets/{id}/facts` | Nothing from Judah |

Credential profiles are the option for servers that can't run an agent. No
command written by an LLM ever runs on a host; the command lists are fixed
in code (`backend/app/services/host_evidence_service.py`,
`backend/app/services/winrm_host_evidence.py`).

If a check can't run (login rejected, permission missing, host offline),
the finding says "could not check … <reason>" and is **never** treated as
safe.

## Credential profiles

Each profile is an API configuration on the organization (Integrations →
API keys, or `POST /api/v1/external-discovery/configs/{organization_id}`):

| Field | SSH (`host_ssh` or `host_ssh:<label>`) | WinRM (`host_winrm` or `host_winrm:<label>`) |
| --- | --- | --- |
| `api_user` | username | `CORP\svc-judah` or `svc-judah@corp.example` |
| `api_key` | private key (unencrypted ed25519/ECDSA/RSA) or password | password |
| `config.targets` | **required**: CIDRs and hostname globs | **required** |
| `config.priority` | lower is tried first (default 100) | same |
| other `config` | `auth` (`key`/`password`), `port` (22), `known_hosts`, `trust_on_first_use` (false), `sudo` (true) | `transport` (`ntlm`/`kerberos`), `port` (5986), `https` (true), `ca_cert` (PEM) |

Use labels to split accounts by environment, e.g. `host_winrm:windows-prod`
for `10.40.0.0/16` and `host_ssh:linux-dmz` for `*.dmz.corp.example`. An
asset is checked with the first profile, by priority, whose targets match
it. Assets outside every profile's targets are never contacted.

Secrets are encrypted at rest with Judah's API-key cipher. Rotate them by
re-saving the profile.

### Linux and macOS (SSH)

1. Create a dedicated account with no interactive privileges beyond login,
   and install the public key for it.
2. Optional, for the effective sshd configuration (`sshd -T` needs root):
   ```
   judah-probe ALL=(root) NOPASSWD: /usr/sbin/sshd -T
   ```
   Without it, everything else still works and sshd settings come back as
   "could not check".
3. Collect host keys from a trusted network (`ssh-keyscan`) into the
   profile's `known_hosts`. Unknown host keys are refused unless
   `trust_on_first_use` is set.

Collected: OS and kernel, installed packages (dpkg/rpm), running processes
and command lines, effective sshd config, selected sysctls, listening TCP
ports. On macOS packages aren't collected yet; the probe reports that.

### Windows (WinRM)

1. Create a domain (or local) account and add it to the **Remote
   Management Users** group on the target servers (by GPO for fleets).
   Local admin is not required.
2. Use the WinRM HTTPS listener (5986). If the listener uses an internal
   CA, paste the CA certificate into `ca_cert`. Plain HTTP (5985) is only
   used if `https` is false, and then NTLM/Kerberos message encryption is
   forced on.
3. Kerberos needs Kerberos client configuration in the backend container;
   NTLM works without it.

Collected without admin: OS and patch level (`os.build` = CurrentBuild.UBR),
hotfixes, installed software (registry), process names, services and their
state, listening TCP ports, RDP enabled / NLA required, OpenSSH server
config under `C:\ProgramData\ssh`. Needs local admin: SMBv1 state and other
users' process command lines — without admin those are "could not check".

## CrowdStrike Falcon

Enable **Host evidence** (and optionally **read-only RTR**) on the
CrowdStrike integration. Both are off by default and only run when a host
check is requested, never on the scheduled sync. Scopes: Hosts: Read,
Assets: Read, and Real time response: Read for RTR. See
`backend/app/services/falcon_host_evidence.py`.

## Running checks

```bash
# Findings waiting on host evidence, and which collector/profile covers each
curl -sS "$ASM/api/v1/host-checks/organizations/$ORG_ID/pending" -H "Authorization: Bearer $TOKEN"

# Check everything pending (background), or one asset now
curl -sS -X POST "$ASM/api/v1/host-checks/organizations/$ORG_ID/run" -H "Authorization: Bearer $TOKEN"
curl -sS -X POST "$ASM/api/v1/host-checks/assets/$ASSET_ID/collect" -H "Authorization: Bearer $TOKEN"
```

Each result lists the probes that ran, any that failed and why, and the
before/after verdict of every open CVE finding on the asset.
