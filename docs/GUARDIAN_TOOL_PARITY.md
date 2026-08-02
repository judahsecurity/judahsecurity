# Guardian-CLI Tool Parity

This document maps [Guardian-CLI](https://github.com/zakirkun/guardian-cli) tools to Judah Security ASM and explains how to add more tools so the agent can use them. It also describes how agent scan findings get into the platform’s findings table.

---

## Guardian’s 19 Tools vs ASM

| Guardian tool | In ASM agent (MCP) | In ASM scanner/backend | Notes |
|---------------|--------------------|-------------------------|--------|
| **nmap** | ✅ `execute_nmap` | ✅ Port verify, service detect, API | Agent can run arbitrary nmap args. |
| **masscan** | ✅ `execute_masscan` | ✅ Port scan, API | Agent can run arbitrary masscan args. |
| **httpx** | ✅ `execute_httpx` | ✅ Discovery, scans | |
| **whatweb** | ✅ `execute_whatweb` | ✅ Technology scan (source=whatweb), WhatWeb service | Agent + scheduled/ad hoc scans. |
| **wafw00f** | ✅ `execute_wafw00f` | — | WAF detection. Informational phase (passive). pip install wafw00f. |
| **subfinder** | ✅ `execute_subfinder` | ✅ Discovery | |
| **amass** | ✅ `execute_amass` | ✅ Backend image | |
| **dnsrecon** | ❌ | ❌ | We use dnsx; can add dnsrecon if installed. |
| **nuclei** | ✅ `execute_nuclei` | ✅ Vuln scans | |
| **nikto** | ✅ `execute_nikto` | — | Web server scanner. Exploitation phase. apt install nikto. |
| **sqlmap** | ✅ `execute_sqlmap` | — | SQL injection automation. Exploitation phase. pip install sqlmap. Auto-adds --batch. |
| **wpscan** | ✅ `execute_wpscan` | — | WordPress scanner. Exploitation phase. gem install wpscan. |
| **testssl** | ✅ `execute_testssl` | — | TLS/SSL testing. Informational phase. git clone testssl.sh. |
| **sslyze** | ✅ `execute_sslyze` | — | TLS/SSL scanner. Informational phase. pip install sslyze. |
| **gobuster** | ❌ | ❌ | We have ffuf; gobuster is redundant. |
| **ffuf** | ✅ `execute_ffuf` | ✅ Backend + ffuf_service | Agent can run arbitrary ffuf args. |
| **arjun** | ✅ `execute_arjun` | — | HTTP param discovery. Informational phase. pip install arjun. |
| **xsstrike** | ✅ `execute_xsstrike` | — | XSS scanner. Exploitation phase. pip install XSStrike. |
| **gitleaks** | ✅ `execute_gitleaks` | — | Secret scanning. Informational phase. Go binary. |
| **cmseek** | ✅ `execute_cmseek` | — | CMS detection. Informational phase. pip install cmseek. |

**Also in ASM agent (not in Guardian list):** `execute_naabu`, `execute_dnsx`, `execute_katana`, `execute_curl`, `execute_tldfinder`, `execute_waybackurls`, `execute_knockpy`, `execute_gau`, `execute_kiterunner`, `execute_wappalyzer`, `execute_crtsh`, `execute_schemathesis`, `execute_browser`, `execute_llm_red_team`, `generate_injection_payloads`, `discover_parameters` — all available with `*_help` for usage.

---

## How to Add a New Tool for the Agent

To expose a new CLI tool (e.g. Nikto, SQLMap) so the agent can run it:

### 1. Install the binary

- **Backend container (agent runs here):** Add the tool to `backend/Dockerfile` (e.g. `apt-get install` or copy from a builder stage).
- **Scanner container:** Add to `backend/Dockerfile.scanner` only if scheduled/automated scans should run it; the **agent uses the backend** image.

### 2. Register in MCP (`backend/app/services/mcp/server.py`)

In `_register_default_tools()`:

- Register an **execute_&lt;tool&gt;** `MCPTool`:
  - `name="execute_<tool>"`
  - `parameters={"args": {"type": "string", "description": "..."}}`
  - `required_params=["args"]`
  - `handler=self._execute_<tool>`
  - Choose `phase="informational"` or `phase="exploitation"` (exploitation requires user approval in the agent).
- Register a **&lt;tool&gt;_help** `MCPTool` with no params and `handler=self._<tool>_help`.

Implement handlers that run the CLI, e.g.:

```python
async def _execute_nikto(self, args: str) -> Dict[str, Any]:
    cmd = ["nikto"] + args.split()
    return await self._run_command(cmd, timeout=300)

async def _nikto_help(self) -> Dict[str, Any]:
    return await self._run_command(["nikto", "-h"])
```

### 3. Expose to the agent (`backend/app/services/agent/tools.py`)

In `ASMToolsManager._register_tools()`, add:

- `"execute_<tool>": self.execute_mcp_tool`
- `"<tool>_help": self.execute_mcp_tool`

### 4. Add to prompts and phase map (`backend/app/services/agent/prompts.py`)

- In **get_phase_tools()**: add the tool to the appropriate phase block (informational vs exploitation) and list the `*_help` in the help tools line.
- In **TOOL_PHASE_MAP**: add entries for `execute_<tool>` and `<tool>_help` with the correct phase list (e.g. `["exploitation", "post_exploitation"]` for active scanning tools).

After that, the agent will see the tool in its phase and can call it (with approval for exploitation-phase tools when configured).

---

## Which tools are actually running?

| Tool | In agent (MCP + tools.py) | Binary in backend image | Notes |
|------|---------------------------|-------------------------|--------|
| **Nuclei** | Yes execute_nuclei | Yes Dockerfile | Runs when agent calls it. |
| **FFuf** | Yes execute_ffuf | Yes Dockerfile | Runs when agent calls it. |
| **Naabu, Nmap, Masscan, httpx, subfinder, dnsx, katana, curl, tldfinder, waybackurls, amass, whatweb** | Yes | Yes (see Dockerfile) | Same: agent can run them. |
| **SQLMap** | Yes execute_sqlmap | Yes (pip) | SQL injection automation. Auto --batch. |
| **Nikto** | Yes execute_nikto | Yes (apt) | Web server vulnerability scanner. |
| **wafw00f** | Yes execute_wafw00f | Yes (pip) | WAF detection. |
| **testssl** | Yes execute_testssl | Yes (git clone) | TLS/SSL testing. |
| **SSLyze** | Yes execute_sslyze | Yes (pip) | TLS/SSL scanner (Python). |
| **Arjun** | Yes execute_arjun | Yes (pip) | HTTP parameter discovery. |
| **WPScan** | Yes execute_wpscan | Yes (gem) | WordPress vulnerability scanner. |
| **XSStrike** | Yes execute_xsstrike | Yes (pip) | XSS vulnerability scanner. |
| **Gitleaks** | Yes execute_gitleaks | Yes (Go binary) | Secret scanning. |
| **CMSeeK** | Yes execute_cmseek | Yes (pip) | CMS detection. |

Tool output (e.g. Nuclei/FFuf stdout) is returned to the agent only; it is **not** auto-saved to the database. To get data into the platform, the agent must call **create_finding** (for the Findings/Vulnerabilities UI) or **save_note** (for session notes).

## Where assessment data goes

1. **Conversation / execution trace** – Raw tool output (nuclei, ffuf, etc.) is returned to the LLM and shown in the Agent UI as part of the run. It is not persisted to DB unless the agent takes a follow-up action.
2. **Findings (Vulnerabilities) table** – Only when the agent calls **create_finding**. That writes to the `vulnerabilities` table (`detected_by="agent"`). Data shows in the UI under Findings/Vulnerabilities and on asset detail pages.
3. **Session notes** – When the agent calls **save_note**, data is stored in the `agent_notes` table (by org, user, session). Used for session context; not shown in the main Findings UI.
4. **Scheduled/scanner runs** – Separate from the agent. Scans created via Scans (e.g. Nuclei, port scan) are run by the scanner worker; that pipeline imports results into assets and findings automatically. Agent-run tools do **not** auto-import; the agent must call **create_finding** per finding.

---

## Outputting agent findings to the findings table

Agent discoveries can appear in the platform’s **Findings** (Vulnerabilities) table in two ways:

1. **create_finding** (recommended for vulnerabilities)  
   The agent has a **create_finding** tool. When the agent identifies a real vulnerability or finding, it should call:
   - **create_finding**(title, description, severity, target, [evidence], [cve_id], [remediation])  
   - `target` must be a hostname, domain, or URL that matches an **existing asset** in the organization (use **query_assets** first).  
   - Findings created this way show up in the UI under Vulnerabilities and are stored in the `vulnerabilities` table with `detected_by="agent"`.

2. **save_note** (session-only)  
   **save_note** stores notes (e.g. credential, vulnerability, finding, artifact) in the `agent_notes` table. These are used for session context and do **not** appear in the Findings/Vulnerabilities list. Use **create_finding** when you want a finding to appear in the findings table.

3. **Scheduled / scanner-created findings**  
   Findings from scheduled Nuclei scans, port scans, etc. are imported by the scanner worker (e.g. `NucleiFindingsService`, `PortFindingsService`) and already appear in the findings table. The agent’s **execute_nuclei** runs Nuclei ad hoc and returns stdout only; it does **not** auto-import. To get those into the table, the agent should call **create_finding** for each important result (with title, description, severity, target, evidence from the Nuclei output).

## Which scans populate the asset page

Asset detail data (login portals, technologies, ports, etc.) is filled by **running the right scan type** for that asset. From the **Asset** detail page you can:

- **Run agent assessment** — Opens the Agent page with target and “Vuln scan” preset so the agent assesses this asset and can call **create_finding** for any vulnerabilities.
- **Run scan** (dropdown) — Starts an ad hoc scan for this asset only:
  - **Login portal** — Populates `has_login_portal`, `login_portals`, and related risk drivers.
  - **Technology** — Populates technologies and tech-based risk drivers.
  - **Port scan** — Populates open ports and port-based data.

After the scan completes (see **Scans**), refresh the asset page to see updated login page, technologies, and ports.

---

## Summary

- **Agent-available (Guardian-style):** Nmap, Masscan, HTTPX, Subfinder, Amass, Nuclei, FFuf, WhatWeb, SQLMap, Nikto, wafw00f, testssl, SSLyze, Arjun, WPScan, XSStrike, Gitleaks, CMSeeK, plus Naabu, DNSX, Katana, curl, TLDFinder, WaybackURLs, Knockpy, GAU, Kiterunner, Wappalyzer, crt.sh, Schemathesis, Browser, LLM Red Team, injection payloads, parameter discovery.
- **Not yet in agent:** DNSRecon (covered by dnsx), Gobuster (covered by ffuf).
- **Findings table:** Use **create_finding** so agent discoveries appear in the UI; **save_note** is for session notes only.
- **Asset page:** Use “Run scan” (Login portal / Technology / Port scan) so the asset populates with login pages, technologies, and ports; use “Run agent assessment” to drive the agent from that asset.
