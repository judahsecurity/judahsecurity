# RedAmon vs Judah Security ASM

This document compares [RedAmon](https://github.com/samugit83/redamon) (AI-powered agentic red team framework) with our ASM platform and lists recommended updates we have adopted or may adopt.

---

## Overview

| Aspect | RedAmon | ASM |
|--------|---------|-----|
| **Recon pipeline** | 6-phase (domain → port → HTTP → resource enum → vuln → MITRE) in Kali container | Multi-phase discovery + port scan + nuclei + screenshots; scanner worker + optional graph |
| **AI agent** | LangGraph ReAct, 3 phases (informational → exploitation → post-exploitation) | LangGraph ReAct, same 3 phases with approval gates |
| **MCP tools** | Separate servers per tool (Naabu/curl :8000, Nuclei :8002, Metasploit :8003, Nmap :8004) in Kali | Single in-process MCP server; nuclei, naabu, httpx, subfinder, dnsx, katana, curl, tldfinder, waybackurls, nmap, masscan, ffuf, amass |
| **Graph** | Neo4j, 17 node types, 20+ relationship types | Neo4j for attack surface / asset relationships |
| **Project settings** | 180+ parameters in UI | Project/org settings; scan profiles; agent config in code/env |
| **Web search** | Tavily for CVE/exploit research | ✅ **Added** — optional `web_search` when `TAVILY_API_KEY` is set |
| **Tool output limit** | Configurable "Tool Output Max Chars" (default 20000) | ✅ **Aligned** — `AGENT_TOOL_OUTPUT_MAX_CHARS` (default 20000) |
| **Exploitation** | Metasploit MCP, execute_code, kali_shell | No Metasploit; agent uses scan/CLI tools only |
| **GVM/OpenVAS** | Optional 170k+ NVT network vuln scanner | Not present |
| **GitHub secrets** | GitHub Secret Hunter (repos, gists, commits) | GitHub secret scanning (different implementation) |

---

## Updates We Have Made (RedAmon-Inspired)

1. **Tool output max chars**  
   Default `AGENT_TOOL_OUTPUT_MAX_CHARS` set to **20000** (was 8000) to match RedAmon’s default. Agent tool layer uses this setting for truncation instead of hardcoded values.

2. **Web search for the agent**  
   Optional **`web_search`** tool: when `TAVILY_API_KEY` is set, the agent can run web searches (e.g. CVE details, exploit docs). Available in all phases. See [ENV_EXAMPLE.md](../ENV_EXAMPLE.md) and agent prompts.

3. **Consistent truncation**  
   MCP success/error responses and `execute_mcp_tool` use the same configurable limit so the agent gets consistent, configurable output length.

---

## Recommended Future Enhancements (Not Yet Done)

- **Tool phase matrix in UI**  
  RedAmon exposes which tools are allowed in which phase in project settings. We have `TOOL_PHASE_MAP` in code; exposing a read-only (or editable) matrix in the UI would improve transparency.

- **Project-level tool output limit**  
  RedAmon allows per-project "Tool Output Max Chars". We use a global env/config value; adding an optional project/org override would align behavior.

- **Attack path / intent routing**  
  RedAmon uses an LLM intent router to classify requests (e.g. CVE exploit vs brute force) and route to different workflows. We could add a lightweight classifier to suggest phases or tool chains.

- **Metasploit / exploitation MCP**  
  RedAmon runs Metasploit and `execute_code` in a Kali sandbox. We do not run exploit frameworks; adding optional Metasploit MCP (or similar) would be a larger, environment-specific change.

- **GVM/OpenVAS**  
  Optional network-level vuln scanning (170k+ NVTs) like RedAmon would require a dedicated scanner service and graph integration.

---

## References

- RedAmon: https://github.com/samugit83/redamon  
- Guardian-CLI tool parity: [GUARDIAN_TOOL_PARITY.md](GUARDIAN_TOOL_PARITY.md)  
- MCP and agent tools: [MCP_AND_TLDFINDER.md](MCP_AND_TLDFINDER.md)
