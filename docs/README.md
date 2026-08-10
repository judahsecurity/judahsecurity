# Documentation

Technical docs for the Judah Security ASM platform, AI agent, and Aegis tooling.

## Start here

| Doc | Topic |
|-----|--------|
| [TESTER_PROCESS_AND_ENGAGEMENT_BRAIN.md](./TESTER_PROCESS_AND_ENGAGEMENT_BRAIN.md) | In-product **tester process** — engagement brain, fireteam, differentials, chain cards |
| [PRAETORIAN_ARSENAL_PARITY.md](./PRAETORIAN_ARSENAL_PARITY.md) | Tool arsenal gap matrix vs Praetorian-style 118-capability slide |
| [HARNESS.md](./HARNESS.md) | Pointer to **Aegis Harness** (batch + detection benchmarks) |
| [../harness/README.md](../harness/README.md) | Full harness guide (install, CI gates, ground-truth tags) |
| [../aegis-vanguard/README.md](../aegis-vanguard/README.md) | Autonomous ReACT pentester (ingest + hunters) |
| [../README.md](../README.md) | Platform overview, quick start, architecture |

## Platform & scans

| Doc | Topic |
|-----|--------|
| [RECON_WORKFLOW.md](./RECON_WORKFLOW.md) | Full reconnaissance pipeline |
| [SCAN_TYPES_AND_PROJECT_SETTINGS.md](./SCAN_TYPES_AND_PROJECT_SETTINGS.md) | Scan type configuration |
| [SCAN_EXECUTION_AND_RESULTS.md](./SCAN_EXECUTION_AND_RESULTS.md) | Execution flow and results |
| [SCAN_TROUBLESHOOTING.md](./SCAN_TROUBLESHOOTING.md) | Common scan issues |
| [ADHOC_AND_RECURRING_SCANS.md](./ADHOC_AND_RECURRING_SCANS.md) | Ad-hoc vs scheduled scans |
| [GRAPH_SCHEMA.md](./GRAPH_SCHEMA.md) | Neo4j schema and queries |
| [GRAPH_AND_DATA_FLOW_ROADMAP.md](./GRAPH_AND_DATA_FLOW_ROADMAP.md) | Graph feature roadmap |
| [MCP_AND_TLDFINDER.md](./MCP_AND_TLDFINDER.md) | MCP tool server and TLDFinder |
| [GUARDIAN_TOOL_PARITY.md](./GUARDIAN_TOOL_PARITY.md) | Agent MCP tool parity vs Guardian-CLI |
| [REDAMON_COMPARISON.md](./REDAMON_COMPARISON.md) | RedAmon comparison / adopted ideas |
| [AGENT_IMPROVEMENTS_FROM_REDAMON.md](./AGENT_IMPROVEMENTS_FROM_REDAMON.md) | Agent improvement notes |

## How the pieces relate

```text
ASM AI agent (backend/.../agent/)
  engagement brain + fireteam + compare_requests
           │
           │  product UX / chat / playbooks
           ▼
aegis-vanguard/     ←── harness/ drives batch + benchmarks
  ReACT hunters          findings.jsonl via AEGIS_FINDINGS_SINK
```

Use harness ground-truth **tags** (`default_credentials`, `ssrf`, `idor`, …) when
benchmarks should reflect chain/logic quality, not Nuclei volume alone.
