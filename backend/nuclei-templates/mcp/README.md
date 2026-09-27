# MCP exposure templates

These are platform-wide, read-only checks. Keep their YAML in this versioned
directory so a scanner image and every organization use the same reviewed
definitions. The scanner worker loads `backend/nuclei-templates/` through
`NUCLEI_CUSTOM_TEMPLATES_PATH` during Nuclei scans. Both backend Dockerfiles
copy this directory into the image.

| Template | Observation | Severity |
| --- | --- | --- |
| `mcp-2026-anonymous-tools-list` | Anonymous `tools/list` returned a catalog | Info |
| `mcp-2026-sensitive-tool-catalog` | The anonymous catalog includes a potentially powerful tool name | Medium, review required |
| `mcp-2025-anonymous-initialize` | A legacy HTTP endpoint accepted anonymous initialization | Info |

No template invokes a tool or reads a resource. A catalog or handshake is not
proof that `tools/call` is unauthorized. A protocol-aware follow-up using
assessor-owned canary data is needed to confirm impact. These templates check
the supplied URL plus `/mcp` and `/api/mcp` on the same host; custom paths and
legacy SSE-only servers require separate discovery coverage.

Organization-specific or analyst-generated templates belong in the existing
`custom_nuclei_templates` database table. Only active records are materialized
to `nuclei-templates-generated/org_<id>/` before a scan. Do not duplicate these
shared MCP templates into each organization's table.

Validate before release:

```sh
nuclei -validate -t backend/nuclei-templates/mcp -duc -ni
```
