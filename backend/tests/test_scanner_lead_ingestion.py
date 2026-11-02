"""Scanner lead rows become coverage cells, not findings, and dedupe."""

from app.services.agent.tools import ASMToolsManager

TARGET = "https://app.example.test"


def _manager():
    manager = ASMToolsManager()
    manager._fallback_target = TARGET
    manager._capability_map = {"target": TARGET, "scope": TARGET}
    return manager


def test_sqlmap_lead_seeds_a_sql_injection_cell():
    manager = _manager()
    rows = [{"method": "GET", "url": TARGET + "/items.php", "name": "id",
             "location": "query", "source": "sqlmap_lead"}]
    created = manager._ingest_scanner_leads(rows)
    assert created > 0
    from app.services.agent.engagement_brain import engagement_brain_from_dict
    brain = engagement_brain_from_dict(manager._engagement_brain)
    sqli = [c for c in brain.coverage_cells
            if c.get("test_type") == "sqli" and c.get("path") == "/items.php"]
    assert sqli, "expected a sql_injection coverage cell from the sqlmap lead"
    # The row persists in the inventory for later passes.
    assert any(r.get("source") == "sqlmap_lead"
               for r in manager._capability_map["parameter_inventory"])


def test_ffuf_discovery_seeds_endpoint_cells():
    manager = _manager()
    rows = [{"method": "GET", "url": TARGET + "/api/accounts", "name": "endpoint",
             "location": "query", "source": "ffuf_discovery"}]
    created = manager._ingest_scanner_leads(rows)
    assert created > 0
    from app.services.agent.engagement_brain import engagement_brain_from_dict
    brain = engagement_brain_from_dict(manager._engagement_brain)
    # /api/ endpoints yield a cors endpoint cell among others.
    assert any(c.get("path") == "/api/accounts" and c.get("test_type") == "cors"
               for c in brain.coverage_cells)


def test_ingestion_is_idempotent():
    manager = _manager()
    rows = [{"method": "GET", "url": TARGET + "/items.php", "name": "id",
             "location": "query", "source": "sqlmap_lead"}]
    assert manager._ingest_scanner_leads(rows) > 0
    # Re-ingesting the same lead adds no new rows or cells.
    assert manager._ingest_scanner_leads(rows) == 0


def test_empty_rows_do_nothing():
    manager = _manager()
    assert manager._ingest_scanner_leads([]) == 0
    assert "parameter_inventory" not in manager._capability_map
