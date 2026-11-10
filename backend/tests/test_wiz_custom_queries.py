"""Custom Wiz GraphQL pulls: script parsing, read-only guard, paging and storage."""

import asyncio
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.wiz_custom_query import WizCustomQuery, WizCustomQueryRecord  # noqa: E402
from app.models.wiz_integration import WizIntegration  # noqa: E402
from app.services import wiz_custom_query_service as svc  # noqa: E402
from app.services.wiz_service import WizClient  # noqa: E402

# Shape of the script Wiz's "Copy as Python" produces (trimmed).
ENDPOINTS_SCRIPT = '''
"""
# Python 3.9+
pip(3) install requests
"""
import requests

CLIENT_ID = "SERVICE_ACCOUNT_CLIENT_ID"
QUERY = """
    query ApplicationEndpointsTable($first: Int, $after: String, $filterBy: ApplicationEndpointFilters) {
      applicationEndpoints(first: $first, after: $after, filterBy: $filterBy) {
        nodes { id host port }
        pageInfo { endCursor hasNextPage }
      }
    }
"""
VARIABLES = {
  "fetchTotalCount": False,
  "first": 20,
  "filterBy": {},
  "after": "eyJmaWVsZHMiOltdfQ=="
}

def main():
    raise SystemExit("must never run")
'''

PREFERENCES_MUTATION = """
    mutation UpdateUserPreferences($input: UpdateUIUserPreferencesInput!) {
      updateUIUserPreferences(input: $input) { preferences { preferences } }
    }
"""


def test_parse_python_script_extracts_query_and_variables_without_running_it():
    parsed = svc.parse_python_script(ENDPOINTS_SCRIPT)
    assert parsed["query"].startswith("query ApplicationEndpointsTable")
    assert parsed["variables"]["first"] == 20
    assert parsed["variables"]["fetchTotalCount"] is False


@pytest.mark.parametrize(
    "script, message",
    [
        ("VARIABLES = {}", "No QUERY"),
        ("QUERY = build()", "literal"),
        ("QUERY = 'query { a }'\nVARIABLES = [1]", "dictionary"),
        ("def (", "Could not parse"),
    ],
)
def test_parse_python_script_errors(script, message):
    with pytest.raises(svc.WizQueryError, match=message):
        svc.parse_python_script(script)


def test_mutations_and_subscriptions_are_rejected():
    with pytest.raises(svc.WizQueryError, match="mutation"):
        svc.validate_query(PREFERENCES_MUTATION)
    with pytest.raises(svc.WizQueryError):
        svc.validate_query("subscription { events { id } }")
    with pytest.raises(svc.WizQueryError):
        svc.validate_query("query A { a { id } }\nmutation B { b }")


def test_read_queries_pass_even_when_fields_mention_mutation():
    query = 'query Q { issues(filterBy: {search: "mutation"}) { nodes { mutationCount } } }'
    assert svc.validate_query(query) == query
    assert svc.validate_query("{ applicationEndpoints { nodes { id } } }")


def test_page_variables_replace_a_cursor_copied_from_the_browser():
    query = svc.parse_python_script(ENDPOINTS_SCRIPT)["query"]
    variables = {"first": 20, "after": "stale-cursor", "filterBy": {"x": 1}}
    first = svc.page_variables(query, variables, 100, None)
    assert first == {"first": 100, "after": None, "filterBy": {"x": 1}}
    assert variables["after"] == "stale-cursor"  # caller's copy untouched
    assert svc.page_variables(query, variables, 100, "c2")["after"] == "c2"


def test_find_connection_auto_detects_nested_connections():
    data = {"graphSearch": {"totalCount": 3, "nodes": [{"id": 1}], "pageInfo": {}}}
    assert svc.find_connection(data)[0] == "graphSearch"
    data = {"viewer": {"things": {"edges": [{"node": {"id": 1}}], "pageInfo": {}}}}
    path, connection = svc.find_connection(data)
    assert path == "viewer.things"
    assert svc._connection_nodes(connection) == [{"id": 1}]
    with pytest.raises(svc.WizQueryError):
        svc.find_connection({"x": {"y": 1}})


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("lively-wave-0320a3e1e.4.azurestaticapps.net", ("lively-wave-0320a3e1e.4.azurestaticapps.net", AssetType.SUBDOMAIN, None)),
        ("https://Example.com:443/x", ("example.com", AssetType.DOMAIN, "https://Example.com:443/x")),
        ("10.1.2.3", ("10.1.2.3", AssetType.IP_ADDRESS, None)),
        ("not a host", None),
        ({"name": "x"}, None),
        (None, None),
    ],
)
def test_host_normalization(raw, expected):
    assert svc._host_and_type(raw) == expected


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            WizIntegration.__table__,
            Asset.__table__,
            WizCustomQuery.__table__,
            WizCustomQueryRecord.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Acme"))
    session.add(
        WizIntegration(
            id=1,
            organization_id=1,
            connection_name="prod",
            api_endpoint="https://api.us17.app.wiz.io/graphql",
            client_id_encrypted="x",
            client_secret_encrypted="x",
        )
    )
    session.commit()
    yield session
    session.close()


def _page(nodes, cursor=None):
    return {
        "applicationEndpoints": {
            "nodes": nodes,
            "pageInfo": {"hasNextPage": cursor is not None, "endCursor": cursor},
        }
    }


def _query(db, **overrides):
    parsed = svc.parse_python_script(ENDPOINTS_SCRIPT)
    fields = {
        "organization_id": 1,
        "integration_id": 1,
        "name": "Endpoints",
        "query": parsed["query"],
        "variables": parsed["variables"],
        "page_size": 2,
        "max_pages": 10,
        "asset_host_field": "host",
        **overrides,
    }
    cq = WizCustomQuery(**fields)
    db.add(cq)
    db.commit()
    return cq


def _client(*pages):
    client = WizClient("https://api.us17.app.wiz.io/graphql", "id", "secret")
    client.graphql = AsyncMock(side_effect=list(pages))
    return client


def test_sync_pages_stores_records_and_imports_hosts(db):
    cq = _query(db)
    client = _client(
        _page([{"id": "e1", "host": "lively-wave-0320a3e1e.4.azurestaticapps.net", "port": 443},
               {"id": "e2", "host": "api.acme.com", "port": 8443}], "c1"),
        _page([{"id": "e3", "host": "", "port": 22}]),
    )

    result = asyncio.run(svc.sync_custom_query(db, cq, client=client))

    assert result["ok"] is True, result
    assert result["rows_seen"] == 3 and result["records_created"] == 3 and result["pages"] == 2
    assert result["assets_created"] == 2
    calls = client.graphql.await_args_list
    assert calls[0].args[1]["after"] is None and calls[0].args[1]["first"] == 2
    assert calls[1].args[1]["after"] == "c1"
    asset = db.query(Asset).filter_by(value="lively-wave-0320a3e1e.4.azurestaticapps.net").one()
    assert asset.asset_type == AssetType.SUBDOMAIN and "source:wiz" in asset.tags
    record = db.query(WizCustomQueryRecord).filter_by(external_id="e1").one()
    assert record.asset_id == asset.id and record.data["port"] == 443
    assert db.query(WizCustomQueryRecord).filter_by(external_id="e3").one().asset_id is None
    assert cq.connection_path == "applicationEndpoints" and cq.last_run_ok is True


def test_resync_marks_rows_no_longer_returned(db):
    cq = _query(db, asset_host_field=None)
    asyncio.run(svc.sync_custom_query(db, cq, client=_client(_page([{"id": "a"}, {"id": "b"}]))))
    result = asyncio.run(svc.sync_custom_query(db, cq, client=_client(_page([{"id": "b", "v": 2}]))))

    assert result["records_gone"] == 1 and result["records_updated"] == 1
    assert db.query(WizCustomQueryRecord).filter_by(external_id="a").one().is_present is False
    assert db.query(WizCustomQueryRecord).filter_by(external_id="b").one().data == {"id": "b", "v": 2}


def test_truncated_run_does_not_mark_rows_gone(db):
    cq = _query(db, asset_host_field=None)
    asyncio.run(svc.sync_custom_query(db, cq, client=_client(_page([{"id": "a"}, {"id": "b"}]))))
    cq.max_pages = 1
    db.commit()
    result = asyncio.run(svc.sync_custom_query(db, cq, client=_client(_page([{"id": "b"}], "more"))))

    assert result["ok"] is True and result["records_gone"] == 0
    assert "page limit" in cq.last_error
    assert db.query(WizCustomQueryRecord).filter_by(external_id="a").one().is_present is True


def test_stored_mutation_is_never_sent(db):
    cq = _query(db, asset_host_field=None)
    cq.query = PREFERENCES_MUTATION
    db.commit()
    client = _client()

    result = asyncio.run(svc.sync_custom_query(db, cq, client=client))

    assert result["ok"] is False and "mutation" in result["message"]
    client.graphql.assert_not_awaited()
    assert cq.last_run_ok is False


def _graph_page(rows, cursor=None):
    return {
        "graphSearch": {
            "maxCountReached": False,
            "nodes": rows,
            "pageInfo": {"hasNextPage": cursor is not None, "endCursor": cursor},
        }
    }


def _graph_row(endpoint_id, name, port, vm_id, updated="2026-11-10"):
    return {
        "entities": [
            {"id": endpoint_id, "name": name, "type": "ENDPOINT",
             "properties": {"port": port, "portValidationResult": "Open", "updatedAt": updated}},
            {"id": vm_id, "name": "vm-1", "type": "VIRTUAL_MACHINE", "properties": {"cloudPlatform": "Azure"}},
        ]
    }


def test_critical_ports_template_is_a_valid_paginating_read_query():
    template = next(t for t in svc.TEMPLATES if t["key"] == "critical_ports")
    query = svc.validate_query(template["query"])
    variables = svc.page_variables(query, template["variables"], 500, None)
    assert variables["quick"] is False and variables["after"] is None and variables["first"] == 500
    assert variables["projectId"] == "*"
    assert 3389 in variables["query"]["where"]["port"]["EQUALS"]


def test_graph_search_rows_get_stable_ids_and_host_assets(db):
    template = next(t for t in svc.TEMPLATES if t["key"] == "critical_ports")
    cq = WizCustomQuery(
        organization_id=1, integration_id=1, name="Critical ports", query=template["query"],
        variables=template["variables"], page_size=1, max_pages=10,
        asset_host_field=template["asset_host_field"],
    )
    db.add(cq)
    db.commit()
    client = _client(
        _graph_page([_graph_row("ep1", "20.30.40.50:3389", 3389, "vm1")], "c1"),
        _graph_page([_graph_row("ep2", "db.acme.com:5432", 5432, "vm2")]),
    )
    first = asyncio.run(svc.sync_custom_query(db, cq, client=client))
    assert first["ok"] and first["records_created"] == 2 and first["assets_created"] == 2
    assert client.graphql.await_args_list[1].args[1]["quick"] is False
    assert db.query(Asset).filter_by(value="20.30.40.50").one().asset_type == AssetType.IP_ADDRESS
    assert db.query(WizCustomQueryRecord).filter_by(external_id="graph:ep1|vm1").one().asset_id

    # Same rows with changed properties must update, not churn into new rows.
    again = asyncio.run(svc.sync_custom_query(db, cq, client=_client(
        _graph_page([_graph_row("ep1", "20.30.40.50:3389", 3389, "vm1", updated="2026-11-11"),
                     _graph_row("ep2", "db.acme.com:5432", 5432, "vm2", updated="2026-11-11")]),
    )))
    assert again["records_created"] == 0 and again["records_updated"] == 2 and again["records_gone"] == 0


def test_preview_fields_walk_into_lists():
    fields = svc._field_paths([_graph_row("ep1", "h:22", 22, "vm1")])
    assert "entities.0.name" in fields and "entities.0.properties.port" in fields
