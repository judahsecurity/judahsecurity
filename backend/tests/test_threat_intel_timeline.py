from datetime import datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.models.custom_nuclei_template import CustomNucleiTemplate
from app.services.threat_intel_timeline import (
    build_cve_timeline,
    first_party_detection_events,
    order_and_dedupe,
    resolve_organization_id,
)


class _Query:
    def __init__(self, entity, templates):
        self.entity = entity
        self.templates = templates

    def filter(self, *args):
        return self

    def join(self, *args):
        return self

    def order_by(self, *args):
        return self

    def all(self):
        return self.templates if self.entity is CustomNucleiTemplate else []

    def first(self):
        return None


class _Session:
    def __init__(self, templates):
        self.templates = templates

    def query(self, entity):
        return _Query(entity, self.templates)


def test_timeline_has_stable_ids_dedupes_and_orders_same_timestamp():
    catalog = {
        "nvd": {
            "published": "2024-01-01T00:00:00Z",
            "last_modified": "2024-01-01T00:00:00Z",
        }
    }
    first = build_cve_timeline("CVE-2024-1234", catalog, {})
    second = build_cve_timeline("CVE-2024-1234", catalog, {})
    assert [event["id"] for event in first["exploitation_timeline"]] == [
        event["id"] for event in second["exploitation_timeline"]
    ]
    assert [event["kind"] for event in first["exploitation_timeline"]] == [
        "cve_published",
        "cve_modified",
    ]
    duplicated = order_and_dedupe(first["intel_updates"] + first["intel_updates"])
    assert len(duplicated["intel_updates"]) == 2


def test_deadline_is_not_reported_as_observed_exploitation():
    timeline = build_cve_timeline(
        "CVE-2024-1234",
        {},
        {"cisa": {"dateAdded": "2024-02-01", "dueDate": "2024-02-20"}},
    )["exploitation_timeline"]
    deadline = next(event for event in timeline if event["kind"] == "remediation_due")
    observed = next(event for event in timeline if event["kind"] == "known_exploited_added")
    assert deadline["deadline"] is True
    assert deadline["category"] == "deadline"
    assert observed["deadline"] is False
    assert observed["category"] == "exploitation"


def test_nuclei_events_expose_safe_provenance_not_yaml_or_paths():
    template = CustomNucleiTemplate(
        id=7,
        organization_id=42,
        template_id="judah-cve-2024-1234",
        name="CVE-2024-1234 detector",
        template_yaml="id: secret\nhttp:\n  - path: /private",
        cve_ids=["CVE-2024-1234"],
        source="manual",
        created_at=datetime(2024, 1, 2),
        released_at=datetime(2024, 1, 3),
        enabled_at=datetime(2024, 1, 4),
    )
    events = first_party_detection_events(_Session([template]), "CVE-2024-1234", 42)
    assert [event["kind"] for event in events] == [
        "detection_authored",
        "detection_available",
        "detection_enabled",
    ]
    rendered = str(events)
    assert "id: secret" not in rendered
    assert "/private" not in rendered
    assert events[0]["metadata"]["content_digest"].startswith("sha256:")
    assert events[0]["metadata"]["reference"] == "/nuclei-templates/7"
    assert all(event["scope"] == "organization" for event in events)


def test_missing_dates_are_omitted_instead_of_invented():
    timeline = build_cve_timeline(
        "CVE-2024-1234",
        {"nvd": {"published": None}, "exploit_sources": {"github_repos": {"repos": [{"url": "https://example.test/poc"}]}}},
        {"cisa": {"knownRansomwareCampaignUse": "Known"}},
    )
    assert timeline == {"intel_updates": [], "exploitation_timeline": []}


def test_non_superuser_cannot_select_another_tenant():
    user = SimpleNamespace(is_superuser=False, organization_id=42)
    assert resolve_organization_id(user, None) == 42
    assert resolve_organization_id(user, 42) == 42
    with pytest.raises(HTTPException) as exc:
        resolve_organization_id(user, 99)
    assert exc.value.status_code == 403


def test_superuser_may_explicitly_select_tenant_or_global_view():
    user = SimpleNamespace(is_superuser=True, organization_id=None)
    assert resolve_organization_id(user, 99) == 99
    assert resolve_organization_id(user, None) is None
