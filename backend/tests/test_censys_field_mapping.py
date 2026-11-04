"""Contract tests for the configurable Censys ASM field mapper."""

import unittest
from types import SimpleNamespace

from app.services.censys_field_mapping import (
    apply_mapped_values,
    extract_path,
    mapped_values,
    sample_fields,
    validate_rules,
)


class CensysFieldMappingTests(unittest.TestCase):
    def test_nested_fields_and_custom_metadata_apply_to_existing_row(self):
        rules = validate_rules([
            {"entity": "host", "source_path": "host.operating_system.product", "target": "operating_system"},
            {"entity": "host", "source_path": "host.autonomous_system.asn", "target": "asn"},
            {"entity": "host", "source_path": "host.services[0].service_name", "target": "custom.first_service"},
        ])
        source = {"host": {"operating_system": {"product": "Linux"},
                           "autonomous_system": {"asn": 12345},
                           "services": [{"service_name": "HTTPS"}]}}
        fields, custom = mapped_values(source, "host", rules)
        row = SimpleNamespace(operating_system=None, asn=None, metadata_={"owner": "Rockwell"})
        apply_mapped_values(row, fields, custom)
        self.assertEqual(row.operating_system, "Linux")
        self.assertEqual(row.asn, "12345")
        self.assertEqual(row.metadata_["censys_asm"]["custom"]["first_service"], "HTTPS")
        self.assertEqual(row.metadata_["owner"], "Rockwell")

    def test_rejects_identity_and_unsafe_paths(self):
        for target in ("organization_id", "asset_id", "detected_by", "metadata_"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_rules([{"entity": "risk", "source_path": "severity", "target": target}])
        for source in ("__class__", "foo..bar", "foo[9999]", "foo;bar"):
            with self.subTest(source=source), self.assertRaises(ValueError):
                validate_rules([{"entity": "host", "source_path": source, "target": "asn"}])

    def test_missing_and_invalid_values_do_not_overwrite_existing_fields(self):
        rules = validate_rules([
            {"entity": "risk", "source_path": "cvss", "target": "cvss_score"},
            {"entity": "risk", "source_path": "seen", "target": "last_detected"},
        ])
        fields, custom = mapped_values({"cvss": "bad", "seen": None}, "risk", rules)
        row = SimpleNamespace(cvss_score=7.2, metadata_={})
        apply_mapped_values(row, fields, custom)
        self.assertEqual(row.cvss_score, 7.2)
        self.assertEqual(fields, {})

    def test_sample_paths_match_extractor(self):
        record = {"host": {"services": [{"port": 443}]}}
        paths = [item["path"] for item in sample_fields(record)]
        self.assertIn("host.services[0].port", paths)
        self.assertEqual(extract_path(record, "host.services[0].port"), 443)


if __name__ == "__main__":
    unittest.main()
