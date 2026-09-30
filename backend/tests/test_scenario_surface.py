"""The external map shows observed inputs without leaking URL values."""

import unittest

from app.services.agent.scenario_surface import project_scenario_surface


class ScenarioSurfaceTests(unittest.TestCase):
    def test_login_observation_links_sql_injection_hypothesis_without_query_values(self):
        surface = project_scenario_surface(
            {
                "target": "https://example.test/?session=private-value",
                "pages_visited": ["https://example.test/login?redirect=%2Faccount&token=private-value"],
                "forms": [{"page": "https://example.test/login", "method": "POST",
                           "inputs": ["username", "password"]}],
                "api_endpoints": [{"host": "example.test", "method": "POST",
                                   "path": "/api/login?next=/account"}],
            },
            {"hypotheses": [{"id": "login-sqli", "target": "https://example.test",
                             "evidence": "https://example.test/login", "parameter": "username"}]},
        )

        self.assertEqual(surface["target"], "https://example.test")
        self.assertGreaterEqual(
            {item["label"] for item in surface["items"] if item["kind"] == "parameter"},
            {"username", "password", "redirect", "token", "next"},
        )
        self.assertEqual(surface["contexts"], [
            {"id": "login-sqli", "origin": "https://example.test",
             "path": "/login", "parameter": "username"},
        ])
        self.assertNotIn("private-value", str(surface))
        self.assertNotIn("/account", str(surface))

    def test_unobserved_hypothesis_evidence_does_not_create_a_surface(self):
        surface = project_scenario_surface(
            {"target": "https://example.test", "pages_visited": ["https://example.test/login"]},
            {"hypotheses": [{"id": "claim", "target": "https://example.test",
                             "evidence": "https://example.test/internal/admin"}]},
        )

        self.assertEqual(surface["contexts"][0]["path"], "/")
        self.assertTrue(all(item["path"] != "/internal/admin" for item in surface["items"]))


if __name__ == "__main__":
    unittest.main()
