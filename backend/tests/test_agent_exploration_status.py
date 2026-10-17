"""Browser exploration is visible without leaking URL values or page text."""

from app.services.agent.exploration_status import project_exploration


def test_exploration_summary_counts_safe_actions_and_redacts_values():
    summary = project_exploration({
        "scope": "https://app.example",
        "pages_visited": [
            "https://app.example/", "https://app.example/products?session=private",
            "https://other.example/offscope",
        ],
        "forms": [{"action": "https://app.example/search", "inputs": ["term"]}],
        "discovered_links": [{"url": "https://app.example/products"}],
        "action_checkpoints": [
            {"kind": "navigate", "path": "/", "status": "completed", "request_count": 3},
            {"kind": "tab", "after_path": "/products?session=private",
             "status": "completed", "request_count": 2, "label": "Private customer text"},
        ],
    })
    assert summary["page_paths"] == ["/", "/products"]
    assert summary["pages_observed"] == 2
    assert summary["safe_interactions"] == 1
    assert summary["forms_observed"] == 1
    assert "private" not in str(summary)
    assert "offscope" not in str(summary)
