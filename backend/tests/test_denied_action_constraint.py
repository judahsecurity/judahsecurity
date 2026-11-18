"""A denied action becomes a durable brain constraint (do not re-propose)."""

from app.services.agent.engagement_brain import engagement_brain_from_dict
from app.services.agent.tools import ASMToolsManager


def _manager():
    mgr = ASMToolsManager.__new__(ASMToolsManager)  # skip heavy __init__
    mgr._engagement_brain = None
    return mgr


def test_policy_denial_recorded_once():
    mgr = _manager()
    args = {"target": "https://app.example.test"}
    mgr._record_denied_action("execute_nuclei", args, "blocked by policy", "policy_denied")
    brain = engagement_brain_from_dict(mgr._engagement_brain)
    denied = [a for a in brain.approaches if a.result == "policy_denied"]
    assert len(denied) == 1
    assert denied[0].technique == "execute_nuclei"
    assert denied[0].target == "https://app.example.test"
    # dedup: an identical denial is not re-logged
    mgr._record_denied_action("execute_nuclei", args, "blocked by policy", "policy_denied")
    brain = engagement_brain_from_dict(mgr._engagement_brain)
    assert len([a for a in brain.approaches if a.result == "policy_denied"]) == 1


def test_operator_denial_distinct_target_logged():
    mgr = _manager()
    mgr._record_denied_action("execute_sqlmap", {"url": "https://a.test"}, "no", "operator_denied")
    mgr._record_denied_action("execute_sqlmap", {"url": "https://b.test"}, "no", "operator_denied")
    brain = engagement_brain_from_dict(mgr._engagement_brain)
    assert len([a for a in brain.approaches if a.result == "operator_denied"]) == 2
