import json
import pytest

from app.services.agent.js_intelligence import JSIntelligence


@pytest.mark.asyncio
async def test_inline_external_chunks_maps_and_budgets():
    token = "ghp_" + "x" * 36
    fixtures = {
        "https://app.test/": '<html><script>featureFlags.admin; localStorage.getItem("prefs"); const q="query Orders { orders { id } }";</script><script src="/app.js"></script></html>',
        "https://app.test/app.js": f'import("./chunk.js"); const api="/api/orders"; const ws="wss://app.test/ws"; const token="{token}"; //# sourceMappingURL=app.js.map',
        "https://app.test/chunk.js": 'const hidden="http://admin.internal/api"; import("https://cdn.test/other.js");',
        "https://app.test/app.js.map": json.dumps(
            {"sourcesContent": ['const route="/v1/private";']}
        ),
    }
    calls = []

    async def fetch(url):
        calls.append(url)
        return {
            "_body_text": fixtures[url],
            "response": {"status": 200},
            "evidence_id": url,
        }

    engine = JSIntelligence()
    result = await engine.collect("https://app.test/", fetch=fetch)
    text = json.dumps(result)
    assert len(calls) == 4 and "https://cdn.test/other.js" not in calls
    assert "/api/orders" in text and "/v1/private" in text and "Orders" in text
    assert "prefs" in text and "admin.internal" in text
    assert token not in text and "not_validated" in text
    assert result["gaps"]
    candidate = next(c for c in engine.candidates.values() if c.provider == "github")
    assert token not in repr(candidate)
    blocked = await engine.validate(
        candidate.id, enabled=False, allowed_providers=["github"]
    )
    assert blocked["validation"] == "blocked"


@pytest.mark.asyncio
async def test_validation_requires_opt_in_provider_hook_and_evidence_never_finding():
    engine = JSIntelligence()
    engine.extract("app.js", 'const x="ghp_' + "x" * 36 + '"')
    cid = next(iter(engine.candidates))

    async def validator(value):
        return {"status": "valid"}

    engine.validators["github"] = validator
    result = await engine.validate(cid, enabled=True, allowed_providers=["github"])
    assert result["validation"] == "inconclusive" and result["finding"] is False

    async def with_evidence(value):
        return {"status": "valid", "evidence_id": "provider-receipt"}

    engine.validators["github"] = with_evidence
    result = await engine.validate(cid, enabled=True, allowed_providers=["github"])
    assert result["validation"] == "valid" and result["finding"] is False
