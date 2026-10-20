"""Background enrichment should not repeat a completed worker in one session."""

from unittest.mock import AsyncMock

import pytest

from app.services.agent import recon_workers


@pytest.mark.asyncio
async def test_completed_enrichment_is_not_started_again(monkeypatch):
    worker_body = AsyncMock(return_value="completed")
    monkeypatch.setattr(recon_workers, "_worker_body", worker_body)
    monkeypatch.setattr(recon_workers, "_emit", AsyncMock())
    from app.services.agent import action_ledger
    monkeypatch.setattr(action_ledger, "append_action", lambda *_args, **_kwargs: None)

    session_id = "dedupe-completed-enrichment"
    target = "https://app.example.test"
    first = await recon_workers.spawn_workers(
        url=target, session_id=session_id, kinds=["ferox_dirs"],
        tools_manager=object(),
    )
    assert len(first) == 1
    await recon_workers.wait_workers(session_id, timeout_sec=2)
    assert worker_body.await_count == 1

    repeated = await recon_workers.spawn_workers(
        url=target, session_id=session_id, kinds=["ferox_dirs"],
        tools_manager=object(),
    )
    assert repeated == []
    assert worker_body.await_count == 1
