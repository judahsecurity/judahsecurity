"""Best-effort graph projection for committed integration imports."""

import asyncio
import logging

logger = logging.getLogger(__name__)


async def sync_integration_assets_to_graph(
    organization_id: int, asset_values: set[str]
) -> None:
    """Sync touched assets after commit without changing the import outcome.

    API and scheduled runs share integration service functions, so callers do
    not need separate graph hooks. Neo4j is optional and runs off the event loop.
    """
    if not asset_values:
        return
    try:
        from app.services.graph_service import sync_organization_background

        result = await asyncio.to_thread(
            sync_organization_background, organization_id, sorted(asset_values)
        )
        if result.get("error"):
            logger.warning(
                "Integration graph sync failed for organization %s: %s",
                organization_id,
                result["error"],
            )
    except Exception:
        logger.exception("Integration graph sync failed for organization %s", organization_id)
