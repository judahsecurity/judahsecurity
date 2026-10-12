"""Keep browser assets out of executable web operation and input queues."""

from __future__ import annotations

import re
from urllib.parse import urlsplit


_ASSET_SUFFIX = re.compile(
    r"\.(?:css|js|mjs|map|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|otf|"
    r"mp[34]|webm|avif|bmp)$",
    re.IGNORECASE,
)


def is_static_asset(value: object) -> bool:
    """Match a path suffix even when a cache-busting query is present."""
    return bool(_ASSET_SUFFIX.search(urlsplit(str(value or "")).path))
