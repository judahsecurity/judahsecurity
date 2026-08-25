"""Passive homepage fingerprint — what any visitor's browser already receives.

Glasswing recon starts here: GET the URL, read generator meta, plugin HTML
comments, ``?ver=`` query strings, and Server headers. Versioned products are
hunt targets (and CVE-applicability evidence), not orientation-only labels.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse


# (canonical name, regex with one version group, evidence kind)
_NAMED_PATTERNS = (
    ("wordpress", re.compile(r'content=["\']WordPress\s+([\d.]+)', re.I), "generator_meta"),
    ("yoast seo", re.compile(r"Yoast SEO plugin v([\d.]+)", re.I), "html_comment"),
    ("woocommerce", re.compile(r"WooCommerce[^\d]{0,24}([\d.]+)", re.I), "html_comment"),
    ("elementor", re.compile(r"elementor(?:-frontend)?(?:\.min)?\.js[^\"']*[?&]ver=([\d.]+)", re.I), "script_ver"),
    ("contact form 7", re.compile(r"contact-form-7[^\"']*[?&]ver=([\d.]+)", re.I), "script_ver"),
    ("jetpack", re.compile(r"/jetpack[^\"']*[?&]ver=([\d.]+)", re.I), "script_ver"),
    ("akismet", re.compile(r"/akismet[^\"']*[?&]ver=([\d.]+)", re.I), "script_ver"),
)

_PLUGIN_VER_RE = re.compile(
    r"/wp-content/plugins/([a-z0-9\-]+)/[^\"'\s>]*[?&]ver=([\d.]+)",
    re.I,
)
_PLUGIN_PATH_RE = re.compile(r"/wp-content/plugins/([a-z0-9\-]+)/", re.I)
_SERVER_RE = re.compile(r"^(Apache|nginx|Microsoft-IIS|LiteSpeed)/([\d.]+)", re.I)
_WP_JSON_RE = re.compile(r"wp-json|/wp-includes/|wp-content|generator.*wordpress", re.I)

# Plugin directory slug → canonical product name
_SLUG_NAMES = {
    "wordpress-seo": "yoast seo",
    "woocommerce": "woocommerce",
    "elementor": "elementor",
    "contact-form-7": "contact form 7",
    "jetpack": "jetpack",
    "akismet": "akismet",
    "all-in-one-wp-migration": "all-in-one wp migration",
    "wordfence": "wordfence",
    "litespeed-cache": "litespeed cache",
    "wp-super-cache": "wp super cache",
}


def _add(
    products: List[Dict[str, str]],
    *,
    name: str,
    version: str = "",
    evidence: str = "",
    source: str = "",
) -> None:
    name = (name or "").strip().lower()
    version = (version or "").strip()
    if not name:
        return
    key = f"{name}|{version}"
    seen = {f"{p.get('name')}|{p.get('version') or ''}" for p in products}
    if key in seen:
        return
    # Prefer a versioned row over a duplicate unversioned one
    if version:
        products[:] = [
            p for p in products
            if not (p.get("name") == name and not p.get("version"))
        ]
    products.append({
        "name": name,
        "version": version,
        "evidence": (evidence or "")[:220],
        "source": source,
    })


def parse_passive_stack(
    html: str = "",
    headers: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, str]]:
    """Extract versioned (and unversioned WP/plugin) products from one response."""
    html = html or ""
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    products: List[Dict[str, str]] = []

    for name, rx, kind in _NAMED_PATTERNS:
        m = rx.search(html)
        if not m:
            continue
        snippet = m.group(0)
        _add(
            products,
            name=name,
            version=m.group(1),
            evidence=snippet[:180],
            source=kind,
        )

    for m in _PLUGIN_VER_RE.finditer(html):
        slug = m.group(1).lower()
        name = _SLUG_NAMES.get(slug, slug.replace("-", " "))
        _add(
            products,
            name=name,
            version=m.group(2),
            evidence=m.group(0)[:180],
            source="plugin_ver",
        )

    if _WP_JSON_RE.search(html) or "wp-json" in " ".join(headers.values()).lower():
        if not any(p.get("name") == "wordpress" for p in products):
            _add(products, name="wordpress", evidence="wp-json / wp-content markers", source="path")

    for m in _PLUGIN_PATH_RE.finditer(html):
        slug = m.group(1).lower()
        name = _SLUG_NAMES.get(slug, slug.replace("-", " "))
        if not any(p.get("name") == name for p in products):
            _add(products, name=name, evidence=m.group(0)[:120], source="plugin_path")

    server = headers.get("server") or ""
    sm = _SERVER_RE.match(server.strip())
    if sm:
        _add(
            products,
            name=sm.group(1).lower(),
            version=sm.group(2),
            evidence=server[:120],
            source="server_header",
        )
    elif server:
        _add(products, name=server.split("/")[0].lower(), evidence=server[:120], source="server_header")

    x_powered = headers.get("x-powered-by") or ""
    php = re.search(r"PHP/([\d.]+)", x_powered, re.I)
    if php:
        _add(products, name="php", version=php.group(1), evidence=x_powered[:120], source="x_powered_by")

    return products


def format_passive_stack(products: Iterable[Dict[str, str]]) -> str:
    rows = list(products or [])
    if not rows:
        return "  Passive stack: (none extracted from homepage HTML/headers)"
    lines = ["  Passive stack (homepage HTML/headers — Glasswing observe):"]
    for p in rows[:20]:
        ver = p.get("version") or "version unknown"
        src = p.get("source") or ""
        ev = p.get("evidence") or ""
        lines.append(
            f"    - {p.get('name')} {ver}"
            + (f" ({src})" if src else "")
            + (f" — {ev}" if ev else "")
        )
    return "\n".join(lines)


def versioned_products(products: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
    return [p for p in (products or []) if (p.get("version") or "").strip()]


def origin_from_url(url: str) -> str:
    text = (url or "").strip()
    if not text:
        return ""
    if not text.startswith(("http://", "https://")):
        text = f"https://{text}"
    parsed = urlparse(text.split()[0].rstrip(".,)"))
    if not parsed.netloc:
        return ""
    return f"{parsed.scheme or 'https'}://{parsed.netloc}".rstrip("/")
