"""API route package.

Route modules are intentionally imported by the application entrypoint instead
of eagerly here, so isolated workers and tests do not initialize every API
integration as a side effect of importing one route.
"""

__all__ = [
    "auth",
    "users", 
    "organizations",
    "assets",
    "vulnerabilities",
    "scans",
    "discovery",
    "nuclei",
    "ports",
    "screenshots",
    "external_discovery",
    "waybackurls",
    "pentest",
]
