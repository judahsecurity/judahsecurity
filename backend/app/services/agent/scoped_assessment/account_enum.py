"""Bounded account-enumeration proof on an observed lookup input.

Account enumeration requires a *controlled* existing account and a
guaranteed-nonexistent one, plus a difference that repeats. A single
nonexistent-account response is inconclusive (see ``proof_policy``).

This recipe sends four bounded, read-only requests to the same observed
endpoint, interleaving one operator-declared existing (controlled) value with
one synthetic absent value bound to this run's nonce:

    existing, absent, existing, absent

It confirms only when both existing responses agree on a value-free
discriminator, both absent responses agree, and the two differ — i.e. the
endpoint is a stable existence oracle. The absent value is nonce-bound and
never a real user identifier, so the recipe cannot spray live accounts.
"""

from __future__ import annotations

from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from urllib.request import Request, build_opener

from app.services.agent.assessment_proxy import assessment_urllib_handlers

from .browser import assert_in_scope
from .http_observe import _cookie_header, _NoRedirect

PROOF_RECIPE = "account_enum_differential_v1"
# A coarse body-size bucket tolerates small token jitter while still separating
# a full profile body from a short "unknown account" body. Any per-request
# volatility that is larger than the bucket breaks self-agreement and correctly
# yields an inconclusive result rather than a false positive.
_SIZE_BUCKET = 48


def absent_value(nonce: str) -> str:
    """A synthetic identifier bound to this run that cannot be a real account."""
    if not nonce or len(nonce) > 40 or not nonce.isalnum():
        raise ValueError("A bounded alphanumeric nonce is required")
    return f"aegis-enum-absent-{nonce}"


def _with_value(url: str, parameter: str, value: str) -> str:
    """Replace exactly the observed query parameter with a controlled value."""
    parts = urlsplit(url)
    query = parse_qs(parts.query, keep_blank_values=True)
    if parameter not in query:
        raise ValueError("Account-enum proof requires an observed query parameter")
    query[parameter] = [value]
    return urlunsplit(parts._replace(query=urlencode(query, doseq=True)))


def _discriminator(url: str, *, allowed_origin: str, state: dict | None) -> list[int]:
    """A value-free (status, size-bucket) signal for one bounded GET."""
    assert_in_scope(url, [allowed_origin])
    headers = {"Accept": "text/html, */*;q=0.8"}
    cookie = _cookie_header(state, url)
    if cookie:
        headers["Cookie"] = cookie
    opener = build_opener(*assessment_urllib_handlers(), _NoRedirect())
    try:
        response = opener.open(Request(url, headers=headers, method="GET"), timeout=15)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(65536) or b""
        return [int(response.status), len(body) // _SIZE_BUCKET]


def decide_differential(
    existing: list[list[int]], absent: list[list[int]]
) -> dict:
    """Pure decision over the four bounded observations.

    ``existing`` and ``absent`` each hold two discriminators. Confirmed only
    when each side is internally identical and the two sides differ.
    """
    existing_t = [tuple(item) for item in existing]
    absent_t = [tuple(item) for item in absent]
    existing_stable = len(set(existing_t)) == 1
    absent_stable = len(set(absent_t)) == 1
    differ = existing_stable and absent_stable and existing_t[0] != absent_t[0]
    return {
        "existing_discriminator": list(existing_t[0]) if existing_stable else None,
        "absent_discriminator": list(absent_t[0]) if absent_stable else None,
        "existing_stable": existing_stable,
        "absent_stable": absent_stable,
        "proof_confirmed": bool(differ),
    }


def probe_account_enum(
    url: str, *, parameter: str, existing_value: str, allowed_origin: str,
    state: dict | None, nonce: str,
) -> dict:
    """Prove a stable existence oracle with two controlled and two absent GETs."""
    if not existing_value or len(existing_value) > 120:
        raise ValueError("A controlled existing account value is required")
    absent = absent_value(nonce)
    existing_url = _with_value(url, parameter, existing_value)
    absent_url = _with_value(url, parameter, absent)
    # Interleave so transient server state cannot masquerade as the oracle.
    existing_obs = [
        _discriminator(existing_url, allowed_origin=allowed_origin, state=state),
        None,
    ]
    absent_obs = [
        _discriminator(absent_url, allowed_origin=allowed_origin, state=state),
        None,
    ]
    existing_obs[1] = _discriminator(existing_url, allowed_origin=allowed_origin, state=state)
    absent_obs[1] = _discriminator(absent_url, allowed_origin=allowed_origin, state=state)
    decision = decide_differential(existing_obs, absent_obs)
    return {
        "operation": "scoped_account_enum",
        "proof_recipe": PROOF_RECIPE,
        "parameter": parameter,
        "discriminator_kind": "status_size_bucket",
        "nonce": nonce,
        "requests_sent": 4,
        "existing_discriminator": decision["existing_discriminator"],
        "absent_discriminator": decision["absent_discriminator"],
        "existing_stable": decision["existing_stable"],
        "absent_stable": decision["absent_stable"],
        "proof_confirmed": decision["proof_confirmed"],
        "finding": False,  # One actor's proof is a candidate, never publication.
    }


def account_enum_proof_valid(row: dict) -> bool:
    """Shape and self-consistency check for one account-enum proof row."""
    if not isinstance(row, dict):
        return False
    if row.get("operation") != "scoped_account_enum":
        return False
    if row.get("proof_recipe") != PROOF_RECIPE:
        return False
    if row.get("requests_sent") != 4:
        return False
    existing = row.get("existing_discriminator")
    absent = row.get("absent_discriminator")
    if not (isinstance(existing, list) and isinstance(absent, list)):
        return False
    if len(existing) != 2 or len(absent) != 2:
        return False
    if not all(isinstance(value, int) for value in (*existing, *absent)):
        return False
    return (row.get("existing_stable") is True
            and row.get("absent_stable") is True
            and existing != absent
            and row.get("proof_confirmed") is True)
