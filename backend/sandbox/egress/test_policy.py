"""Egress policy unit tests. Run: python -m pytest backend/sandbox/egress."""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from policy import SessionScope, address_allowed, decide, host_in_scope  # noqa: E402


def scope(**kw):
    return SessionScope.from_dict({"hosts": ["app.test", "172.18.0.3"], **kw})


def test_host_scope_matches_exact_and_oob_suffix():
    s = scope(oob_suffixes=["oast.pro"])
    assert host_in_scope("app.test", s)
    assert host_in_scope("abc.oast.pro", s)
    assert not host_in_scope("evil.test", s)
    assert not host_in_scope("notapp.test", s)
    assert not host_in_scope("localhost", s)


def test_only_scoped_private_ip_is_allowed():
    s = scope()
    assert address_allowed("8.8.8.8", s)          # public
    assert address_allowed("172.18.0.3", s)       # scoped lab IP
    assert not address_allowed("172.18.0.9", s)   # other private IP
    assert not address_allowed("127.0.0.1", s)
    assert not address_allowed("169.254.169.254", s)


def test_metadata_is_denied_even_if_someone_scopes_it():
    s = SessionScope.from_dict({"hosts": ["169.254.169.254"]})
    assert "169.254.169.254" not in s.private_ips
    assert not address_allowed("169.254.169.254", s)


def test_ipv4_mapped_loopback_is_denied():
    assert not address_allowed("::ffff:127.0.0.1", scope())


def test_decide_rejects_rebinding_to_private_address():
    # Host is in scope but resolves to an internal address.
    d = decide(scheme="http", host="app.test", port=80, resolved=["10.0.0.5"],
               scope=scope(), requests_used=0)
    assert not d.allowed and "non-public" in d.reason


def test_decide_rejects_mixed_resolution():
    d = decide(scheme="https", host="app.test", port=443,
               resolved=["8.8.8.8", "127.0.0.1"], scope=scope(), requests_used=0)
    assert not d.allowed


def test_decide_enforces_scheme_scope_and_budget():
    s = scope(max_requests=3)
    assert decide(scheme="https", host="app.test", port=443, resolved=["8.8.8.8"],
                  scope=s, requests_used=0).allowed
    assert not decide(scheme="ftp", host="app.test", port=21, resolved=["8.8.8.8"],
                      scope=s, requests_used=0).allowed
    assert not decide(scheme="https", host="evil.test", port=443, resolved=["8.8.8.8"],
                      scope=s, requests_used=0).allowed
    assert not decide(scheme="https", host="app.test", port=443, resolved=["8.8.8.8"],
                      scope=s, requests_used=3).allowed
    assert not decide(scheme="https", host="app.test", port=443, resolved=[],
                      scope=s, requests_used=0).allowed


def test_decide_without_a_session_denies():
    d = decide(scheme="https", host="app.test", port=443, resolved=["8.8.8.8"],
               scope=None, requests_used=0)
    assert not d.allowed
