"""Multi-identity IDOR/BOLA differential oracle — verdict logic."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import scanners


class _Resp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text


class _FakeClient:
    """Maps (url, identity-marker) -> _Resp based on the Cookie header."""
    def __init__(self, table):
        self.table = table

    def __enter__(self): return self
    def __exit__(self, *a): return False

    def request(self, method, url, headers=None, content=None):
        cookie = (headers or {}).get("Cookie", "anon")
        who = "A" if "A" in cookie else ("B" if "B" in cookie else "anon")
        return self.table[(url, who)]


def _patch_httpx(monkeypatch, table):
    import httpx
    monkeypatch.setattr(httpx, "Client", lambda *a, **k: _FakeClient(table))


def test_confirmed_idor(monkeypatch):
    owner_body = "Order #55 owner=bob total=$4000 addr=123 Main St ......................"
    url = "https://app.example.com/api/orders/55"
    table = {
        (url, "B"): _Resp(200, owner_body),        # owner sees own order
        (url, "A"): _Resp(200, owner_body),        # attacker ALSO sees bob's order
        (url, "anon"): _Resp(401, "unauthorized"), # anon denied
    }
    _patch_httpx(monkeypatch, table)
    out = scanners.run_idor_probe(url, '{"Cookie":"session=B"}', '{"Cookie":"session=A"}')
    assert out["summary"]["idor"] == 1
    assert out["results"][0]["verdict"] == "idor"


def test_isolated(monkeypatch):
    url = "https://app.example.com/api/orders/55"
    table = {
        (url, "B"): _Resp(200, "Order #55 owner=bob ...................................."),
        (url, "A"): _Resp(403, "forbidden"),
        (url, "anon"): _Resp(401, "unauthorized"),
    }
    _patch_httpx(monkeypatch, table)
    out = scanners.run_idor_probe(url, '{"Cookie":"session=B"}', '{"Cookie":"session=A"}')
    assert out["results"][0]["verdict"] == "isolated"


def test_missing_authentication(monkeypatch):
    body = "Order #55 owner=bob total=$4000 addr=123 Main St ......................"
    url = "https://app.example.com/api/orders/55"
    table = {
        (url, "B"): _Resp(200, body),
        (url, "A"): _Resp(200, body),
        (url, "anon"): _Resp(200, body),  # served with NO auth at all
    }
    _patch_httpx(monkeypatch, table)
    out = scanners.run_idor_probe(url, '{"Cookie":"session=B"}', '{"Cookie":"session=A"}')
    assert out["results"][0]["verdict"] == "missing_authentication"


def test_bad_headers_rejected():
    out = scanners.run_idor_probe("https://x.example.com/a", "", '{"Cookie":"A"}')
    assert "error" in out
