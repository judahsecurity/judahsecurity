"""Credential profiles and password vaults (HashiCorp Vault, AWS Secrets
Manager, CyberArk CCP), all against simulated services; network blocked."""

import json
import socket
from types import SimpleNamespace

import httpx
import pytest
from botocore.exceptions import ClientError

from app.services import host_evidence_service as hes
from app.services import secret_stores as ss


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("test attempted a real network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)


def store(provider, config, secret="", active=True, name="vault"):
    return SimpleNamespace(provider=provider, config=config, get_secret=lambda: secret, is_active=active, name=name)


@pytest.fixture
def http(monkeypatch):
    """Route secret-store HTTP to a handler; record client kwargs."""
    state = SimpleNamespace(handler=None, requests=[], client_kwargs=[])

    def handler(request):
        state.requests.append(request)
        return state.handler(request)

    def client(**kwargs):
        state.client_kwargs.append(kwargs)
        return httpx.Client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(ss, "_http_client", client)
    return state


# ── HashiCorp Vault ──────────────────────────────────────────────────────────

def test_vault_token_kv2(http):
    http.handler = lambda r: httpx.Response(200, json={"data": {"data": {"private_key": "PEM", "user": "x"}}})
    got = ss.fetch_secret(store("hashicorp_vault", {"address": "https://vault.corp:8200", "namespace": "infra"}, "s.tok"),
                          {"path": "judah/linux-prod", "key": "private_key"})
    assert got.secret == "PEM"
    req = http.requests[0]
    assert str(req.url) == "https://vault.corp:8200/v1/secret/data/judah/linux-prod"
    assert req.headers["X-Vault-Token"] == "s.tok" and req.headers["X-Vault-Namespace"] == "infra"


def test_vault_approle_kv1(http):
    def handler(r):
        if r.url.path == "/v1/auth/approle/login":
            assert json.loads(r.content) == {"role_id": "role-1", "secret_id": "sid"}
            return httpx.Response(200, json={"auth": {"client_token": "s.app"}})
        assert r.headers["X-Vault-Token"] == "s.app" and r.url.path == "/v1/kv/judah/win"
        return httpx.Response(200, json={"data": {"password": "pw"}})

    http.handler = handler
    cfg = {"address": "https://vault.corp", "auth_method": "approle", "role_id": "role-1", "kv_mount": "kv", "kv_version": "1"}
    assert ss.fetch_secret(store("hashicorp_vault", cfg, "sid"), {"path": "judah/win", "key": "password"}).secret == "pw"


def test_vault_errors_are_safe(http):
    http.handler = lambda r: httpx.Response(403, json={"errors": ["permission denied s.tok"]})
    with pytest.raises(ss.SecretStoreError) as e:
        ss.fetch_secret(store("hashicorp_vault", {"address": "https://vault.corp"}, "s.tok"), {"path": "a", "key": "k"})
    assert "access denied" in str(e.value) and "s.tok" not in str(e.value)

    http.handler = lambda r: httpx.Response(200, json={"data": {"data": {"a": "1", "b": "2"}}})
    with pytest.raises(ss.SecretStoreError, match="several fields"):
        ss.fetch_secret(store("hashicorp_vault", {"address": "https://vault.corp"}, "t"), {"path": "a"})
    with pytest.raises(ss.SecretStoreError, match="'missing' not found"):
        ss.fetch_secret(store("hashicorp_vault", {"address": "https://vault.corp"}, "t"), {"path": "a", "key": "missing"})
    with pytest.raises(ss.SecretStoreError, match="https"):
        ss.fetch_secret(store("hashicorp_vault", {"address": "http://vault.corp"}, "t"), {"path": "a", "key": "k"})
    for ref in ({"path": "../../sys/raw", "key": "k"}, {"path": "judah//x", "key": "k"}, {"path": "a", "key": "k?x"}):
        with pytest.raises(ss.SecretStoreError, match="unsupported characters"):
            ss.fetch_secret(store("hashicorp_vault", {"address": "https://vault.corp"}, "t"), ref)
    assert not [r for r in http.requests if "sys" in r.url.path]


def test_vault_connection_errors(http):
    def down(_r):
        raise httpx.ConnectError("refused")

    http.handler = down
    with pytest.raises(ss.SecretStoreError, match="could not connect"):
        ss.fetch_secret(store("hashicorp_vault", {"address": "https://vault.corp"}, "t"), {"path": "a", "key": "k"})


def test_vault_test_and_ca(http):
    http.handler = lambda r: httpx.Response(200, json={"data": {"policies": ["judah-read"]}})
    msg = ss.test_store(store("hashicorp_vault", {"address": "https://vault.corp", "ca_cert": "-----BEGIN CERTIFICATE-----"}, "t"))
    assert "judah-read" in msg
    verify = http.client_kwargs[0]["verify"]
    assert isinstance(verify, str) and verify.endswith(".pem")  # temp CA file, removed afterwards
    import os
    assert not os.path.exists(verify)


# ── AWS Secrets Manager ──────────────────────────────────────────────────────

class FakeAWS:
    def __init__(self, secrets=None, error=None):
        self.secrets, self.error, self.calls = secrets or {}, error, []

    def __call__(self, service, **kwargs):
        self.calls.append((service, kwargs))
        return self

    def get_secret_value(self, SecretId, VersionStage=None):
        if self.error:
            raise ClientError({"Error": {"Code": self.error, "Message": "arn:... secret text"}}, "GetSecretValue")
        return {"SecretString": self.secrets[SecretId]}

    def assume_role(self, **params):
        self.calls.append(("assume_role", params))
        return {"Credentials": {"AccessKeyId": "AKIA", "SecretAccessKey": "s", "SessionToken": "t"}}

    def get_caller_identity(self):
        return {"Arn": "arn:aws:sts::123456789012:assumed-role/judah/i-1"}


def test_aws_json_key_and_assume_role(monkeypatch):
    fake = FakeAWS({"judah/windows-prod": json.dumps({"username": "CORP\\svc", "password": "pw"})})
    monkeypatch.setattr(ss, "_boto3_client", fake)
    cfg = {"region": "us-east-1", "role_arn": "arn:aws:iam::123456789012:role/judah-read", "external_id": "ext-1"}
    got = ss.fetch_secret(store("aws_secrets_manager", cfg), {"secret_id": "judah/windows-prod", "key": "password"})
    assert got.secret == "pw"
    assume = [c for c in fake.calls if c[0] == "assume_role"][0][1]
    assert assume["ExternalId"] == "ext-1" and assume["RoleSessionName"] == "judah-host-evidence"
    sm = [c for c in fake.calls if c[0] == "secretsmanager"][0][1]
    assert sm["aws_session_token"] == "t" and sm["region_name"] == "us-east-1"


def test_aws_plain_string_and_errors(monkeypatch):
    monkeypatch.setattr(ss, "_boto3_client", FakeAWS({"plain": "just-a-password"}))
    assert ss.fetch_secret(store("aws_secrets_manager", {"region": "eu-west-2"}), {"secret_id": "plain"}).secret == "just-a-password"
    monkeypatch.setattr(ss, "_boto3_client", FakeAWS(error="AccessDeniedException"))
    with pytest.raises(ss.SecretStoreError) as e:
        ss.fetch_secret(store("aws_secrets_manager", {"region": "eu-west-2"}), {"secret_id": "x"})
    assert "AccessDeniedException" in str(e.value) and "secret text" not in str(e.value)
    with pytest.raises(ss.SecretStoreError, match="region"):
        ss.fetch_secret(store("aws_secrets_manager", {}), {"secret_id": "x"})
    with pytest.raises(ss.SecretStoreError, match="role ARN"):
        ss.fetch_secret(store("aws_secrets_manager", {"region": "us-east-1", "role_arn": "nope"}), {"secret_id": "x"})


def test_aws_test(monkeypatch):
    monkeypatch.setattr(ss, "_boto3_client", FakeAWS())
    assert "assumed-role/judah" in ss.test_store(store("aws_secrets_manager", {"region": "us-east-1"}))


# ── CyberArk CCP ─────────────────────────────────────────────────────────────

def test_cyberark_ccp_with_client_cert(http):
    def handler(r):
        assert r.url.path == "/AIMWebService/api/Accounts"
        assert dict(r.url.params) == {"AppID": "Judah", "Safe": "Linux-Servers", "Object": "judah-probe"}
        return httpx.Response(200, json={"Content": "pw", "UserName": "judah-probe", "Address": "10.20.1.12"})

    http.handler = handler
    cfg = {"url": "https://ccp.corp", "app_id": "Judah", "client_cert": "-----BEGIN CERTIFICATE-----"}
    got = ss.fetch_secret(store("cyberark_ccp", cfg, "-----BEGIN PRIVATE KEY-----"), {"safe": "Linux-Servers", "object": "judah-probe"})
    assert (got.secret, got.username) == ("pw", "judah-probe")
    cert = http.client_kwargs[0]["cert"]
    assert cert[0].endswith(".pem") and cert[1].endswith(".pem")


def test_cyberark_errors(http):
    http.handler = lambda r: httpx.Response(404, json={"ErrorCode": "APPAP004E", "ErrorMsg": "Password object not found"})
    with pytest.raises(ss.SecretStoreError, match="not found"):
        ss.fetch_secret(store("cyberark_ccp", {"url": "https://ccp.corp", "app_id": "Judah"}), {"safe": "S", "object": "O"})
    with pytest.raises(ss.SecretStoreError, match="together"):
        ss.fetch_secret(store("cyberark_ccp", {"url": "https://ccp.corp", "app_id": "Judah", "client_cert": "C"}), {"safe": "S", "object": "O"})
    assert "test a profile" in ss.test_store(store("cyberark_ccp", {"url": "https://ccp.corp", "app_id": "Judah"}))


def test_disabled_store_is_refused():
    with pytest.raises(ss.SecretStoreError, match="disabled"):
        ss.fetch_secret(store("hashicorp_vault", {"address": "https://v"}, "t", active=False), {"path": "a"})


# ── Profiles through host checks and the API ─────────────────────────────────

@pytest.fixture()
def db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.db.database import Base
    import app.models  # noqa: F401 — registers every model
    from app.models.api_config import APIConfig
    from app.models.asset import Asset
    from app.models.host_credential import HostCredentialProfile, HostSecretStore
    from app.models.netblock import Netblock
    from app.models.organization import Organization

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[Organization.__table__, Netblock.__table__, Asset.__table__,
                                             APIConfig.__table__, HostSecretStore.__table__, HostCredentialProfile.__table__])
    s = sessionmaker(bind=engine)()
    s.add_all([Organization(id=1, name="Acme"), Organization(id=2, name="Other")])
    s.commit()
    yield s
    s.close()


@pytest.fixture()
def client(db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.deps import get_db, require_admin, require_analyst
    from app.api.routes import host_credentials

    state = SimpleNamespace(user=SimpleNamespace(role=SimpleNamespace(value="admin"), organization_id=1))
    app = FastAPI()
    app.include_router(host_credentials.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_admin] = lambda: state.user
    app.dependency_overrides[require_analyst] = lambda: state.user
    c = TestClient(app)
    c.state = state
    return c


def test_profile_crud_never_returns_secrets(client):
    r = client.post("/host-credentials/profiles", json={
        "name": "linux-dmz", "kind": "ssh", "username": "judah-probe", "secret": "-----BEGIN OPENSSH PRIVATE KEY-----x",
        "targets": ["10.20.0.0/16", "*.dmz.corp.example"], "priority": 10,
        "options": {"known_hosts": "10.20.1.12 ssh-ed25519 AAAA", "sudo": True}})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["has_secret"] and "secret" not in body and "secret_encrypted" not in body
    assert "PRIVATE KEY" not in r.text
    pid = body["id"]
    r = client.put(f"/host-credentials/profiles/{pid}", json={"priority": 5, "targets": ["10.20.1.0/24"]})
    assert r.json()["priority"] == 5 and r.json()["targets"] == ["10.20.1.0/24"] and r.json()["has_secret"]
    listed = client.get("/host-credentials").json()
    assert [p["name"] for p in listed["profiles"]] == ["linux-dmz"] and "PRIVATE KEY" not in json.dumps(listed)
    assert client.delete(f"/host-credentials/profiles/{pid}").status_code == 204


@pytest.mark.parametrize("targets,detail", [
    (["*"], "CIDR or a hostname"), (["0.0.0.0/0"], "too broad"), (["10.0.0.0/7"], "too broad"),
    ([""], "at least one target"), (["bad host!"], "CIDR or a hostname"),
])
def test_profile_targets_are_validated(client, targets, detail):
    r = client.post("/host-credentials/profiles", json={"name": "x", "kind": "ssh", "username": "u", "secret": "s",
                                                        "targets": targets})
    assert r.status_code == 422 and detail in r.text


def test_profile_validation(client):
    base = {"name": "x", "kind": "winrm", "username": "u", "secret": "s", "targets": ["10.40.0.0/16"]}
    assert "unsupported winrm options" in client.post("/host-credentials/profiles", json={**base, "options": {"sudo": True}}).text
    assert "transport" in client.post("/host-credentials/profiles", json={**base, "options": {"transport": "basic"}}).text
    assert "password or private key" in client.post("/host-credentials/profiles", json={**base, "secret": None}).text
    assert "choose the secret store" in client.post("/host-credentials/profiles", json={**base, "secret_source": "store"}).text
    assert client.post("/host-credentials/profiles", json=base).status_code == 201
    assert client.post("/host-credentials/profiles", json=base).status_code == 409


def test_stores_and_vault_backed_profile(client, http):
    r = client.post("/host-credentials/stores", json={"name": "corp-vault", "provider": "hashicorp_vault",
                                                      "config": {"address": "https://vault.corp", "auth_method": "token"},
                                                      "secret": "s.tok"})
    assert r.status_code == 201 and r.json()["has_secret"] and "s.tok" not in r.text
    sid = r.json()["id"]
    assert "unsupported settings" in client.post("/host-credentials/stores", json={
        "name": "v2", "provider": "hashicorp_vault", "config": {"address": "https://v", "token": "x"}}).text
    assert "https://" in client.post("/host-credentials/stores", json={
        "name": "v3", "provider": "cyberark_ccp", "config": {"url": "http://ccp", "app_id": "J"}}).text
    assert "certificate" in client.post("/host-credentials/stores", json={
        "name": "v4", "provider": "cyberark_ccp", "config": {"url": "https://ccp", "app_id": "J", "client_cert": "-----BEGIN PRIVATE KEY-----"}}).text

    prof = {"name": "windows-prod", "kind": "winrm", "username": "CORP\\svc-judah", "secret_source": "store",
            "secret_store_id": sid, "secret_ref": {"path": "judah/windows", "key": "password"}, "targets": ["10.40.0.0/16"]}
    assert "secret reference needs: path" in client.post("/host-credentials/profiles", json={**prof, "secret_ref": {}}).text
    r = client.post("/host-credentials/profiles", json=prof)
    assert r.status_code == 201 and r.json()["secret_store_name"] == "corp-vault"
    pid = r.json()["id"]
    assert client.delete(f"/host-credentials/stores/{sid}").status_code == 409

    http.handler = lambda req: httpx.Response(200, json={"data": {"data": {"password": "pw"}}})
    r = client.post(f"/host-credentials/profiles/{pid}/test")
    assert r.json() == {"ok": True, "message": "Fetched the credential for 'CORP\\\\svc-judah' from corp-vault."}

    http.handler = lambda req: httpx.Response(403)
    r = client.post(f"/host-credentials/profiles/{pid}/test").json()
    assert not r["ok"] and "access denied" in r["message"]
    assert client.get("/host-credentials").json()["profiles"][0]["last_test_ok"] is False

    http.handler = lambda req: httpx.Response(200, json={"data": {"policies": ["judah"]}})
    assert client.post(f"/host-credentials/stores/{sid}/test").json()["ok"]


def test_profile_test_can_log_in_to_one_in_scope_asset(client, db, monkeypatch):
    from app.api.routes import host_credentials
    from app.models.asset import Asset, AssetType

    a = Asset(name="lnx", value="lnx-web-12", asset_type=AssetType.IP_ADDRESS, organization_id=1, ip_address="10.20.1.12")
    out = Asset(name="out", value="partner", asset_type=AssetType.IP_ADDRESS, organization_id=1, ip_address="192.0.2.9")
    db.add_all([a, out])
    db.commit()
    pid = client.post("/host-credentials/profiles", json={"name": "l", "kind": "ssh", "username": "u", "secret": "s",
                                                          "targets": ["10.20.0.0/16"]}).json()["id"]
    logins = []

    class Runner(hes.CommandRunner):
        def __init__(self, asset, cred):
            logins.append((asset.ip_address, cred.username, cred.secret))

    monkeypatch.setattr(host_credentials, "_runner_for", lambda asset, cred: Runner(asset, cred))
    r = client.post(f"/host-credentials/profiles/{pid}/test", json={"asset_id": a.id}).json()
    assert r["ok"] and "Logged in to 10.20.1.12" in r["message"] and logins == [("10.20.1.12", "u", "s")]
    assert client.post(f"/host-credentials/profiles/{pid}/test", json={"asset_id": out.id}).status_code == 400


def test_orgs_are_isolated(client):
    pid = client.post("/host-credentials/profiles", json={"name": "a", "kind": "ssh", "username": "u", "secret": "s",
                                                          "targets": ["10.0.0.0/8"]}).json()["id"]
    client.state.user = SimpleNamespace(role=SimpleNamespace(value="admin"), organization_id=2)
    assert client.get("/host-credentials").json()["profiles"] == []
    assert client.put(f"/host-credentials/profiles/{pid}", json={"priority": 1}).status_code == 404
    assert client.post(f"/host-credentials/profiles/{pid}/test").status_code == 404


def test_vault_failure_during_a_host_check_is_could_not_check(db, http):
    from app.models.host_credential import HostCredentialProfile, HostSecretStore

    st = HostSecretStore(organization_id=1, name="corp-vault", provider="hashicorp_vault", config={"address": "https://vault.corp"})
    st.set_secret("s.tok")
    db.add(st)
    db.flush()
    db.add(HostCredentialProfile(organization_id=1, name="linux", kind="ssh", username="u", secret_source="store",
                                 secret_store_id=st.id, secret_ref={"path": "p", "key": "k"}, targets=["10.20.0.0/16"]))
    db.commit()
    creds = hes.load_credentials(db, 1)
    assert [c.name for c in creds] == ["linux"] and creds[0].secret == ""  # not fetched while listing
    assert http.requests == []
    http.handler = lambda req: httpx.Response(503)
    asset = SimpleNamespace(id=1, value="lnx", ip_address="10.20.1.12", metadata_={})
    record = hes.collect_host_facts(asset, creds[0], runner_factory=lambda *a: pytest.fail("must not log in"))
    assert "could not fetch the credential for profile 'linux'" in record["error"] and "HTTP 503" in record["error"]
