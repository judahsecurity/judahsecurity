"""Judah Gate certificate authority.

Judah Gate terminates TLS from local assessment tools so it can see, pace and
count each request, then opens its own verified TLS connection to the target.
Tools trust the Gate through this private CA.

* The CA and one shared leaf key are created on first use under
  ``JUDAH_GATE_CA_DIR`` (default ``$AEGIS_DATA_DIR/judah-gate`` or
  ``/app/data/judah-gate``), private keys mode 0600.
* Every per-host leaf certificate uses the same key, so Chromium can be told
  to trust exactly that key with ``--ignore-certificate-errors-spki-list``
  instead of ignoring certificate errors in general.
* Leaf certificates are short-lived (30 days) and cached per host.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import os
import ssl
import threading
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_LOCK = threading.Lock()
_CTX_CACHE: dict[str, ssl.SSLContext] = {}


def ca_dir() -> Path:
    explicit = os.environ.get("JUDAH_GATE_CA_DIR", "").strip()
    if explicit:
        return Path(explicit)
    base = os.environ.get("AEGIS_DATA_DIR", "").strip() or "/app/data"
    return Path(base) / "judah-gate"


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _load_or_create_key(path: Path) -> ec.EllipticCurvePrivateKey:
    if path.is_file():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    _write_private(path, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    return key


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def ensure_ca(directory: Optional[Path] = None) -> tuple[Path, Path]:
    """Return ``(ca_cert_path, leaf_key_path)``, creating them once."""
    directory = directory or ca_dir()
    cert_path = directory / "judah-gate-ca.pem"
    key_path = directory / "judah-gate-ca.key"
    leaf_key_path = directory / "judah-gate-leaf.key"
    with _LOCK:
        ca_key = _load_or_create_key(key_path)
        _load_or_create_key(leaf_key_path)
        if not cert_path.is_file():
            name = x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Judah Security"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Judah Gate local CA"),
            ])
            cert = (
                x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(_now() - dt.timedelta(days=1))
                .not_valid_after(_now() + dt.timedelta(days=825))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False, data_encipherment=False,
                    key_agreement=False, encipher_only=False, decipher_only=False,
                ), critical=True)
                .sign(ca_key, hashes.SHA256())
            )
            cert_path.parent.mkdir(parents=True, exist_ok=True)
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, leaf_key_path


def ca_cert_path() -> Path:
    return ensure_ca()[0]


def leaf_spki_sha256(directory: Optional[Path] = None) -> str:
    """Base64 SHA-256 of the shared leaf key's SubjectPublicKeyInfo (for Chromium)."""
    _, leaf_key_path = ensure_ca(directory)
    key = serialization.load_pem_private_key(leaf_key_path.read_bytes(), password=None)
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(hashlib.sha256(spki).digest()).decode()


def _leaf_cert(host: str, directory: Path) -> Path:
    cert_path, leaf_key_path = ensure_ca(directory)
    digest = hashlib.sha256(host.encode()).hexdigest()[:24]
    out = directory / "leaves" / f"{digest}.pem"
    if out.is_file():
        cert = x509.load_pem_x509_certificate(out.read_bytes())
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(
            tzinfo=dt.timezone.utc)
        if not_after - _now() > dt.timedelta(days=2):
            return out
    ca_key = serialization.load_pem_private_key((directory / "judah-gate-ca.key").read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    leaf_key = serialization.load_pem_private_key(leaf_key_path.read_bytes(), password=None)
    try:
        san = x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(host))])
    except ValueError:
        san = x509.SubjectAlternativeName([x509.DNSName(host)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(hours=1))
        .not_valid_after(_now() + dt.timedelta(days=30))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return out


def server_context(host: str, directory: Optional[Path] = None) -> ssl.SSLContext:
    """TLS context the Gate presents to a local tool for ``host``."""
    host = host.lower().strip("[]")
    directory = directory or ca_dir()
    key = f"{directory}|{host}"
    with _LOCK:
        cached = _CTX_CACHE.get(key)
    if cached is not None:
        return cached
    leaf = _leaf_cert(host, directory)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(leaf), str(directory / "judah-gate-leaf.key"))
    ctx.set_alpn_protocols(["http/1.1"])
    with _LOCK:
        _CTX_CACHE[key] = ctx
    return ctx


__all__ = ["ca_cert_path", "ca_dir", "ensure_ca", "leaf_spki_sha256", "server_context"]
