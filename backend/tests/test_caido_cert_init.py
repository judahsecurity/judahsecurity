"""The optional Caido sidecar receives a stable CA without sharing its key."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL is unavailable")
def test_caido_ca_init_is_valid_private_and_idempotent(tmp_path):
    private = tmp_path / "private"
    public = tmp_path / "public"
    private.mkdir()
    public.mkdir()
    script = Path(__file__).parents[1] / "scripts" / "init_caido_ca.sh"
    environment = {
        **os.environ,
        "CAIDO_CA_PRIVATE_DIR": str(private),
        "CAIDO_CA_PUBLIC_DIR": str(public),
    }
    subprocess.run(["sh", str(script)], env=environment, check=True, capture_output=True)
    p12 = private / "ca.p12"
    certificate = public / "ca.crt"
    assert p12.is_file() and certificate.is_file()
    assert stat.S_IMODE(p12.stat().st_mode) == 0o600
    assert stat.S_IMODE(certificate.stat().st_mode) == 0o644
    subprocess.run(
        ["openssl", "pkcs12", "-in", str(p12), "-passin", "pass:", "-noout"],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["openssl", "verify", "-CAfile", str(certificate), str(certificate)],
        check=True, capture_output=True,
    )
    fingerprint = subprocess.check_output([
        "openssl", "x509", "-in", str(certificate), "-noout", "-fingerprint",
    ])
    subprocess.run(["sh", str(script)], env=environment, check=True, capture_output=True)
    assert fingerprint == subprocess.check_output([
        "openssl", "x509", "-in", str(certificate), "-noout", "-fingerprint",
    ])
