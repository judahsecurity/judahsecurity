from app.services.totp_service import generate_totp, normalize_totp_secret


def test_rfc6238_vector():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert generate_totp(secret, at_time=59, digits=8) == "94287082"


def test_accepts_otpauth_uri():
    uri = "otpauth://totp/Judah:test?secret=JBSWY3DPEHPK3PXP&issuer=Judah"
    assert normalize_totp_secret(uri) == "JBSWY3DPEHPK3PXP"
    assert len(generate_totp(uri, at_time=0)) == 6
