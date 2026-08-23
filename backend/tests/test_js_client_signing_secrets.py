"""CWE-321 Object.keys-join HMAC / MQTT / RFID detection in public JS bundles."""

from __future__ import annotations

from app.services.js_client_signing_secrets import (
    analyze_js_client_secrets,
    summarize_client_signing_findings,
)
from app.services.js_url_secrets_service import DEFAULT_MAX_BYTES
from app.services.agent.engagement_brain import (
    classify_finding_type,
    engagement_brain_from_dict,
    queue_followups_for_finding,
)
from app.services.agent.methodology_catalog import methodologies_from_capability_map


# Minified iLens/Angular shape from the UnifyTwin-class finding (property names
# concatenate to the secret; the literal never appears as a string).
ILENS_BUNDLE = (
    'u.N={mqttPath:"/mqtt"},u.wasteName={b:"",is:"",w:"",a:"",j:"",it:""},'
    'u.gatewayPass={a:"",d:"",m:"",in:""},u.SSLBooleanValues={0:!1,1:!0},'
    'ws://":"wss://",path:o.N.mqttPath,userName:Object.keys(u.wasteName).join(""),'
    'password:Object.keys(u.gatewayPass).join(""),useSSL:u.SSLBooleanValues[s],'
    'rfidUserName:"admin",rfidPassword:"admin123"},APPS:["p/oee/summary/apps"],'
    'topics:["hmi/live_tags"],SCADA:"digital-twin";'
    'this.waste={k:"",li:"",Lens:"",KLiL:"",e:"",nsK:"",L:""},this.serviceParams={};'
    'passSignature(n))return e;const i=Object.keys(this.waste).join(""),'
    'o=crypto_js.enc.Utf8.parse(JSON.stringify({alg:"HS256",typ:"JWT"})),'
    'u=crypto_js.HmacSHA256(l,i);return u=this.base64url(u),l+"."+u;'
    'for(const t in this.waste)e+=t;return e}getSessionKey(){const e=this.returnK();'
)


def test_max_bytes_covers_angular_main_bundles():
    assert DEFAULT_MAX_BYTES >= 16 * 1024 * 1024


def test_ilens_waste_object_reconstructs_hmac_key():
    hits = analyze_js_client_secrets(ILENS_BUNDLE, source_url="https://example.test/main-es2015.js")
    hmac = [h for h in hits if h["kind"] == "hmac_signing_key"]
    assert hmac, hits
    rec = hmac[0]["reconstructed"]
    assert rec == "kliLensKLiLensKL"
    assert hmac[0]["cwe"] == "CWE-321"
    assert hmac[0]["severity"] == "critical"
    assert hmac[0]["joined_in_bundle"] is True
    assert any("HmacSHA256" in u or "HS256" in u for u in hmac[0]["usage"])


def test_ilens_mqtt_and_rfid_credentials():
    hits = analyze_js_client_secrets(ILENS_BUNDLE)
    creds = {h["reconstructed"]: h for h in hits if h["kind"] in {"obfuscated_credential", "plaintext_ics_credential"}}
    assert "biswajit" in creds
    assert "admin" in creds  # gatewayPass a+d+m+in and/or rfid username
    assert any(h.get("reconstructed") == "admin123" for h in hits)
    mqtt_user = next(h for h in hits if h["reconstructed"] == "biswajit")
    assert mqtt_user["cwe"] == "CWE-798"
    assert mqtt_user["kind"] == "obfuscated_credential"


def test_allows_critical_ra_hmac_not_couchdb():
    from app.services.js_client_signing_secrets import allows_critical_ra

    assert allows_critical_ra(
        "CWE-321 HMAC-SHA256 signing key Object.keys join in public JS bundle"
    )
    assert not allows_critical_ra(
        "AuthSession cookie base64 username hex_timestamp hmac using secret"
    )
    hits = analyze_js_client_secrets(ILENS_BUNDLE)
    summary = summarize_client_signing_findings(hits)
    assert summary["hmac_key_demonstrated"] is True
    assert summary["ics_creds_demonstrated"] is True
    assert summary["submit_without_live_api"] is True
    assert summary["cwe"] == "CWE-321"


def test_gitleaks_would_miss_the_literal():
    # The signing key must not appear as a quoted string — that is the point of the obfuscation.
    assert '"kliLensKLiLensKL"' not in ILENS_BUNDLE
    assert "'kliLensKLiLensKL'" not in ILENS_BUNDLE
    assert "kliLensKLiLensKL" not in ILENS_BUNDLE  # only exists after join of keys


def test_env_encryption_key_is_separate_critical_hit():
    from app.services.js_client_signing_secrets import (
        analyze_js_client_secrets,
        allows_critical_ra,
        coerce_js_secret_severity,
        summarize_client_signing_findings,
    )

    bundle = (
        'const env={production:!0,emailjs_userid:"43nmA_Fhe-yfIFXQK",'
        'emailjs_templateid:"template_cz6vvkl",emailjs_serviceid:"service_lizebi6",'
        'encryption_key:"x!A%D*G-KaPdSgVkYp3s6v8y/B?E(H+MbQeThWmZq4t7w!z$C&F)J@NcRfUjXn2r"}'
    )
    hits = analyze_js_client_secrets(bundle, source_url="https://estart.example.com/main.js")
    enc = [h for h in hits if h["kind"] == "client_encryption_key"]
    assert enc, hits
    assert enc[0]["cwe"] == "CWE-321"
    assert enc[0]["severity"] == "critical"
    assert enc[0]["reconstructed"].startswith("x!A%")
    summary = summarize_client_signing_findings(hits)
    assert summary["encryption_key_demonstrated"] is True
    assert summary["submit_without_live_api"] is True
    assert coerce_js_secret_severity(
        "Exploitable EmailJS Service Credentials",
        "Hardcoded EmailJS keys in the production JS bundle",
        "api.emailjs.com 200 OK",
        "high",
    ) == "critical"
    assert coerce_js_secret_severity(
        "Client encryption_key in JavaScript bundle",
        "Symmetric key in the public env object",
        "encryption_key in main.js",
        "high",
    ) == "critical"
    assert allows_critical_ra(
        "EmailJS service_lizebi6 template_cz6vvkl browser canary send from client JS"
    )
    assert allows_critical_ra(
        "Client encryption_key in a public JavaScript env object next to EmailJS"
    )
    assert analyze_js_client_secrets('encryption_key:"YOUR_KEY_PLACEHOLDER_XX"') == []



def test_empty_config_object_without_join_is_ignored():
    benign = 'this.config={timeout:"",retry:"",debug:"",mode:""};export default this.config;'
    assert analyze_js_client_secrets(benign) == []


def test_unrelated_object_keys_join_comma_is_ignored():
    benign = 'const names=Object.keys(this.headers).join(",");fetch(url,{headers:this.headers});'
    assert analyze_js_client_secrets(benign) == []


def test_js_files_seed_hmac_methodology():
    cmap = {
        "target": "https://glens.example.com",
        "has_admin": False,
        "has_login_form": False,
        "pages_visited": ["https://glens.example.com/"],
        "forms": [],
        "api_endpoints": [],
        "js_files": ["https://glens.example.com/main-es2015.abc123.js"],
        "js_endpoints": [],
        "websockets": [],
        "sse": [],
        "source_maps": [],
        "param_rich_paths": [],
        "api_samples": [],
    }
    methods = methodologies_from_capability_map(cmap)
    ids = {m.id for m in methods}
    assert "js_client_hmac_signing" in ids
    assert "js_client_encryption_key" in ids
    card = next(m for m in methods if m.id == "js_client_hmac_signing")
    assert "CWE-321" in card.cwe_ids
    assert "timeout is not a kill" in card.test.lower() or "timeout is" in card.test.lower()


def test_hmac_finding_queues_signing_and_mqtt_cards():
    brain = engagement_brain_from_dict(None)
    created = queue_followups_for_finding(
        brain,
        vuln_type="js_secrets",
        title="Hardcoded HMAC-SHA256 signing key in client JS (CWE-321)",
        target="https://glens.example.com",
        evidence=(
            "Object.keys(this.waste).join('') reconstructs HMAC key; "
            "HmacSHA256 alg HS256; mqttPath rfidPassword SCADA hmi/live_tags"
        ),
    )
    titles = " ".join(h.title.lower() for h in created)
    tests = " ".join(h.test.lower() for h in created)
    assert "hmac" in titles or "signing" in titles
    assert "mqtt" in titles or "rfid" in titles
    assert "timeout is not a kill" in tests or "not a kill" in tests
    assert not any("hostname-keyed" in h.title.lower() for h in created)
    assert not any("emailjs" in h.title.lower() for h in created)
    assert not any("encryption_key" in h.title.lower() for h in created)


def test_oauth_js_secrets_still_skips_hmac_cards():
    brain = engagement_brain_from_dict(None)
    created = queue_followups_for_finding(
        brain,
        vuln_type="js_secrets",
        title="Hardcoded API credentials in Next.js chunk",
        target="https://sandbox-admin.example.com",
        evidence="client_id: " + ("a" * 32) + " / client_secret: " + ("b" * 32),
    )
    assert not any("hmac" in h.title.lower() for h in created)
    assert not any("mqtt" in h.title.lower() for h in created)


def test_classify_hmac_title_as_js_secrets():
    assert classify_finding_type(title="Hardcoded HMAC-SHA256 Signing Key (CWE-321)") == "js_secrets"
    assert classify_finding_type(title="MQTT broker credentials in Angular bundle") == "js_secrets"
