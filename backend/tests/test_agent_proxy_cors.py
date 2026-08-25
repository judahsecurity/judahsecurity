"""Production agent chat needs CORS + nginx WS that actually upgrades."""

from pathlib import Path

from app.core.config import settings


ROOT = Path(__file__).resolve().parents[2]
NGINX = ROOT / "nginx" / "templates" / "app.conf.template"


def test_cors_allowlist_includes_theforcesecurity_https():
    assert "https://aegis.theforcesecurity.io" in settings.CORS_ORIGINS
    assert "https://aegis.judahsecurity.io" in settings.CORS_ORIGINS


def test_cors_origin_regex_covers_aegis_theforcesecurity():
    import re

    rx = re.compile(settings.CORS_ORIGIN_REGEX)
    assert rx.fullmatch("https://aegis.theforcesecurity.io")
    assert rx.fullmatch("https://aegis.judahsecurity.io")
    assert rx.fullmatch("https://www.aegis.theforcesecurity.io")
    assert not rx.fullmatch("http://aegis.theforcesecurity.io")
    assert not rx.fullmatch("https://eviltheforcesecurity.io")


def test_nginx_websocket_uses_non_keepalive_upstream():
    text = NGINX.read_text()
    assert "upstream asm_backend_ws" in text
    assert "proxy_pass http://asm_backend_ws;" in text
    api_block = text.split("location /api/ {", 1)[1].split("location ", 1)[0]
    assert "proxy_set_header Upgrade" not in api_block
    assert 'proxy_set_header Connection "";' in api_block
