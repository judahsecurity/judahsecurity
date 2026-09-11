import asyncio

from app.services.deep_crawl_service import CrawlResult, _perform_login


class _Handle:
    def __init__(self, page, kind):
        self.page = page
        self.kind = kind

    async def is_visible(self):
        return True

    async def fill(self, value):
        self.page.values[self.kind] = value

    async def click(self, timeout=None):
        if self.page.stage == "login":
            self.page.stage = "mfa"
            self.page.url = "https://app.test/mfa"
        elif self.page.stage == "mfa":
            self.page.stage = "dashboard"
            self.page.url = "https://app.test/dashboard"

    async def press(self, key):
        await self.click()


class _MfaPage:
    def __init__(self):
        self.stage = "login"
        self.url = "https://app.test/login"
        self.values = {}
        self.handles = {
            name: _Handle(self, name)
            for name in ("username", "password", "totp", "submit")
        }

    async def goto(self, url, wait_until=None, timeout=None):
        self.url = url

    async def wait_for_load_state(self, state, timeout=None):
        return None

    async def query_selector_all(self, selector):
        if self.stage == "login":
            if "password" in selector:
                return [self.handles["password"]]
            if any(word in selector for word in ("email", "username", 'type="text"')):
                return [self.handles["username"]]
            if "button" in selector or "submit" in selector:
                return [self.handles["submit"]]
        if self.stage == "mfa":
            if any(word in selector.lower() for word in ("one-time", "totp", "otp", "verification", "code")):
                return [self.handles["totp"]]
            if "button" in selector or "submit" in selector:
                return [self.handles["submit"]]
        return []

    async def query_selector(self, selector):
        values = await self.query_selector_all(selector)
        return values[0] if values else None


def test_login_completes_totp_challenge():
    page = _MfaPage()
    result = CrawlResult()
    ok = asyncio.run(_perform_login(page, {
        "url": "https://app.test/login",
        "username": "scanner@app.test",
        "password": "password",
        "totp_secret": "JBSWY3DPEHPK3PXP",
        "success_url": "/dashboard",
    }, 1000, result))

    assert ok is True
    assert page.values["username"] == "scanner@app.test"
    assert page.values["password"] == "password"
    assert page.values["totp"].isdigit()
    assert len(page.values["totp"]) == 6
    assert result.errors == []


def test_login_fails_closed_when_mfa_secret_is_missing():
    page = _MfaPage()
    result = CrawlResult()
    ok = asyncio.run(_perform_login(page, {
        "url": "https://app.test/login",
        "username": "scanner@app.test",
        "password": "password",
    }, 1000, result))

    assert ok is False
    assert "no TOTP secret" in result.errors[-1]
