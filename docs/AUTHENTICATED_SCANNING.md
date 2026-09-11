# Authenticated scanning with MFA

Autonomous pentests can crawl and test application routes that require a login.
In **Autonomous Pentest → New Pentest**, provide the login URL, dedicated scanner
username and password. If the account uses an authenticator app, also provide
its Base32 TOTP secret or an `otpauth://` setup URI.

At scan start Judah:

1. decrypts the credentials only in the scanner process;
2. submits the username and password in an isolated Chromium context;
3. detects a visible TOTP challenge and generates a fresh RFC 6238 code;
4. verifies that credential and MFA fields are gone (or checks the configured
   success URL/selector);
5. crawls the authenticated surface and reuses that browser state for later
   browser-based tests.

If configured authentication cannot be verified, the pentest stops before
testing. It does not silently continue as an anonymous scan.

## Operational guidance

- Use a dedicated, non-human scanner account for each application and role.
- Treat the TOTP setup secret like a password. Judah encrypts passwords and
  TOTP secrets at rest with `API_KEY_ENCRYPTION_KEY` (falling back to the
  deployment `SECRET_KEY`) and never returns them through the pentest API.
- TOTP is supported for unattended scans. SMS codes, email codes, security
  keys, CAPTCHAs, and push approvals require a human-assisted session and are
  not automated.
- Keep scanner and application hosts time-synchronized. Standard TOTP uses a
  30-second period and six digits.

## API-only selector overrides

Most login forms are detected automatically. Custom applications can send
these optional fields inside `auth_config`: `username_selector`,
`password_selector`, `submit_selector`, `totp_selector`,
`totp_submit_selector`, `success_url`, and `success_selector`. Nonstandard TOTP
implementations may also set `totp_digits` (6–8) and `totp_period` (15–120
seconds).
