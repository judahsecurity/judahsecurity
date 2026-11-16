"""Small, deliberately vulnerable local targets for product-agent class runs.

Run one class/polarity per process. Never expose this fixture beyond loopback.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
from email import policy
from email.parser import BytesParser
import html
import json
import posixpath
import re
import secrets
import socket
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CLASSES = ("sqli", "sqli_encoded", "sqli_post_blind", "xss", "xss_dom", "xss_post_xhr", "ssrf", "idor",
           "graphql_authz", "unsafe_file_upload", "csrf", "ssti", "command_injection", "path_traversal", "jwt")

# --- SSTI: a toy template engine. Only small integer products are evaluated. ---
_TEMPLATE_EXPRESSIONS = (
    re.compile(r"\{\{\s*(\d{1,9})\s*\*\s*(\d{1,9})\s*\}\}"),   # Jinja2 / Twig
    re.compile(r"\$\{\s*(\d{1,9})\s*\*\s*(\d{1,9})\s*\}"),      # FreeMarker / EL
    re.compile(r"#\{\s*(\d{1,9})\s*\*\s*(\d{1,9})\s*\}"),        # Ruby / Pug
    re.compile(r"<%=\s*(\d{1,9})\s*\*\s*(\d{1,9})\s*%>"),         # ERB
)


def render_toy_template(value: str) -> str:
    """Evaluate ``{{a*b}}``-style arithmetic the way a vulnerable engine would."""
    for pattern in _TEMPLATE_EXPRESSIONS:
        value = pattern.sub(lambda m: str(int(m.group(1)) * int(m.group(2))), value)
    return value


# --- Command injection: shell semantics simulated in pure Python. ---
# Nothing here ever reaches a real shell, subprocess, or the network.
_SUBSTITUTION = re.compile(r"\$\((?!\()((?:[^()]|\(\([^()]*\)\))*)\)|`([^`]*)`")
_SEPARATOR = re.compile(r"\|\||&&|[;|&\n]")
_EXPR = re.compile(r"""expr\s+(\d{1,9})\s*(\\\*|'\*'|"\*"|\*|\+|-)\s*(\d{1,9})""")
_ARITH = re.compile(r"\$\(\(\s*(\d{1,9})\s*([*+-])\s*(\d{1,9})\s*\)\)")
_SAFE_HOST = re.compile(r"[A-Za-z0-9.-]{1,253}")


def _arith(a: str, op: str, b: str) -> str:
    left, right = int(a), int(b)
    return str(left * right if "*" in op else left + right if op == "+" else left - right)


def _simulate_command(command: str) -> str:
    command = _ARITH.sub(lambda m: _arith(*m.groups()), command.strip())
    if not command:
        return ""
    match = _EXPR.fullmatch(command)
    if match:
        return _arith(*match.groups())
    if command == "echo" or command.startswith("echo "):
        return command[5:].strip().strip("'\"")
    if command in {"id", "whoami"}:
        return "uid=33(www-data) gid=33(www-data) groups=33(www-data)" if command == "id" else "www-data"
    return f"sh: 1: {command.split()[0]}: not found"


def _ping_output(host: str) -> str:
    return (f"PING {host} ({host}): 56 data bytes\n"
            f"icmp_seq=0 ttl=64 time=0.042 ms\n--- {host} ping statistics ---\n"
            "packets transmitted: one, received: one, packet loss: none\n")


def simulate_ping_shell(host: str) -> str:
    """Model ``sh -c "ping -c 1 " + host`` without running anything."""
    host = _SUBSTITUTION.sub(lambda m: _simulate_command(m.group(1) or m.group(2) or ""), host)
    host = _ARITH.sub(lambda m: _arith(*m.groups()), host)
    first, *rest = _SEPARATOR.split(host)
    output = [_ping_output(first.strip()) if first.strip() else "ping: usage error: Destination address required\n"]
    output.extend(_simulate_command(command) + "\n" for command in rest if command.strip())
    return "".join(output)


# --- Path traversal: an in-memory filesystem. The real filesystem is never read. ---
LAB_FILES_ROOT = "/var/www/lab/files"
FAKE_FILESYSTEM = {
    LAB_FILES_ROOT + "/report.txt": "Quarterly report: public summary\n",
    LAB_FILES_ROOT + "/readme.txt": "Public lab downloads\n",
    "/etc/passwd": ("root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"),
    "/etc/hostname": "aegis-class-lab\n",
}


def resolve_lab_file(value: str, vulnerable: bool) -> str | None:
    """Return fake file content, or ``None`` when missing or refused."""
    if "\x00" in value:
        return None
    if vulnerable:
        resolved = posixpath.normpath(posixpath.join(LAB_FILES_ROOT, value.replace("\\", "/")))
    else:
        if value.startswith("/") or "\\" in value or ".." in value.split("/"):
            return None
        resolved = posixpath.normpath(posixpath.join(LAB_FILES_ROOT, value))
        if not resolved.startswith(LAB_FILES_ROOT + "/"):
            return None
    return FAKE_FILESYSTEM.get(resolved)


# --- JWT: HS256 tokens; the positive also accepts unsigned ``alg: none``. ---
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def issue_lab_jwt(subject: str, key: bytes) -> str:
    signing_input = (_b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()) + "."
                     + _b64url(json.dumps({"sub": subject}).encode()))
    signature = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + _b64url(signature)


def verify_lab_jwt(token: str, key: bytes, vulnerable: bool) -> str | None:
    """Return the subject of an accepted token, else ``None``."""
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None
        algorithm = str(header.get("alg") or "")
        if algorithm.lower() == "none":
            if not vulnerable:
                return None
        elif algorithm == "HS256":
            expected = hmac.new(key, f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, _b64url_decode(signature_b64)):
                return None
        else:
            return None
    except (ValueError, TypeError, binascii.Error, UnicodeDecodeError):
        return None
    subject = payload.get("sub")
    return subject if isinstance(subject, str) else None


JWT_DOCUMENTS = {"1": ("A", "aegis-lab-private-record"), "2": ("B", "peer document")}


def handler_for(bug_class: str, vulnerable: bool, callback_suffix: str):
    state = {"profile": "initial", "uploads": {}, "csrf_tokens": set(),
             "jwt_key": secrets.token_bytes(32)}

    class LabHandler(BaseHTTPRequestHandler):
        def _send(self, status, body, content_type="application/json", headers=None):
            body = body.encode() if isinstance(body, str) else body
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status, data):
            self._send(status, json.dumps(data))

        def _body(self):
            length = min(int(self.headers.get("Content-Length") or 0), 8192)
            return self.rfile.read(length)

        def _identity(self):
            return self.headers.get("X-Lab-Identity") or (
                "A" if "lab_session=A" in self.headers.get("Cookie", "") else
                "B" if "lab_session=B" in self.headers.get("Cookie", "") else "anonymous"
            )

        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            path = parsed.path
            query = urllib.parse.parse_qs(parsed.query)
            if path == "/":
                csrf_token = secrets.token_hex(8) if bug_class == "xss_post_xhr" else ""
                if csrf_token:
                    state["csrf_tokens"].add(csrf_token)
                links = {
                    "sqli": '<form action="/search"><input name="q"><button>Search</button></form>',
                    "sqli_encoded": '<a href="/catalog?category=cHVibGlj">Public catalog</a><script>const category=btoa("public");document.querySelector("a").href="/catalog?category="+encodeURIComponent(category)</script>',
                    "sqli_post_blind": '<button id="load">Load catalog</button><div id="results"></div>'
                                       '<script>document.getElementById("load").onclick=async()=>{'
                                       'const response=await fetch("/api/filter",{method:"POST",'
                                       'headers:{"Content-Type":"application/json"},'
                                       'body:JSON.stringify({template:"botox",page:2})});'
                                       'document.getElementById("results").textContent='
                                       'JSON.stringify(await response.json())}</script>',
                    "xss": '<form action="/search"><input name="q"><button>Search</button></form>',
                    "xss_dom": '<a href="/blog?search=hello">Search blog</a>',
                    "xss_post_xhr": '<button role="tab" aria-controls="results">Preview</button>'
                                    '<div id="results"></div><script>'
                                    'document.querySelector("[role=tab]").onclick=async()=>{'
                                    'const response=await fetch("/api/render",{method:"POST",'
                                    'headers:{"Content-Type":"application/json"},'
                                    'body:JSON.stringify({message:"hello",csrf_token:"' + csrf_token + '"})});'
                                    'document.getElementById("results").innerHTML=await response.text()}'
                                    '</script>',
                    "ssrf": '<a href="/api/fetch?url=https%3A%2F%2Fexample.com">URL preview</a>',
                    "idor": '<a href="/api/objects/1">Private object</a>',
                    "graphql_authz": '<a href="/graphql">GraphQL API</a><p>POST JSON query node(id: "1") { ownerId secret }</p>',
                    "unsafe_file_upload": '<form action="/api/uploads" method="post" enctype="multipart/form-data"><input type="file" name="file"><button>Upload</button></form><p>JSON API accepts filename, content_type, content. GET/DELETE /api/uploads/{id}</p>',
                    "csrf": '<form action="/login" method="post"><input name="username"><input type="password" name="password"></form><form action="/profile" method="post"><input name="display_name"><button>Save</button></form>',
                    "ssti": '<a href="/greeting?message=Hello">Greeting preview</a>',
                    "command_injection": '<form action="/tools/ping"><input name="host" value="127.0.0.1"><button>Ping</button></form>'
                                         '<a href="/tools/ping?host=127.0.0.1">Ping localhost</a>',
                    "path_traversal": '<a href="/download?file=report.txt">Download report</a>',
                    "jwt": '<a href="/api/token">Issue API token</a> <a href="/api/documents/1">Document 1</a>'
                           '<p>Send Authorization: Bearer &lt;token&gt;. Document 1 belongs to A.</p>',
                }
                self._send(200, f"<h1>Aegis class lab</h1>{links[bug_class]}", "text/html")
                return
            if path == "/whoami":
                identity = self._identity()
                self._json(200 if identity != "anonymous" else 401, {"principal_id": identity})
                return
            if (bug_class == "sqli" and path == "/search") or (
                bug_class == "sqli_encoded" and path == "/catalog"
            ):
                value = query.get("q" if bug_class == "sqli" else "category", [""])[0]
                if bug_class == "sqli_encoded":
                    try:
                        value = base64.b64decode(value, validate=True).decode("utf-8")
                    except (ValueError, UnicodeDecodeError, binascii.Error):
                        self._json(400, {"error": "invalid category encoding"})
                        return
                db = sqlite3.connect(":memory:")
                db.execute("CREATE TABLE items (name TEXT, detail TEXT)")
                db.executemany("INSERT INTO items VALUES (?, ?)", [
                    ("public", "public item"), ("private", "aegis-lab-private-record")])
                try:
                    sql = "SELECT name, detail FROM items WHERE name = '" + value + "'" if vulnerable else "SELECT name, detail FROM items WHERE name = ?"
                    rows = db.execute(sql, () if vulnerable else (value,)).fetchall()
                    self._json(200, {"results": rows})
                except sqlite3.Error:
                    self._json(400, {"error": "invalid search"})
                finally:
                    db.close()
                return
            if bug_class == "xss" and path == "/search":
                value = query.get("q", [""])[0]
                rendered = value if vulnerable else html.escape(value, quote=True)
                self._send(200, f"<h1>Search</h1><div>{rendered}</div>", "text/html")
                return
            if bug_class == "xss_dom" and path == "/blog":
                sink = "innerHTML" if vulnerable else "textContent"
                self._send(200, '<h1>Blog</h1><div id="results"></div>'
                           '<script>const value=new URLSearchParams(location.search).get("search")||"";'
                           f'document.getElementById("results").{sink}=value;'
                           '</script>', "text/html")
                return
            if bug_class == "ssrf" and path == "/api/fetch":
                url = query.get("url", [""])[0]
                host = (urllib.parse.urlsplit(url).hostname or "").lower()
                allowed = bool(callback_suffix and host.endswith("." + callback_suffix.lower()))
                if not vulnerable or not allowed or not url.startswith("https://"):
                    self._json(403, {"error": "URL blocked"})
                    return
                try:
                    socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
                except OSError:
                    pass
                self._json(202, {"status": "fetch attempted"})
                return
            if bug_class == "idor" and path == "/api/objects/1":
                identity = self._identity()
                if identity == "anonymous":
                    self._json(401, {"error": "login required"})
                elif identity != "A" and not vulnerable:
                    self._json(403, {"error": "not owner"})
                else:
                    self._json(200, {"owner_id": "A", "secret": "aegis-lab-private-record"})
                return
            if bug_class == "graphql_authz" and path == "/graphql":
                self._json(200, {"endpoint": "/graphql", "example": "query { node(id: \"1\") { ownerId secret } }"})
                return
            if bug_class == "unsafe_file_upload" and path.startswith("/api/uploads/"):
                item = state["uploads"].get(path.rsplit("/", 1)[-1])
                if not item:
                    self._json(404, {"error": "missing"})
                elif vulnerable:
                    self._send(200, item["content"], item["content_type"])
                else:
                    self._send(200, item["content"], "text/plain",
                               {"Content-Disposition": "attachment; filename=canary.txt"})
                return
            if bug_class == "csrf" and path == "/profile":
                self._json(200, {"principal_id": self._identity(), "display_name": state["profile"]})
                return
            if bug_class == "ssti" and path == "/greeting":
                value = query.get("message", ["Hello"])[0][:500]
                rendered = render_toy_template(value) if vulnerable else value
                self._send(200, f"<h1>Greeting</h1><p>{html.escape(rendered, quote=True)}</p>", "text/html")
                return
            if bug_class == "command_injection" and path == "/tools/ping":
                host = query.get("host", [""])[0][:300]
                if vulnerable:
                    self._send(200, simulate_ping_shell(host), "text/plain")
                elif _SAFE_HOST.fullmatch(host):
                    self._send(200, _ping_output(host), "text/plain")
                else:
                    self._json(400, {"error": "invalid host", "host": host})
                return
            if bug_class == "path_traversal" and path == "/download":
                name = query.get("file", [""])[0][:500]
                content = resolve_lab_file(name, vulnerable)
                if content is None:
                    self._json(404, {"error": "file not found", "file": name})
                else:
                    self._send(200, content, "text/plain")
                return
            if bug_class == "jwt" and path == "/api/token":
                identity = self._identity()
                if identity == "anonymous":
                    self._json(401, {"error": "login required"})
                else:
                    self._json(200, {"token": issue_lab_jwt(identity, state["jwt_key"])})
                return
            if bug_class == "jwt" and path.startswith("/api/documents/"):
                document = JWT_DOCUMENTS.get(path.rsplit("/", 1)[-1])
                authorization = self.headers.get("Authorization", "")
                subject = (verify_lab_jwt(authorization[7:].strip(), state["jwt_key"], vulnerable)
                           if authorization.lower().startswith("bearer ") else None)
                if document is None:
                    self._json(404, {"error": "missing"})
                elif subject is None:
                    self._json(401, {"error": "valid bearer token required"})
                elif subject != document[0]:
                    self._json(403, {"error": "not owner"})
                else:
                    self._json(200, {"owner_id": document[0], "secret": document[1]})
                return
            if bug_class == "csrf" and path == "/login":
                self._send(200, '<form method="post"><input name="username"><input type="password" name="password"></form>', "text/html")
                return
            self._json(404, {"error": "missing"})

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            body = self._body()
            if bug_class == "xss_post_xhr" and path == "/api/render":
                try:
                    data = json.loads(body)
                    value, token = data["message"], data["csrf_token"]
                    if not isinstance(value, str) or not isinstance(token, str):
                        raise ValueError("invalid field type")
                except (ValueError, KeyError, TypeError):
                    self._json(400, {"error": "invalid request"})
                    return
                if token not in state["csrf_tokens"]:
                    self._json(403, {"error": "invalid token"})
                    return
                state["csrf_tokens"].remove(token)
                self._send(200, value if vulnerable else html.escape(value, quote=True), "text/html")
                return
            if bug_class == "sqli_post_blind" and path == "/api/filter":
                try:
                    data = json.loads(body)
                    value = data["template"]
                    if not isinstance(value, str):
                        raise ValueError("template must be a string")
                except (ValueError, KeyError, TypeError):
                    self._json(400, {"error": "invalid request"})
                    return
                db = sqlite3.connect(":memory:")
                db.execute("CREATE TABLE items (name TEXT, detail TEXT)")
                db.executemany("INSERT INTO items VALUES (?, ?)", [
                    ("public", "public item"), ("private", "aegis-lab-private-record"),
                ])
                try:
                    sql = ("SELECT name, detail FROM items WHERE name = '" + value + "'"
                           if vulnerable else "SELECT name, detail FROM items WHERE name = ?")
                    rows = db.execute(sql, () if vulnerable else (value,)).fetchall()
                    self._json(200, {"results": rows})
                except sqlite3.Error:
                    # Intentionally suppress database errors so this fixture
                    # tests Boolean detection, not the SQL-error recipe.
                    self._json(200, {"results": []})
                finally:
                    db.close()
                return
            if bug_class == "csrf" and path == "/login":
                form = urllib.parse.parse_qs(body.decode())
                name = form.get("username", [""])[0]
                if name in ("A", "B") and form.get("password", [""])[0] == "lab-pass":
                    self._send(200, json.dumps({"principal_id": name}), headers={
                        "Set-Cookie": f"lab_session={name}; Path=/; HttpOnly",
                    })
                else:
                    self._json(401, {"error": "invalid credentials"})
                return
            if bug_class == "graphql_authz" and path == "/graphql":
                try:
                    data = json.loads(body)
                except ValueError:
                    self._json(400, {"errors": [{"message": "invalid JSON"}]})
                    return
                identity = self._identity()
                if (data.get("variables") or {}).get("id") != "1":
                    self._json(200, {"data": {"node": None}})
                elif identity == "anonymous" or (identity != "A" and not vulnerable):
                    self._json(200, {"data": {"node": None}, "errors": [{"message": "forbidden"}]})
                else:
                    self._json(200, {"data": {"node": {"ownerId": "A", "secret": "aegis-lab-private-record"}}})
                return
            if bug_class == "unsafe_file_upload" and path == "/api/uploads":
                try:
                    if "multipart/form-data" in self.headers.get("Content-Type", ""):
                        message = BytesParser(policy=policy.default).parsebytes(
                            ("Content-Type: " + self.headers["Content-Type"] + "\r\nMIME-Version: 1.0\r\n\r\n").encode() + body
                        )
                        part = next(item for item in message.iter_parts() if item.get_filename())
                        content = (part.get_payload(decode=True) or b"").decode("utf-8")
                        content_type = part.get_content_type()
                    else:
                        data = json.loads(body)
                        content = str(data["content"])
                        content_type = str(data.get("content_type") or "text/plain")
                except (ValueError, KeyError, TypeError, StopIteration, UnicodeDecodeError):
                    self._json(400, {"error": "send JSON filename, content_type, content"})
                    return
                if not vulnerable and (content_type != "text/plain" or "<" in content):
                    self._json(415, {"error": "inert text only"})
                    return
                item_id = str(len(state["uploads"]) + 1)
                state["uploads"][item_id] = {"content": content, "content_type": content_type}
                self._json(201, {"id": item_id, "url": f"/api/uploads/{item_id}"})
                return
            if bug_class == "csrf" and path == "/profile":
                if self._identity() == "anonymous":
                    self._json(401, {"error": "login required"})
                    return
                if not vulnerable and (self.headers.get("X-CSRF-Token") != "lab-token-A"
                                       or self.headers.get("Origin") != f"http://{self.headers.get('Host')}"):
                    self._json(403, {"error": "CSRF check failed"})
                    return
                if "application/json" in self.headers.get("Content-Type", ""):
                    value = json.loads(body).get("display_name", "")
                else:
                    value = urllib.parse.parse_qs(body.decode()).get("display_name", [""])[0]
                state["profile"] = str(value)[:120]
                self._json(200, {"display_name": state["profile"]})
                return
            self._json(404, {"error": "missing"})

        def do_DELETE(self):
            path = urllib.parse.urlsplit(self.path).path
            if bug_class == "unsafe_file_upload" and path.startswith("/api/uploads/"):
                state["uploads"].pop(path.rsplit("/", 1)[-1], None)
                self._json(200, {"deleted": True})
            elif bug_class == "csrf" and path == "/profile":
                state["profile"] = "initial"
                self._json(200, {"deleted": True})
            else:
                self._json(404, {"error": "missing"})

    return LabHandler


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--class", dest="bug_class", choices=CLASSES, required=True)
    parser.add_argument("--polarity", choices=("positive", "negative"), required=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--callback-suffix", default="", help="Controlled OAST DNS suffix for SSRF positive")
    args = parser.parse_args(argv)
    if args.bug_class == "ssrf" and args.polarity == "positive" and not args.callback_suffix:
        parser.error("SSRF positive requires --callback-suffix")
    server = ThreadingHTTPServer(
        ("127.0.0.1", args.port),
        handler_for(args.bug_class, args.polarity == "positive", args.callback_suffix),
    )
    print(f"{args.bug_class} {args.polarity}: http://127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
