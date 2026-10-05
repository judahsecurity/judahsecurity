"""Small, deliberately vulnerable local targets for product-agent class runs.

Run one class/polarity per process. Never expose this fixture beyond loopback.
"""

from __future__ import annotations

import argparse
from email import policy
from email.parser import BytesParser
import html
import json
import socket
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CLASSES = ("sqli", "xss", "ssrf", "idor", "graphql_authz", "unsafe_file_upload", "csrf")


def handler_for(bug_class: str, vulnerable: bool, callback_suffix: str):
    state = {"profile": "initial", "uploads": {}}

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
                links = {
                    "sqli": '<form action="/search"><input name="q"><button>Search</button></form>',
                    "xss": '<form action="/search"><input name="q"><button>Search</button></form>',
                    "ssrf": '<a href="/api/fetch?url=https%3A%2F%2Fexample.com">URL preview</a>',
                    "idor": '<a href="/api/objects/1">Private object</a>',
                    "graphql_authz": '<a href="/graphql">GraphQL API</a><p>POST JSON query node(id: "1") { ownerId secret }</p>',
                    "unsafe_file_upload": '<form action="/api/uploads" method="post" enctype="multipart/form-data"><input type="file" name="file"><button>Upload</button></form><p>JSON API accepts filename, content_type, content. GET/DELETE /api/uploads/{id}</p>',
                    "csrf": '<form action="/login" method="post"><input name="username"><input type="password" name="password"></form><form action="/profile" method="post"><input name="display_name"><button>Save</button></form>',
                }
                self._send(200, f"<h1>Aegis class lab</h1>{links[bug_class]}", "text/html")
                return
            if path == "/whoami":
                identity = self._identity()
                self._json(200 if identity != "anonymous" else 401, {"principal_id": identity})
                return
            if bug_class == "sqli" and path == "/search":
                value = query.get("q", [""])[0]
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
            if bug_class == "csrf" and path == "/login":
                self._send(200, '<form method="post"><input name="username"><input type="password" name="password"></form>', "text/html")
                return
            self._json(404, {"error": "missing"})

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            body = self._body()
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
