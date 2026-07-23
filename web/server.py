"""bv-secrets dashboard — unprivileged HTTP facade.

The store is mounted read-only and no rotation runs here: actions drop a job in the
spool, which the privileged worker runs on the host.

Guards: app password (on top of the Caddy admin gate), in-memory
HttpOnly/Secure/SameSite=Strict session cookie, POSTs protected by double-submit CSRF.
"""
import json
import os
import secrets as pysecrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import urlparse

from . import routes, session, views
from .html import ASSET_TYPES, ASSET_V, asset

PORT = int(os.environ.get("BV_PORT", "8000"))
MAX_BODY = 65536
BAD_AUTH_DELAY = 0.5
IMMUTABLE = "public, max-age=31536000, immutable"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    # ---- primitives ----
    def _cookies(self):
        out = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "=" in part:
                key, value = part.strip().split("=", 1)
                out[key] = value
        return out

    def _authed(self):
        return session.valid(self._cookies().get("bv_sess", ""))

    def _body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > MAX_BODY:
            raise ValueError("corps de requête trop volumineux")
        return json.loads(self.rfile.read(length) or b"{}")

    def _send(self, code, body, ctype="application/json", extra=None, cache="no-store"):
        payload = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", cache)
        for key, value in (extra or []):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, code, obj, extra=None):
        self._send(code, json.dumps(obj), extra=extra)

    def _dispatch(self, table, path, body=None):
        handler = table.get(path)
        if not handler:
            return self._json(404, {"error": "not found"})
        code, obj = handler(SimpleNamespace(path=path, body=body or {}))
        if code == 401 and path in routes.RATE_LIMITED:
            time.sleep(BAD_AUTH_DELAY)
        self._json(code, obj)

    # ---- GET ----
    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        try:
            if path == "/health":
                return self._send(200, "ok", "text/plain")
            # assets before the session check: the login page needs them
            if path.startswith("/static/"):
                return self._serve_asset(path[len("/static/"):])
            if path == "/":
                return self._serve_root()
            if not self._authed():
                return self._json(401, {"error": "auth"})
            if path.startswith("/api/jobs/"):
                code, obj = routes.api_job(SimpleNamespace(path=path, body={}))
                return self._json(code, obj)
            return self._dispatch(routes.GET_ROUTES, path)
        except Exception as ex:
            return self._json(500, {"error": str(ex)})

    def _serve_asset(self, rel):
        path = asset(rel)
        if not path:
            return self._json(404, {"error": "not found"})
        # URL carries the content hash: immutable, so cacheable forever
        return self._send(200, path.read_bytes(), ASSET_TYPES[path.suffix], cache=IMMUTABLE)

    def _serve_root(self):
        if not self._authed():
            return self._send(200, views.login(session.configured()), "text/html; charset=utf-8")
        csrf = self._cookies().get("bv_csrf") or pysecrets.token_hex(16)
        return self._send(200, views.dashboard(csrf), "text/html; charset=utf-8",
                          extra=[session.csrf_cookie(csrf)])

    # ---- POST ----
    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        try:
            if path == "/api/login":
                return self._login()
            if path == "/api/logout":
                session.drop(self._cookies().get("bv_sess", ""))
                return self._json(200, {"ok": True}, extra=[session.clear_session_cookie()])
            if not self._authed():
                return self._json(401, {"error": "auth"})
            if not session.csrf_ok(self._cookies().get("bv_csrf", ""),
                                   self.headers.get("X-CSRF", "")):
                return self._json(403, {"error": "csrf"})
            return self._dispatch(routes.POST_ROUTES, path, self._body())
        except Exception as ex:
            return self._json(500, {"error": str(ex)})

    def _login(self):
        if not session.check_password(str(self._body().get("password", ""))):
            time.sleep(BAD_AUTH_DELAY)
            return self._json(401, {"error": "bad password"})
        return self._json(200, {"ok": True}, extra=[session.session_cookie(session.new())])


def main():
    print(f"bv-secrets web: port {PORT}, assets {ASSET_V}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
