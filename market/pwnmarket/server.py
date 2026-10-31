"""The market website and its read-only JSON API (published on port 8080)."""
import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger("market.server")

WEB = os.path.join(os.path.dirname(__file__), "web")
HTML = "text/html; charset=utf-8"
# URL path -> (file in web/, content type)
FILES = {
    "/": ("index.html", HTML),
    "/index.html": ("index.html", HTML),
    "/how-it-works": ("how-it-works.html", HTML),
    "/site.css": ("site.css", "text/css; charset=utf-8"),
    "/site.js": ("site.js", "text/javascript; charset=utf-8"),
}


def make_server(market, port):
    pages = {}
    for path, (name, content_type) in FILES.items():
        with open(os.path.join(WEB, name), "rb") as f:
            pages[path] = (f.read(), content_type)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            url = urlparse(self.path)
            try:
                if url.path in pages:
                    self._send(200, *pages[url.path])
                elif url.path == "/healthz":
                    self._send(200, b"ok\n", "text/plain")
                elif url.path in ("/api/odds", "/odds"):
                    self._json(market.snapshot())
                elif url.path == "/api/model":
                    self._json(market.explain())
                elif url.path == "/api/history":
                    try:
                        minutes = int(parse_qs(url.query).get("minutes", ["60"])[0])
                    except ValueError:
                        return self._send(400, b"minutes must be a whole number\n", "text/plain")
                    self._json(market.history(minutes))
                else:
                    self._send(404, b"not found\n", "text/plain")
            except Exception:
                logger.exception("request failed: %s", self.path)
                self._send(500, b"something went wrong\n", "text/plain")

        def _json(self, data):
            self._send(200, json.dumps(data).encode(), "application/json")

        def _send(self, status, body, content_type):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
