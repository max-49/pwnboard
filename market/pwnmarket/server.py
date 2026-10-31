"""A tiny read-only HTTP endpoint: /healthz and /odds. Not published outside the docker network."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def make_server(market, port):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/healthz":
                self._send(200, b"ok\n", "text/plain")
            elif self.path == "/odds":
                self._send(200, json.dumps(market.snapshot()).encode(), "application/json")
            else:
                self._send(404, b"not found\n", "text/plain")

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
