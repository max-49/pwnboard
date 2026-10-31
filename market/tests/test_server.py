import http.client
import json

import pytest

from pwnmarket.server import make_server


class FakeMarket:
    def snapshot(self):
        return {"round": 5, "rounds_left": 10, "stale": False, "teams": []}

    def history(self, minutes):
        return {"minutes": minutes}

    def explain(self):
        return {"ready": False, "params": {}}


@pytest.fixture
def get():
    server = make_server(FakeMarket(), 0)
    port = server.server_address[1]

    def fetch(path):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", path)
        response = conn.getresponse()
        return response.status, response.getheader("Content-Type"), response.read()

    yield fetch
    server.shutdown()
    server.server_close()


def test_serves_the_page(get):
    status, content_type, body = get("/")
    assert status == 200 and content_type.startswith("text/html")
    assert b"PWNMarket" in body


def test_json_endpoints(get):
    assert json.loads(get("/api/odds")[2])["round"] == 5
    assert json.loads(get("/odds")[2])["round"] == 5
    assert json.loads(get("/api/history?minutes=30")[2]) == {"minutes": 30}
    assert json.loads(get("/api/history")[2]) == {"minutes": 60}


def test_bad_input_and_unknown_paths(get):
    assert get("/api/history?minutes=abc")[0] == 400
    assert get("/nope")[0] == 404
    assert get("/healthz")[0] == 200


def test_how_it_works_page_and_shared_assets(get):
    status, content_type, body = get("/how-it-works")
    assert status == 200 and content_type.startswith("text/html")
    assert b"/api/model" in body
    assert get("/site.css")[1].startswith("text/css")
    assert get("/site.js")[1].startswith("text/javascript")
    assert json.loads(get("/api/model")[2]) == {"ready": False, "params": {}}
