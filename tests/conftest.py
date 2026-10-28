"""Shared fixtures.

Postgres and Redis are replaced with fakes, so the tests need no running services.
"""
import os
from pathlib import Path
from unittest import mock

# Both are read when the pwnboard package is imported, so set them first
os.environ["BOARD"] = str(Path(__file__).parent / "fixtures" / "sample_board.json")
os.environ.setdefault("SECRET_KEY", "test-secret-key")

import fakeredis  # noqa: E402
import pytest  # noqa: E402

from pwnboard.web import app, authentication, endpoints, login_throttle, routes  # noqa: E402
from tests.spec_helpers import SpecChecker, load_spec, request_json  # noqa: E402

IP_A = "10.1.1.1"
IP_B = "10.2.1.1"


@pytest.fixture
def redis(monkeypatch):
    """An in-memory Redis shared by every module that talks to it."""
    fake = fakeredis.FakeStrictRedis(decode_responses=True)
    for module in (endpoints, routes, login_throttle):
        monkeypatch.setattr(module, "redis_client", fake)
    return fake


@pytest.fixture(scope="session")
def spec():
    return load_spec()


@pytest.fixture
def client(redis, spec):
    """A test client that also checks every response against openapi.yaml."""
    test_client = app.test_client()
    checker = SpecChecker(spec)
    open_request = test_client.open

    def open_and_check(*args, **kwargs):
        response = open_request(*args, **kwargs)
        checker.check(response, request_json(kwargs))
        return response

    test_client.open = open_and_check
    return test_client


@pytest.fixture
def login(client):
    """Return a function that logs the test client in with the given role."""
    def _login(role="user", username="tester"):
        with client.session_transaction() as session:
            session["user"] = username
            session["role"] = role
        return client
    return _login


@pytest.fixture
def db(monkeypatch):
    """A fake Postgres connection. Set db.cur.fetchone / db.cur.fetchall to control query results."""
    conn = mock.MagicMock()
    # `with conn.cursor() as cur` and `with dict_cursor(conn) as cur` both yield this object
    conn.cur = conn.cursor.return_value.__enter__.return_value
    conn.cur.fetchone.return_value = None
    conn.cur.fetchall.return_value = []
    for module in (endpoints, authentication):
        monkeypatch.setattr(module, "get_db", lambda: conn)
    return conn


@pytest.fixture
def tokens_enabled(monkeypatch):
    monkeypatch.setattr(endpoints, "USE_ACCESS_TOKENS", True)


@pytest.fixture
def tokens_disabled(monkeypatch):
    monkeypatch.setattr(endpoints, "USE_ACCESS_TOKENS", False)


@pytest.fixture
def valid_token(monkeypatch):
    """Make every bearer token valid, and record which tokens were checked."""
    checked = []

    def verify(token):
        checked.append(token)
        return {"application": "whatever the token was created for"}

    monkeypatch.setattr(endpoints, "verifyAccessToken", verify)
    return checked
