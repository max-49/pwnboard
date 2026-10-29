"""GET /hosts/{ip}/callbacks and /hosts/{ip}/creds: listing what is recorded for a host."""
import time

import pytest

from pwnboard.web import endpoints
from tests.conftest import IP_A

BEARER = {"Authorization": "Bearer some-token"}
NOW = time.time()


def minutes_ago(minutes, extra_seconds=0):
    return NOW - minutes * 60 - extra_seconds


# Each endpoint with the rows its query returns: (application/username, access_info/password, last_seen).
# The defaults are 5 minutes for callbacks and 30 for credentials.
ENDPOINTS = {
    "callbacks": {
        "rows": [
            ("old-c2", "", minutes_ago(5, 1)),                  # exactly at the timeout: not active
            ("fresh-c2", "https://c2.example/x", minutes_ago(1)),
            ("newer-c2", "", minutes_ago(0)),
            ("ancient-c2", "", minutes_ago(90)),
        ],
        "keys": ["application", "access_info"],
    },
    "creds": {
        "rows": [
            ("stale-user", "pw-old", minutes_ago(30, 1)),
            ("fresh-user", "pw-fresh", minutes_ago(10)),
            ("newer-user", "pw-newer", minutes_ago(2)),
            ("ancient-user", "pw-ancient", minutes_ago(600)),
        ],
        "keys": ["username", "password"],
    },
}


@pytest.fixture(params=sorted(ENDPOINTS))
def endpoint(request):
    return request.param


@pytest.fixture
def rows(db, endpoint):
    db.cur.fetchall.return_value = ENDPOINTS[endpoint]["rows"]
    return ENDPOINTS[endpoint]["rows"]


def get(client, endpoint, ip=IP_A, query="", headers=BEARER):
    return client.get(f"/hosts/{ip}/{endpoint}{query}", headers=headers)


class TestListing:
    def test_everything_is_listed_active_first_then_newest(self, client, db, rows, endpoint, tokens_enabled, valid_token):
        response = get(client, endpoint)
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"
        entries = response.get_json()
        first_key = ENDPOINTS[endpoint]["keys"][0]
        assert [entry[first_key] for entry in entries] == [
            {"callbacks": "newer-c2", "creds": "newer-user"}[endpoint],
            {"callbacks": "fresh-c2", "creds": "fresh-user"}[endpoint],
            {"callbacks": "old-c2", "creds": "stale-user"}[endpoint],
            {"callbacks": "ancient-c2", "creds": "ancient-user"}[endpoint],
        ]
        assert [entry["active"] for entry in entries] == [True, True, False, False]
        assert set(entries[0]) == {*ENDPOINTS[endpoint]["keys"], "last_seen", "age_minutes", "active"}

    def test_active_true_keeps_only_active_entries(self, client, db, rows, endpoint, tokens_enabled, valid_token):
        entries = get(client, endpoint, query="?active=true").get_json()
        assert len(entries) == 2 and all(e["active"] for e in entries)

    def test_other_values_of_active_are_refused(self, client, db, endpoint, tokens_enabled, valid_token):
        response = get(client, endpoint, query="?active=maybe")
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "invalid_request"

    def test_an_address_that_is_not_on_the_board_is_not_found(self, client, db, endpoint, tokens_enabled, valid_token):
        assert get(client, endpoint, ip="203.0.113.9").status_code == 404

    def test_reading_changes_nothing(self, client, db, rows, endpoint, tokens_enabled, valid_token):
        get(client, endpoint)
        get(client, endpoint, query="?active=true")
        statements = [call.args[0].strip().upper() for call in db.cur.execute.call_args_list]
        assert statements and all(sql.startswith("SELECT") for sql in statements)
        db.commit.assert_not_called()

    def test_a_database_failure_is_an_error_not_an_empty_list(self, client, db, endpoint, tokens_enabled, valid_token):
        db.cur.execute.side_effect = RuntimeError("database is down")
        assert get(client, endpoint).status_code == 500


class TestAuthentication:
    def test_a_valid_token_is_enough(self, client, db, endpoint, tokens_enabled, valid_token):
        assert get(client, endpoint).status_code == 200
        assert valid_token == ["some-token"]

    def test_no_credentials_at_all_is_refused(self, client, db, endpoint, tokens_enabled):
        response = client.get(f"/hosts/{IP_A}/{endpoint}")
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"

    def test_an_unknown_or_expired_token_is_refused(self, client, db, endpoint, tokens_enabled, monkeypatch):
        monkeypatch.setattr(endpoints, "verifyAccessToken", lambda token: False)
        assert get(client, endpoint).status_code == 401

    def test_a_logged_in_session_works_without_a_token(self, client, db, login, endpoint, tokens_enabled):
        assert get(login("user"), endpoint, headers={}).status_code == 200

    def test_with_tokens_disabled_a_bearer_header_is_not_enough(self, client, db, endpoint, tokens_disabled, valid_token):
        # These endpoints return passwords, so they are never open without a session
        assert get(client, endpoint).status_code == 401
        assert valid_token == []
