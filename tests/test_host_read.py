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
        first_key = ENDPOINTS[endpoint]["keys"][0]
        assert [entry[first_key] for entry in response.get_json()] == [
            {"callbacks": "newer-c2", "creds": "newer-user"}[endpoint],
            {"callbacks": "fresh-c2", "creds": "fresh-user"}[endpoint],
            {"callbacks": "old-c2", "creds": "stale-user"}[endpoint],
            {"callbacks": "ancient-c2", "creds": "ancient-user"}[endpoint],
        ]

    def test_each_entry_says_how_old_it_is_and_whether_it_is_active(self, client, db, rows, endpoint, tokens_enabled, valid_token):
        entries = get(client, endpoint).get_json()
        assert [e["active"] for e in entries] == [True, True, False, False]
        expected_ages = {"callbacks": [0, 1, 5, 90], "creds": [2, 10, 30, 600]}[endpoint]
        for entry, age in zip(entries, expected_ages):
            assert age <= entry["age_minutes"] <= age + 1  # a minute boundary may pass during the test
        assert set(entries[0]) == {*ENDPOINTS[endpoint]["keys"], "last_seen", "age_minutes", "active"}
        assert isinstance(entries[0]["last_seen"], int)

    def test_active_true_keeps_only_active_entries(self, client, db, rows, endpoint, tokens_enabled, valid_token):
        entries = get(client, endpoint, query="?active=true").get_json()
        assert len(entries) == 2 and all(e["active"] for e in entries)

    @pytest.mark.parametrize("value", ["false", "FALSE"])
    def test_active_false_is_no_filter(self, client, db, rows, endpoint, tokens_enabled, valid_token, value):
        assert len(get(client, endpoint, query=f"?active={value}").get_json()) == 4

    @pytest.mark.parametrize("value", ["maybe", "1", "", "yes"])
    def test_other_values_of_active_are_refused(self, client, db, endpoint, tokens_enabled, valid_token, value):
        response = get(client, endpoint, query=f"?active={value}")
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "invalid_request"

    def test_a_host_with_no_records_gives_an_empty_list(self, client, db, endpoint, tokens_enabled, valid_token):
        response = get(client, endpoint)
        assert response.status_code == 200 and response.get_json() == []

    def test_an_address_that_is_not_on_the_board_is_not_found(self, client, db, endpoint, tokens_enabled, valid_token):
        response = get(client, endpoint, ip="203.0.113.9")
        assert response.status_code == 404
        assert response.get_json()["error"]["code"] == "not_found"

    def test_the_timeouts_are_the_configured_ones(self, client, db, rows, endpoint, tokens_enabled, valid_token, monkeypatch):
        monkeypatch.setenv("HOST_TIMEOUT", "100")
        monkeypatch.setenv("CREDS_TIMEOUT", "1000")
        assert all(entry["active"] for entry in get(client, endpoint).get_json())

    def test_a_row_with_an_unusable_time_is_left_out(self, client, db, endpoint, tokens_enabled, valid_token):
        db.cur.fetchall.return_value = [("a", "b", "not-a-time"), ("c", "d", minutes_ago(0))]
        assert len(get(client, endpoint).get_json()) == 1

    def test_the_answer_is_never_cached(self, client, db, rows, endpoint, tokens_enabled, valid_token):
        assert get(client, endpoint).headers["Cache-Control"] == "no-store"

    def test_reading_changes_nothing(self, client, db, rows, endpoint, tokens_enabled, valid_token):
        get(client, endpoint)
        get(client, endpoint, query="?active=true")
        statements = [call.args[0].strip().upper() for call in db.cur.execute.call_args_list]
        assert statements and all(sql.startswith("SELECT") for sql in statements)
        db.commit.assert_not_called()

    def test_a_database_failure_is_an_error_not_an_empty_list(self, client, db, endpoint, tokens_enabled, valid_token):
        db.cur.execute.side_effect = RuntimeError("database is down")
        response = get(client, endpoint)
        assert response.status_code == 500
        assert response.get_json()["error"]["code"]


class TestAuthentication:
    def test_a_valid_token_is_enough(self, client, db, endpoint, tokens_enabled, valid_token):
        assert get(client, endpoint).status_code == 200
        assert valid_token == ["some-token"]

    def test_no_credentials_at_all_is_refused_and_says_how_to_authenticate(self, client, db, endpoint, tokens_enabled):
        response = client.get(f"/hosts/{IP_A}/{endpoint}")
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"
        assert "Bearer" in response.get_json()["error"]["message"]

    @pytest.mark.parametrize("header", ["Basic abc", "Bearer", "Bearer   ", "some-token"])
    def test_a_header_that_is_not_a_bearer_token_is_refused(self, client, db, endpoint, tokens_enabled, header):
        response = get(client, endpoint, headers={"Authorization": header})
        assert response.status_code == 401

    def test_an_unknown_or_expired_token_is_refused(self, client, db, endpoint, tokens_enabled, monkeypatch):
        monkeypatch.setattr(endpoints, "verifyAccessToken", lambda token: False)
        response = get(client, endpoint)
        assert response.status_code == 401
        assert "not valid or has expired" in response.get_json()["error"]["message"]

    def test_a_logged_in_session_works_without_a_token(self, client, db, login, endpoint, tokens_enabled):
        assert get(login("user"), endpoint, headers={}).status_code == 200

    def test_a_bad_token_is_refused_even_when_logged_in(self, client, db, login, endpoint, tokens_enabled, monkeypatch):
        monkeypatch.setattr(endpoints, "verifyAccessToken", lambda token: False)
        assert get(login("user"), endpoint).status_code == 401

    def test_with_tokens_disabled_a_bearer_header_is_not_enough(self, client, db, endpoint, tokens_disabled, valid_token):
        response = get(client, endpoint)
        assert response.status_code == 401
        assert "WWW-Authenticate" not in response.headers
        assert valid_token == []

    def test_with_tokens_disabled_a_session_still_works(self, client, db, login, endpoint, tokens_disabled):
        assert get(login("user"), endpoint, headers=BEARER).status_code == 200
