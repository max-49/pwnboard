"""Behavior of the beacon and credential endpoints (/pwn, /checkin, /creds).

These tests record what the API does today so that later changes (a versioned API, a new
framework) can be checked against it. Anything marked as a known gap documents behavior
that should change, not behavior to keep.
"""
import json

import pytest

from tests.conftest import IP_A, IP_B

CALLBACK_PATHS = ["/pwn", "/checkin"]


def queued(redis, name):
    return [json.loads(item) for item in redis.lrange(name, 0, -1)]


class TestCallbackBasics:
    @pytest.mark.parametrize("path", CALLBACK_PATHS)
    def test_valid_callback_is_queued(self, client, redis, tokens_disabled, path):
        response = client.post(path, json={"ip": IP_A, "application": "c2"})
        assert response.status_code == 200
        assert response.get_data(as_text=True) == "valid\n"
        [item] = queued(redis, "callback_queue")
        assert item["ip"] == IP_A and item["application"] == "c2"
        assert isinstance(item["last_seen"], float)

    def test_extra_fields_are_accepted_and_passed_through(self, client, redis, tokens_disabled):
        client.post("/pwn", json={"ip": IP_A, "application": "c2", "access_type": "shell", "server": "s", "message": "m"})
        [item] = queued(redis, "callback_queue")
        assert (item["access_type"], item["server"], item["message"]) == ("shell", "s", "m")

    def test_body_is_read_as_json_whatever_the_content_type(self, client, redis, tokens_disabled):
        # `curl -d '{...}'` sends application/x-www-form-urlencoded, and that works today
        response = client.post("/pwn", data=json.dumps({"ip": IP_A, "application": "c2"}),
                               content_type="application/x-www-form-urlencoded")
        assert response.status_code == 200
        assert len(queued(redis, "callback_queue")) == 1

    def test_ips_list_queues_one_item_per_address(self, client, redis, tokens_disabled):
        response = client.post("/pwn", json={"ips": [IP_A, IP_B], "application": "c2"})
        assert response.status_code == 200
        items = queued(redis, "callback_queue")
        assert sorted(item["ip"] for item in items) == sorted([IP_A, IP_B])
        assert all("ips" not in item for item in items)

    def test_challenge_is_echoed_as_plain_text_before_any_auth(self, client, tokens_enabled):
        response = client.post("/pwn", json={"challenge": "<b>abc</b>"})
        assert response.status_code == 200
        assert response.mimetype == "text/plain"
        assert response.get_data(as_text=True) == "<b>abc</b>"


class TestCallbackErrors:
    @pytest.mark.parametrize("body, message", [
        ({"ip": "9.9.9.9", "application": "c2"}, "invalid IP\n"),
        ({"application": "c2"}, "invalid POST\n"),
        ({"ip": IP_A}, "Invalid: Missing 'application' field in the request"),
        ([1], "Invalid: the request body must be a JSON object\n"),
        ({"ip": [1], "application": "c2"}, "Invalid: 'ip' must be a string of at most 45 characters\n"),
        ({"ip": IP_A, "application": 5}, "Invalid: 'application' must be a string of at most 64 characters\n"),
        ({"ip": IP_A, "application": "a" * 65}, "Invalid: 'application' must be a string of at most 64 characters\n"),
        ({"ip": IP_A, "application": "c2", "access_info": "x" * 2001}, "Invalid: 'access_info' must be a string of at most 2000 characters\n"),
        ({"ips": [1], "application": "c2"}, "Invalid: 'ips' must be a list of strings\n"),
        ({"ips": [IP_A] * 1001, "application": "c2"}, "Invalid: 'ips' can contain at most 1000 addresses\n"),
    ])
    def test_bad_payloads_return_400_and_queue_nothing(self, client, redis, tokens_disabled, body, message):
        response = client.post("/pwn", json=body)
        assert response.status_code == 400
        assert response.get_data(as_text=True) == message
        assert redis.llen("callback_queue") == 0

    def test_invalid_json_returns_400(self, client, tokens_disabled):
        response = client.post("/pwn", data="{not json", content_type="application/json")
        assert response.status_code == 400

    def test_ips_list_with_a_bad_address_is_partially_queued(self, client, redis, tokens_disabled):
        # Known gap: addresses before the bad one are already queued when the 400 is returned
        response = client.post("/pwn", json={"ips": [IP_A, "9.9.9.9", IP_B], "application": "c2"})
        assert response.status_code == 400
        assert [item["ip"] for item in queued(redis, "callback_queue")] == [IP_A]

    def test_body_over_1mb_is_rejected(self, client, redis, tokens_disabled):
        response = client.post("/pwn", data=b'{"application":"' + b"x" * (1024 * 1024) + b'"}',
                               content_type="application/json")
        assert response.status_code == 413


class TestTokenAuth:
    def test_missing_header(self, client, redis, tokens_enabled):
        response = client.post("/pwn", json={"ip": IP_A, "application": "c2"})
        assert response.status_code == 401
        assert response.get_data(as_text=True).startswith("Not authorized. This server uses Access Tokens")

    @pytest.mark.parametrize("header", ["Bearer", "Bearer ", "Basic abc", "abc"])
    def test_malformed_header(self, client, redis, tokens_enabled, header):
        response = client.post("/pwn", json={"ip": IP_A, "application": "c2"}, headers={"Authorization": header})
        assert response.status_code == 401
        assert response.get_data(as_text=True) == "Please use Bearer Token (and Bearer keyword)\n"
        assert redis.llen("callback_queue") == 0

    def test_rejected_token(self, client, redis, tokens_enabled, monkeypatch):
        from pwnboard.web import endpoints
        monkeypatch.setattr(endpoints, "verifyAccessToken", lambda token, application: False)
        response = client.post("/pwn", json={"ip": IP_A, "application": "c2"}, headers={"Authorization": "Bearer nope"})
        assert response.status_code == 401
        assert response.get_data(as_text=True) == "Not authorized! Ensure 'application' field matches PWNBoard app name.\n"

    def test_valid_token_is_checked_against_the_payload_application(self, client, redis, tokens_enabled, valid_token):
        response = client.post("/pwn", json={"ip": IP_A, "application": "c2"}, headers={"Authorization": "bearer abc"})
        assert response.status_code == 200
        assert valid_token == [("abc", "c2")]

    def test_no_header_needed_when_tokens_are_disabled(self, client, redis, tokens_disabled):
        response = client.post("/pwn", json={"ip": IP_A, "application": "c2"})
        assert response.status_code == 200


class TestCredentials:
    BODY = {"ip": IP_A, "application": "c2", "username": "root", "password": "hunter2"}

    def test_valid_credentials_are_queued(self, client, redis, tokens_disabled):
        response = client.post("/creds", json=self.BODY)
        assert response.status_code == 200
        assert response.get_data(as_text=True) == "valid\n"
        [item] = queued(redis, "creds_queue")
        assert item["username"] == "root" and item["password"] == "hunter2"
        assert item["admin"] == -1  # unknown unless the sender says otherwise
        assert redis.llen("callback_queue") == 0

    @pytest.mark.parametrize("admin", [0, 1])
    def test_admin_flag(self, client, redis, tokens_disabled, admin):
        client.post("/creds", json={**self.BODY, "admin": admin})
        assert queued(redis, "creds_queue")[0]["admin"] == admin

    def test_admin_flag_must_be_0_or_1(self, client, redis, tokens_disabled):
        response = client.post("/creds", json={**self.BODY, "admin": 2})
        assert response.status_code == 400
        assert response.get_data(as_text=True) == "Invalid: admin must be set to either 0 (not admin) or 1 (admin)\n"

    @pytest.mark.parametrize("missing", ["application", "username", "password"])
    def test_required_fields(self, client, redis, tokens_disabled, missing):
        body = {k: v for k, v in self.BODY.items() if k != missing}
        response = client.post("/creds", json=body)
        assert response.status_code == 400
        assert response.get_data(as_text=True) == "Invalid: Missing 'username', 'password', or 'application' in the request\n"

    def test_password_must_be_a_string(self, client, redis, tokens_disabled):
        response = client.post("/creds", json={**self.BODY, "password": 1})
        assert response.status_code == 400

    def test_ips_list_works_for_credentials_too(self, client, redis, tokens_disabled):
        body = {k: v for k, v in self.BODY.items() if k != "ip"}
        response = client.post("/creds", json={**body, "ips": [IP_A, IP_B]})
        assert response.status_code == 200
        assert len(queued(redis, "creds_queue")) == 2

    def test_requires_a_token_like_callbacks(self, client, redis, tokens_enabled):
        assert client.post("/creds", json=self.BODY).status_code == 401


class TestWrongRequests:
    def test_get_is_not_allowed(self, client):
        assert client.get("/pwn").status_code == 405

    def test_removed_routes_stay_removed(self, client, tokens_disabled):
        assert client.post("/generic", json={"ip": IP_A, "application": "c2"}).status_code == 404
