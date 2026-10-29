"""The beacon and credential endpoints (/pwn, /checkin, /creds) that red team tools depend on.

Only what tools rely on is covered: valid data is accepted and queued, bad data and bad
tokens are refused, and nothing is queued when a request is refused.
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
        ({"ip": IP_A}, "Invalid: Missing 'application' field in the request"),
        ({"ip": IP_A, "application": "a" * 65}, "Invalid: 'application' must be a string of at most 64 characters\n"),
        ({"ips": [1], "application": "c2"}, "Invalid: 'ips' must be a list of strings\n"),
    ])
    def test_bad_payloads_return_400_and_queue_nothing(self, client, redis, tokens_disabled, body, message):
        response = client.post("/pwn", json=body)
        assert response.status_code == 400
        assert response.get_data(as_text=True) == message
        assert redis.llen("callback_queue") == 0

    def test_invalid_json_returns_400(self, client, tokens_disabled):
        response = client.post("/pwn", data="{not json", content_type="application/json")
        assert response.status_code == 400


class TestTokenAuth:
    def test_missing_header(self, client, redis, tokens_enabled):
        response = client.post("/pwn", json={"ip": IP_A, "application": "c2"})
        assert response.status_code == 401
        assert redis.llen("callback_queue") == 0

    @pytest.mark.parametrize("header", ["Bearer", "Basic abc"])
    def test_malformed_header(self, client, redis, tokens_enabled, header):
        response = client.post("/pwn", json={"ip": IP_A, "application": "c2"}, headers={"Authorization": header})
        assert response.status_code == 401
        assert redis.llen("callback_queue") == 0

    def test_a_valid_token_is_accepted_whatever_the_application(self, client, redis, tokens_enabled, valid_token):
        for application in ("c2", "scanner"):
            response = client.post("/pwn", json={"ip": IP_A, "application": application},
                                   headers={"Authorization": "bearer abc"})
            assert response.status_code == 200
        assert valid_token == ["abc", "abc"]

    def test_no_header_needed_when_tokens_are_disabled(self, client, redis, tokens_disabled):
        response = client.post("/pwn", json={"ip": IP_A, "application": "c2"})
        assert response.status_code == 200


class TestTokenLookup:
    """The real token check against a fake database, instead of the valid_token shortcut."""

    def token_row(self, application="c2", expires=None):
        return {"token_name": "deploy", "application": application, "description": "", "username": "bob",
                "created": 1760000000, "expires": expires, "prefix": "abc"}

    @pytest.mark.parametrize("path, body", [
        ("/pwn", {"ip": IP_A, "application": "totally-different"}),
        ("/creds", {"ip": IP_A, "application": "totally-different", "username": "u", "password": "pw"}),
        ("/info", {"ip": IP_A, "application": "totally-different", "key": "k", "value": "v"}),
    ])
    def test_a_token_works_on_every_ingest_endpoint(self, client, redis, tokens_enabled, db, path, body):
        db.cur.fetchone.return_value = self.token_row(application="c2")
        response = client.post(path, json=body, headers={"Authorization": "Bearer abc"})
        assert response.status_code == 200

    def test_unknown_tokens_are_rejected(self, client, redis, tokens_enabled, db):
        db.cur.fetchone.return_value = None
        response = client.post("/pwn", json={"ip": IP_A, "application": "c2"}, headers={"Authorization": "Bearer nope"})
        assert response.status_code == 401
        assert redis.llen("callback_queue") == 0

    def test_expired_tokens_are_rejected(self, client, redis, tokens_enabled, db):
        db.cur.fetchone.return_value = self.token_row(expires=1)
        response = client.post("/pwn", json={"ip": IP_A, "application": "c2"}, headers={"Authorization": "Bearer abc"})
        assert response.status_code == 401

    def test_the_lookup_uses_the_hash_of_the_token(self, client, redis, tokens_enabled, db):
        import hashlib
        db.cur.fetchone.return_value = self.token_row()
        client.post("/pwn", json={"ip": IP_A, "application": "c2"}, headers={"Authorization": "Bearer secret-token"})
        assert db.cur.execute.call_args.args[1] == (hashlib.sha256(b"secret-token").hexdigest(),)


class TestCredentials:
    BODY = {"ip": IP_A, "application": "c2", "username": "root", "password": "hunter2"}

    def test_valid_credentials_are_queued(self, client, redis, tokens_disabled):
        response = client.post("/creds", json=self.BODY)
        assert response.status_code == 200
        assert response.get_data(as_text=True) == "valid\n"
        [item] = queued(redis, "creds_queue")
        assert item["username"] == "root" and item["password"] == "hunter2"
        assert redis.llen("callback_queue") == 0

    def test_the_admin_flag_is_passed_on_and_must_be_0_or_1(self, client, redis, tokens_disabled):
        client.post("/creds", json={**self.BODY, "admin": 1})
        assert queued(redis, "creds_queue")[0]["admin"] == 1
        assert client.post("/creds", json={**self.BODY, "admin": 2}).status_code == 400

    def test_required_fields(self, client, redis, tokens_disabled):
        body = {k: v for k, v in self.BODY.items() if k != "password"}
        assert client.post("/creds", json=body).status_code == 400
        assert redis.llen("creds_queue") == 0

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
