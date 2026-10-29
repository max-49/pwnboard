"""The token, user and account endpoints, which the web UI calls with a login session.

Every error from these endpoints is JSON: {"error": {"code": ..., "message": ..., "details": [...]}}.
Only the critical behaviour is covered: who may call what, and that accounts and tokens are
created, stored and removed correctly.
"""
import hashlib
import io
import time

import pytest

from pwnboard.web import endpoints

# (method, path) of every endpoint that needs a login
LOGIN_ONLY = [
    ("POST", "/tokens/create"),
    ("GET", "/tokens"),
    ("DELETE", "/tokens/abc"),
    ("POST", "/account/change_password"),
]
ADMIN_ONLY = [
    ("GET", "/admin/users"),
    ("POST", "/admin/users"),
    ("DELETE", "/admin/users/bob"),
    ("GET", "/admin/users/bob/tokens"),
    ("GET", "/admin/users/bulk_csv_template"),
    ("POST", "/admin/users/bulk"),
    ("POST", "/admin/users/bulk_csv"),
]


def call(client, method, path, **kwargs):
    return client.open(path, method=method, **kwargs)


def error(response):
    """The "error" object of a JSON error response."""
    assert response.mimetype == "application/json", response.get_data(as_text=True)
    return response.get_json()["error"]


def assert_error(response, status, code, message=None):
    assert response.status_code == status
    body = error(response)
    assert body["code"] == code
    if message is not None:
        assert body["message"] == message
    return body


class TestAccessControl:
    @pytest.mark.parametrize("method, path", LOGIN_ONLY + ADMIN_ONLY)
    def test_anonymous_requests_get_401(self, client, method, path):
        assert_error(call(client, method, path), 401, "unauthenticated")

    @pytest.mark.parametrize("path", ["/pwnboard", "/manage_user_accounts"])
    def test_anonymous_page_requests_still_redirect_to_the_login_page(self, client, path):
        response = client.get(path)
        assert response.status_code == 302
        assert response.headers["Location"] == "/"

    @pytest.mark.parametrize("method, path", ADMIN_ONLY)
    def test_admin_endpoints_reject_other_roles(self, login, method, path):
        assert_error(call(login("user"), method, path), 403, "forbidden")

    @pytest.mark.parametrize("role", ["guest", "restricted"])
    def test_guests_and_restricted_users_cannot_create_tokens(self, login, db, role):
        response = login(role).post("/tokens/create", data={"token_name": "n", "application": "a"})
        assert_error(response, 403, "forbidden")

    def test_restricted_users_cannot_change_passwords(self, login, db, monkeypatch):
        monkeypatch.setattr(endpoints, "changeUserPassword", lambda *args, **kwargs: True)
        response = login("restricted").post("/account/change_password", data={"old_pass": "a", "new_pass": "b"})
        assert_error(response, 403, "forbidden")

    @pytest.mark.parametrize("page, role, status", [("/manage_apps", "guest", 403), ("/manage_apps", "user", 200)])
    def test_pages_follow_the_same_role_rules_as_the_api(self, login, page, role, status):
        assert login(role).get(page).status_code == status

    def test_logout_clears_the_session(self, login, client):
        login("user")
        assert client.get("/logout").status_code == 302
        assert client.get("/tokens").status_code == 401  # no longer logged in


class TestUsers:
    def test_list_users(self, login, db):
        db.cur.fetchall.return_value = [{"username": "alice", "role": "user", "created": 1760000000},
                                        {"username": "bob", "role": "admin", "created": 1760000100}]
        response = login("admin").get("/admin/users")
        assert response.status_code == 200
        assert response.get_json() == [{"username": "alice", "role": "user", "created": 1760000000},
                                       {"username": "bob", "role": "admin", "created": 1760000100}]

    def test_create_user(self, login, db):
        response = login("admin").post("/admin/users", data={"username": "carol", "password": "pw", "role": "guest"})
        assert response.status_code == 201
        assert response.get_json() == {"username": "carol", "role": "guest"}
        insert = db.cur.execute.call_args_list[-1].args
        assert insert[0].startswith("INSERT INTO users")
        assert insert[1][0] == "carol" and insert[1][2] == "guest"
        assert insert[1][1].startswith("$argon2")  # the password is stored hashed

    def test_create_user_that_already_exists(self, login, db):
        db.cur.fetchone.return_value = (1,)
        response = login("admin").post("/admin/users", data={"username": "carol", "password": "pw", "role": "user"})
        assert_error(response, 409, "user_exists", "User already exists")

    @pytest.mark.parametrize("form, message", [
        ({"username": 'x"><img src=x>', "password": "pw"}, "Invalid username: only letters, digits, _, ., - are allowed (max 64 characters)"),
        ({"username": "bob", "password": "pw", "role": "superadmin"}, "Invalid role"),
    ])
    def test_create_user_validation(self, login, db, form, message):
        response = login("admin").post("/admin/users", data=form)
        assert_error(response, 400, "invalid_request", message)

    def test_delete_user(self, login, db):
        db.cur.fetchone.return_value = (1,)
        response = login("admin").delete("/admin/users/bob")
        assert response.status_code == 204

    def test_admins_cannot_delete_themselves(self, login, db):
        response = login("admin", username="root").delete("/admin/users/root")
        assert_error(response, 400, "invalid_request", "Cannot delete current user")


class TestTokens:
    def test_create_token_returns_it_once_and_stores_only_its_hash(self, login, db):
        response = login("user").post("/tokens/create", data={"token_name": "deploy", "application": "c2"})
        assert response.status_code == 201
        assert response.mimetype == "application/json"
        token = response.get_json()["token"]
        insert = db.cur.execute.call_args_list[-1].args
        assert insert[0].lstrip().startswith("INSERT INTO access_tokens")
        assert insert[1][0] == hashlib.sha256(token.encode()).hexdigest()
        assert token not in insert[1]
        assert insert[1][5] == token[:3]  # only the first characters are kept for display

    def test_zero_means_no_expiry(self, login, db):
        login("user").post("/tokens/create", data={"token_name": "n", "application": "a", "expiry": "0"})
        assert db.cur.execute.call_args_list[-1].args[1][7] is None

    def test_default_expiry_is_seven_days(self, login, db):
        login("user").post("/tokens/create", data={"token_name": "n", "application": "a"})
        params = db.cur.execute.call_args_list[-1].args[1]
        assert params[7] - params[6] == 7 * 86400
        assert abs(params[6] - time.time()) < 5

    def test_a_token_needs_a_name(self, login, db):
        response = login("user").post("/tokens/create", data={"token_name": "", "application": "a"})
        assert_error(response, 400, "invalid_request", "Token name is required (max 64 characters)")

    def test_list_own_tokens(self, login, db):
        row = {"hash": "h1", "token_name": "t", "application": "a", "description": "", "username": "tester",
               "created": 1760000000, "expires": 1760600000, "prefix": "abc"}
        db.cur.fetchall.return_value = [row]
        response = login("user", username="tester").get("/tokens")
        assert response.status_code == 200
        assert response.get_json() == [row]
        assert db.cur.execute.call_args.args[1] == ("tester",)

    def test_delete_own_token(self, login, db):
        db.cur.fetchone.return_value = {"username": "tester"}
        db.cur.rowcount = 1
        assert login("user", username="tester").delete("/tokens/h1").status_code == 204

    def test_users_cannot_delete_other_peoples_tokens(self, login, db):
        db.cur.fetchone.return_value = {"username": "someone-else"}
        assert_error(login("user", username="tester").delete("/tokens/h1"), 403, "forbidden")


class TestBulkUsers:
    def test_bulk_create(self, login, db):
        response = login("admin").post("/admin/users/bulk", data={"usernames": "a, b ,c", "password": "pw", "role": "user"})
        assert response.status_code == 200
        assert response.get_json() == {"created": ["a", "b", "c"], "failed": []}

    def test_bulk_rejects_bad_usernames_before_creating_anyone(self, login, db):
        response = login("admin").post("/admin/users/bulk", data={"usernames": "good,<bad>", "password": "pw"})
        body = assert_error(response, 400, "validation_failed")
        assert len(body["details"]) == 1 and "Invalid username '<bad>'" in body["details"][0]
        assert not any(c.args[0].lstrip().startswith("INSERT") for c in db.cur.execute.call_args_list)

    def test_csv_create(self, login, db):
        text = "username,password,role\nalice,pw1,user\nbob,pw2,admin\n"
        response = login("admin").post("/admin/users/bulk_csv", content_type="multipart/form-data",
                                       data={"file": (io.BytesIO(text.encode()), "users.csv")})
        assert response.status_code == 200
        assert response.get_json() == {"created": ["alice", "bob"], "failed": []}


class TestChangePassword:
    def test_success_ends_the_session(self, login, client, monkeypatch):
        monkeypatch.setattr(endpoints, "changeUserPassword", lambda *args, **kwargs: True)
        response = login("user").post("/account/change_password", data={"old_pass": "a", "new_pass": "b"})
        assert response.status_code == 200
        assert response.get_json() == {"message": "Password changed"}
        assert client.get("/tokens").status_code == 401  # logged out

    def test_failure(self, login, monkeypatch):
        monkeypatch.setattr(endpoints, "changeUserPassword", lambda *args, **kwargs: False)
        response = login("user").post("/account/change_password", data={"old_pass": "a", "new_pass": "b"})
        assert_error(response, 400, "invalid_request", "Password change failed")


BROWSER = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}


class TestFrameworkErrors:
    """404, 405, 413 and crashes are JSON for API clients and the normal HTML page for browsers."""

    def test_unknown_path_is_a_json_404(self, client):
        assert_error(client.get("/no-such-page"), 404, "not_found")

    def test_oversized_body_is_a_json_413(self, client, tokens_disabled):
        response = client.post("/pwn", data=b"x" * (1024 * 1024 + 1), content_type="application/json")
        assert_error(response, 413, "request_entity_too_large")

    def test_browsers_still_get_html_error_pages(self, client):
        response = client.get("/no-such-page", headers=BROWSER)
        assert response.status_code == 404
        assert response.mimetype == "text/html"

    def test_unexpected_exceptions_are_logged_and_become_a_json_500(self, login, db, monkeypatch, caplog):
        def boom(username):
            raise RuntimeError("database is on fire")
        monkeypatch.setattr(endpoints, "list_user_tokens", boom)
        with caplog.at_level("ERROR", logger="pwnboard"):
            response = login("user").get("/tokens")
        body = assert_error(response, 500, "internal_server_error")
        assert "on fire" not in body["message"]  # internals are not shown to the client
        assert "Unhandled error on GET /tokens" in caplog.text
