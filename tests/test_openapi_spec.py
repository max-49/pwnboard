"""The OpenAPI description must be valid and must stay in step with the code.

On top of these tests, every request that the other test modules make is checked against the
spec (see the `client` fixture): the status code and content type of each response must be
declared, JSON bodies must match their schema, and any request body the server accepts must be
valid according to the spec.
"""
import pytest
from openapi_spec_validator import validate

from tests.conftest import IP_A
from tests.spec_helpers import SPEC_PATH, flask_routes, spec_routes, validator


def test_spec_is_valid_openapi(spec):
    validate(spec)


def test_every_endpoint_is_described_and_nothing_extra_is(spec):
    served, described = flask_routes(), spec_routes(spec)
    assert served - described == set(), "endpoints missing from openapi.yaml"
    assert described - served == set(), "openapi.yaml describes endpoints the app does not serve"


def test_operation_ids_are_unique(spec):
    ids = [op["operationId"] for item in spec["paths"].values() for op in item.values() if isinstance(op, dict)]
    assert len(ids) == len(set(ids))


def test_the_app_serves_the_spec_file(client):
    response = client.get("/openapi.yaml")
    assert response.status_code == 200
    assert response.mimetype == "application/yaml"
    assert response.get_data() == SPEC_PATH.read_bytes()


def schema_for(spec, path, content_type="application/json"):
    schema = spec["paths"][path]["post"]["requestBody"]["content"][content_type]["schema"]
    return validator(spec, schema)


class TestRequestSchemasMatchTheServer:
    """Bodies the server rejects because of their shape or size must also fail the schema."""

    OK = {"ip": IP_A, "application": "c2"}

    @pytest.mark.parametrize("path", ["/pwn", "/checkin"])
    @pytest.mark.parametrize("body", [
        {"ip": IP_A, "application": "c2"},
        {"ips": [IP_A, "10.2.1.1"], "application": "c2", "access_info": "x", "server": "s", "message": "m"},
        {"ip": IP_A, "application": "c2", "unlisted_field": [1, 2]},
        {"challenge": "anything"},
        {"challenge": 12},
    ])
    def test_callback_bodies_that_work(self, spec, path, body):
        assert schema_for(spec, path).is_valid(body)

    @pytest.mark.parametrize("body", [
        [1],
        {"application": "c2"},
        {"ip": IP_A},
        {"ip": [1], "application": "c2"},
        {"ip": "1" * 46, "application": "c2"},
        {"ip": IP_A, "application": 5},
        {"ip": IP_A, "application": "a" * 65},
        {"ip": IP_A, "application": "c2", "access_info": "x" * 2001},
        {"ips": [1], "application": "c2"},
        {"ips": [IP_A] * 1001, "application": "c2"},
    ])
    def test_callback_bodies_the_server_rejects(self, spec, body):
        assert not schema_for(spec, "/pwn").is_valid(body)

    CRED = {"ip": IP_A, "application": "c2", "username": "root", "password": "pw"}

    @pytest.mark.parametrize("body", [
        CRED,
        {**CRED, "admin": 0},
        {**CRED, "admin": 1},
        {**{k: v for k, v in CRED.items() if k != "ip"}, "ips": [IP_A]},
    ])
    def test_credential_bodies_that_work(self, spec, body):
        assert schema_for(spec, "/creds").is_valid(body)

    @pytest.mark.parametrize("body", [
        {k: v for k, v in CRED.items() if k != "username"},
        {k: v for k, v in CRED.items() if k != "password"},
        {k: v for k, v in CRED.items() if k != "application"},
        {k: v for k, v in CRED.items() if k != "ip"},
        {**CRED, "admin": 2},
        {**CRED, "password": 1},
        {**CRED, "username": "u" * 257},
        {**CRED, "password": "p" * 257},
    ])
    def test_credential_bodies_the_server_rejects(self, spec, body):
        assert not schema_for(spec, "/creds").is_valid(body)


class TestFormSchemasMatchTheServer:
    @pytest.mark.parametrize("path, form", [
        ("/admin/users", {"username": "x" * 65, "password": "pw"}),
        ("/admin/users", {"username": "bad name", "password": "pw"}),
        ("/admin/users", {"username": "bob", "password": "p" * 129}),
        ("/admin/users", {"username": "bob", "password": "pw", "role": "superadmin"}),
        ("/tokens/create", {"token_name": "n" * 65, "application": "a"}),
        ("/tokens/create", {"token_name": "n", "application": "a" * 65}),
        ("/tokens/create", {"token_name": "n", "application": "a", "description": "d" * 257}),
        ("/account/change_password", {"old_pass": "a", "new_pass": "n" * 129}),
    ])
    def test_forms_the_server_rejects(self, spec, path, form):
        schema = schema_for(spec, path, "application/x-www-form-urlencoded")
        assert not schema.is_valid(form)

    @pytest.mark.parametrize("path, form", [
        ("/admin/users", {"username": "a.b-c_9", "password": "pw", "role": "guest"}),
        ("/tokens/create", {"token_name": "n", "application": "a", "description": "d", "expiry": "7d"}),
        ("/account/change_password", {"old_pass": "a", "new_pass": "b"}),
    ])
    def test_forms_that_work(self, spec, path, form):
        schema = schema_for(spec, path, "application/x-www-form-urlencoded")
        assert schema.is_valid(form)
