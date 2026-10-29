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


def test_every_operation_declares_a_server_error(spec):
    for path, item in spec["paths"].items():
        for method, operation in item.items():
            assert "500" in operation["responses"], f"{method.upper()} {path} does not declare a 500"


def test_endpoints_that_need_a_login_declare_401(spec):
    for path, item in spec["paths"].items():
        for method, operation in item.items():
            if {"sessionCookie": []} in operation.get("security", []):
                assert "401" in operation["responses"], f"{method.upper()} {path} does not declare a 401"


def test_the_app_serves_the_spec_file(client):
    response = client.get("/openapi.yaml")
    assert response.status_code == 200
    assert response.mimetype == "application/yaml"
    assert response.get_data() == SPEC_PATH.read_bytes()


def schema_for(spec, path, content_type="application/json"):
    schema = spec["paths"][path]["post"]["requestBody"]["content"][content_type]["schema"]
    return validator(spec, schema)


class TestRequestSchemasMatchTheServer:
    """A few bodies the server accepts or rejects must get the same answer from the schema."""

    CRED = {"ip": IP_A, "application": "c2", "username": "root", "password": "pw"}

    def test_callback_bodies_that_work(self, spec):
        for body in ({"ip": IP_A, "application": "c2"}, {"ips": [IP_A], "application": "c2", "access_info": "x"}):
            assert schema_for(spec, "/pwn").is_valid(body)

    def test_callback_bodies_the_server_rejects(self, spec):
        for body in ({"application": "c2"}, {"ip": IP_A, "application": "a" * 65}):
            assert not schema_for(spec, "/pwn").is_valid(body)

    def test_credential_bodies(self, spec):
        assert schema_for(spec, "/creds").is_valid(self.CRED)
        assert not schema_for(spec, "/creds").is_valid({**self.CRED, "admin": 2})
