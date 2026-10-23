"""Check test requests and responses against pwnboard/web/openapi.yaml."""
import json
import re
from pathlib import Path

import jsonschema
import yaml

from pwnboard.web import app

SPEC_PATH = Path(__file__).parent.parent / "pwnboard" / "web" / "openapi.yaml"

# Pages and static files, which the spec does not describe
NON_API_ENDPOINTS = {
    "static", "login", "login_post", "index", "manage_apps", "account_settings",
    "manage_user_accounts", "logout",
}


def load_spec():
    return yaml.safe_load(SPEC_PATH.read_text())


def flask_routes():
    """Every (METHOD, '/path/{param}') that the app serves and the spec should describe."""
    routes = set()
    for rule in app.url_map.iter_rules():
        if rule.endpoint in NON_API_ENDPOINTS:
            continue
        path = re.sub(r"<(?:[^:>]+:)?([^>]+)>", r"{\1}", rule.rule)
        for method in rule.methods - {"HEAD", "OPTIONS"}:
            routes.add((method, path))
    return routes


def spec_routes(spec):
    return {(method.upper(), path)
            for path, item in spec["paths"].items()
            for method in item if method in {"get", "post", "put", "patch", "delete"}}


def validator(spec, schema):
    """A JSON Schema validator for a schema from the spec, with its $refs resolved."""
    root = {**schema, "components": spec["components"]}
    return jsonschema.Draft202012Validator(root)


def _resolve(spec, node):
    while isinstance(node, dict) and "$ref" in node:
        target = spec
        for part in node["$ref"].lstrip("#/").split("/"):
            target = target[part]
        node = target
    return node


class SpecChecker:
    """Asserts that a response (and the request that produced it) matches the spec."""

    def __init__(self, spec):
        self.spec = spec
        self.adapter = app.url_map.bind("localhost")

    def operation(self, request):
        from werkzeug.exceptions import HTTPException
        try:
            rule, _ = self.adapter.match(request.path, method=request.method, return_rule=True)
        except HTTPException:
            return None, None  # unknown route or method: the spec does not describe those
        template = re.sub(r"<(?:[^:>]+:)?([^>]+)>", r"{\1}", rule.rule)
        item = self.spec["paths"].get(template, {})
        return template, item.get(request.method.lower())

    def check(self, response, request_json=None):
        template, operation = self.operation(response.request)
        if operation is None:
            return
        where = f"{response.request.method} {template}"

        declared = operation["responses"]
        key = str(response.status_code)
        assert key in declared or "default" in declared, \
            f"{where} returned {key}, which openapi.yaml does not declare (declared: {sorted(declared)})"
        declared_response = _resolve(self.spec, declared.get(key, declared.get("default")))

        content = declared_response.get("content", {})
        if response.get_data():
            assert response.mimetype in content, \
                f"{where} {key} returned {response.mimetype}, but openapi.yaml declares {sorted(content)}"
            if response.mimetype == "application/json":
                schema = _resolve(self.spec, content["application/json"])["schema"]
                errors = list(validator(self.spec, schema).iter_errors(response.get_json()))
                assert not errors, f"{where} {key} body does not match the spec: {errors[0].message}"
        else:
            assert response.status_code in (204, 201, 302) or not content, \
                f"{where} {key} returned no body, but openapi.yaml declares {sorted(content)}"

        # Anything the server accepted must also be valid according to the spec
        body_spec = operation.get("requestBody", {}).get("content", {}).get("application/json")
        if body_spec and response.status_code == 200 and request_json is not None:
            errors = list(validator(self.spec, _resolve(self.spec, body_spec)["schema"]).iter_errors(request_json))
            assert not errors, f"{where}: the server accepted a body the spec rejects: {errors[0].message}"


def request_json(kwargs):
    """The JSON body a test passed to the test client, or None if it did not send JSON."""
    if "json" in kwargs:
        return kwargs["json"]
    data = kwargs.get("data")
    if isinstance(data, (str, bytes)):
        try:
            return json.loads(data)
        except ValueError:
            return None
    return None
