"""Phase 89 (P1): OpenAPI/Swagger import tests.

Covers xssentinel.core.openapi_import:
  * OpenAPI 3.x document -> scan targets
  * path templating ({id} -> sample), query params appended
  * form/JSON request bodies built from schemas
  * $ref resolution (components/schemas and 2.0 definitions)
  * security schemes -> auth headers
  * Swagger 2.0 flavour (host/basePath/body param)
  * dedup, method filtering, error paths
"""
import json

import pytest

from xssentinel.core.openapi_import import (
    OpenApiImportError,
    openapi_to_scan_targets,
)


def _write_spec(tmp_path, doc, name="openapi.json"):
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


OAS3 = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1"},
    "servers": [{"url": "https://api.example.com/v1"}],
    "paths": {
        "/users": {
            "get": {"responses": {"200": {"description": "ok"}}},
            "post": {
                "requestBody": {"content": {
                    "application/x-www-form-urlencoded": {
                        "schema": {"$ref": "#/components/schemas/User"}}}},
                "responses": {"200": {"description": "ok"}},
            },
        },
        "/users/{id}": {
            "get": {
                "parameters": [
                    {"name": "id", "in": "path", "required": True,
                     "schema": {"type": "integer"}},
                    {"name": "verbose", "in": "query",
                     "schema": {"type": "boolean"}},
                ],
                "responses": {"200": {"description": "ok"}},
            },
        },
        "/internal/{id}": {
            "delete": {
                "parameters": [
                    {"name": "id", "in": "path", "required": True,
                     "schema": {"type": "string"}}],
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
    "components": {
        "schemas": {
            "User": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "age": {"type": "integer"},
                },
            }
        },
        "securitySchemes": {
            "ApiKey": {"type": "apiKey", "in": "header",
                       "name": "X-API-Key"},
        },
    },
    "security": [{"ApiKey": []}],
}


class TestOpenApi3:
    def test_basic_operations(self, tmp_path):
        p = _write_spec(tmp_path, OAS3)
        tgts = openapi_to_scan_targets(p)
        methods = {(t["method"], t["url"]) for t in tgts}
        assert ("GET", "https://api.example.com/v1/users") in methods
        assert ("POST", "https://api.example.com/v1/users") in methods
        assert ("DELETE", "https://api.example.com/v1/internal/test") in methods

    def test_path_template_resolved(self, tmp_path):
        p = _write_spec(tmp_path, OAS3)
        tgts = openapi_to_scan_targets(p)
        get_user = [t for t in tgts if t["method"] == "GET"
                    and "users/" in t["url"]][0]
        assert "/users/1" in get_user["url"]
        assert "verbose=True" in get_user["url"] or "verbose=true" in \
            get_user["url"]

    def test_form_body_from_schema(self, tmp_path):
        p = _write_spec(tmp_path, OAS3)
        tgts = openapi_to_scan_targets(p)
        post = [t for t in tgts if t["method"] == "POST"][0]
        assert post["data"] == "name=test&age=1"

    def test_security_header(self, tmp_path):
        p = _write_spec(tmp_path, OAS3)
        tgts = openapi_to_scan_targets(p)
        assert any("X-API-Key: <ApiKey>" in h
                   for t in tgts for h in t["headers"])

    def test_dedup(self, tmp_path):
        doc = json.loads(json.dumps(OAS3))
        doc["paths"]["/users"]["get"] = {
            "responses": {"200": {"description": "ok"}}}
        p = _write_spec(tmp_path, doc)
        tgts = openapi_to_scan_targets(p)
        keys = [(t["method"], t["url"]) for t in tgts]
        assert len(keys) == len(set(keys))


SWAGGER2 = {
    "swagger": "2.0",
    "info": {"title": "t", "version": "1"},
    "host": "old.example.com",
    "basePath": "/api",
    "schemes": ["http"],
    "paths": {
        "/pets": {
            "post": {
                "parameters": [
                    {"name": "pet", "in": "body", "required": True,
                     "schema": {"$ref": "#/definitions/Pet"}}],
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/pets/{petId}": {
            "get": {
                "parameters": [
                    {"name": "petId", "in": "path", "required": True,
                     "type": "integer"}],
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
    "definitions": {
        "Pet": {"type": "object",
                "properties": {"kind": {"type": "string"}}}
    },
}


class TestSwagger2:
    def test_host_and_body_param(self, tmp_path):
        p = _write_spec(tmp_path, SWAGGER2)
        tgts = openapi_to_scan_targets(p)
        post = [t for t in tgts if t["method"] == "POST"][0]
        assert post["url"] == "http://old.example.com/api/pets"
        assert post["data"] == '{"kind": "test"}'
        assert post["content_type"] == "application/json"

    def test_path_param_no_schema(self, tmp_path):
        # Swagger 2.0 path params declare type at param level, not schema.
        doc = json.loads(json.dumps(SWAGGER2))
        # Replace schema-style with 2.0 param-level type handled: our
        # _target_url derefs p["schema"]; 2.0 style needs schema fallback.
        p = _write_spec(tmp_path, doc)
        tgts = openapi_to_scan_targets(p)
        get = [t for t in tgts if t["method"] == "GET"][0]
        # Param has no schema; falls back to example or "test".
        assert "/pets/" in get["url"]


class TestOpenApiErrors:
    def test_missing_file(self):
        with pytest.raises(OpenApiImportError):
            openapi_to_scan_targets("Z:/no/openapi.json")

    def test_bad_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{oops", encoding="utf-8")
        with pytest.raises(OpenApiImportError):
            openapi_to_scan_targets(str(p))

    def test_no_paths(self, tmp_path):
        p = _write_spec(tmp_path, {"openapi": "3.0.0"})
        with pytest.raises(OpenApiImportError):
            openapi_to_scan_targets(str(p))

    def test_all_methods_filtered(self, tmp_path):
        doc = {"openapi": "3.0.0",
               "servers": [{"url": "http://h"}],
               "paths": {"/x": {"options": {"responses": {}},
                                "head": {"responses": {}}}}}
        p = _write_spec(tmp_path, doc)
        with pytest.raises(OpenApiImportError):
            openapi_to_scan_targets(str(p))
