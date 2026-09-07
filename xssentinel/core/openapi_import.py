"""OpenAPI / Swagger import for batch scanning (Phase 89 / P1).

A Swagger/OpenAPI document is the *declared* contract of an API: every
path + operation + parameter schema is an endpoint the scanner should
probe.  This complements HAR (observed traffic) with documented surface
-- including endpoints the browser never hit (admin routes, hidden
params, undocumented POST bodies).

``openapi_to_scan_targets()`` walks the document:

  * each ``paths[path][method]`` operation becomes one scan target;
  * path templating: ``/users/{id}`` is resolved to a concrete URL by
    substituting an example value for every path parameter (the OpenAPI
    ``example``/``examples``/``default``/``schema.example`` chain, else a
    type-derived sample such as ``1`` for integers);
  * query parameters become part of the URL;
  * requestBody ``application/x-www-form-urlencoded`` becomes form data,
    ``application/json`` becomes a raw JSON body (with a minimal example
    object built from the schema);
  * security schemes become headers (``apiKey`` in header -> ``X-Key:``,
    http bearer -> ``Authorization: Bearer``) so authenticated endpoints
    are scanned with their auth in place;
  * only GET/POST/PUT/PATCH/DELETE operations are kept (no OPTIONS/HEAD).

The module is pure (returns plain dicts, no Scanner imports) and mirrors
``core/har_import.py`` so the batch loop can consume either source.
"""
from __future__ import annotations

import json
from urllib.parse import urlencode, urlparse, urlunparse


class OpenApiImportError(ValueError):
    """Raised when an OpenAPI document cannot be parsed into targets."""


#: OpenAPI 2.0 (Swagger) uses a different container key for the schema.
_HTTP_METHODS = ("get", "post", "put", "patch", "delete")


def _sample_for_schema(schema: dict) -> object:
    """Best-effort example value for a (sub)schema."""
    if not isinstance(schema, dict):
        return None
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]
    typ = schema.get("type")
    if typ == "string":
        fmt = schema.get("format")
        if fmt == "date-time":
            return "2026-01-01T00:00:00Z"
        if fmt == "date":
            return "2026-01-01"
        if fmt == "email":
            return "user@example.com"
        if fmt == "uuid":
            return "00000000-0000-0000-0000-000000000000"
        if fmt == "uri":
            return "https://example.com/"
        return "test"
    if typ == "integer":
        return 1
    if typ == "number":
        return 1.5
    if typ == "boolean":
        return True
    if typ == "array":
        return [_sample_for_schema(schema.get("items") or {})]
    if typ == "object":
        props = schema.get("properties") or {}
        return {k: _sample_for_schema(v) for k, v in props.items()}
    if "$ref" in schema:
        return None  # caller resolves refs against the doc
    return None


def _resolve_ref(ref: str, doc: dict) -> dict:
    """Resolve a JSON-pointer-ish ref against the document.

    OpenAPI 3.x keeps schemas under ``#/components/schemas/``; Swagger
    2.0 under ``#/definitions/``.  A plain JSON pointer walk covers both.
    """
    if not ref.startswith("#/"):
        return {}
    node = doc
    for part in ref[2:].split("/"):
        if not isinstance(node, dict) or part not in node:
            return {}
        node = node[part]
    return node if isinstance(node, dict) else {}


def _deref(schema: dict, doc: dict, _depth: int = 0) -> dict:
    """Follow $ref chains (bounded) inside a schema."""
    if _depth > 12 or not isinstance(schema, dict):
        return schema if isinstance(schema, dict) else {}
    if "$ref" in schema:
        resolved = _resolve_ref(schema["$ref"], doc)
        merged = dict(resolved)
        merged.update({k: v for k, v in schema.items() if k != "$ref"})
        return _deref(merged, doc, _depth + 1)
    return schema


def _target_url(scheme: str, host: str, base_path: str,
                path: str, params: list[dict], doc: dict) -> str:
    """Build a concrete URL for one operation.

    Path parameters (``{id}`` style) get sample values; query parameters
    with an example/default get appended.
    """
    url_path = path
    for p in params:
        if p.get("in") != "path":
            continue
        name = p.get("name")
        if not name:
            continue
        sch = _deref(p.get("schema") or {}, doc)
        val = _sample_for_schema(sch)
        if val is None:
            val = p.get("example") or "test"
        url_path = url_path.replace("{" + name + "}", str(val))
    query: dict[str, str] = {}
    for p in params:
        if p.get("in") != "query":
            continue
        name = p.get("name")
        if not name:
            continue
        val = p.get("example")
        if val is None and p.get("schema"):
            val = _sample_for_schema(_deref(p["schema"], doc))
        if val is not None:
            query[name] = str(val)
    base = f"{scheme}://{host}{base_path}"
    path_full = base.rstrip("/") + "/" + url_path.lstrip("/")
    if query:
        return path_full + "?" + urlencode(query)
    return path_full


def openapi_to_scan_targets(spec_path: str,
                            max_targets: int = 0) -> list[dict]:
    """Load an OpenAPI/Swagger doc and return scan-target dicts.

    Supports OpenAPI 3.x (``components/schemas``) and Swagger 2.0
    (``definitions``).  ``max_targets`` caps the result (after dedup).

    Raises :class:`OpenApiImportError` on missing file / invalid JSON /
    no paths / no scannable operations.
    """
    try:
        with open(spec_path, "r", encoding="utf-8",
                  errors="replace") as fh:
            doc = json.load(fh)
    except OSError as e:
        raise OpenApiImportError(f"cannot read OpenAPI file: {e}") from e
    except json.JSONDecodeError as e:
        raise OpenApiImportError(
            f"OpenAPI file is not valid JSON: {e}") from e
    if not isinstance(doc, dict) or "paths" not in doc:
        raise OpenApiImportError(
            f"not an OpenAPI/Swagger document (no paths): {spec_path}")
    paths = doc.get("paths") or {}
    if not isinstance(paths, dict) or not paths:
        raise OpenApiImportError(
            f"OpenAPI document has no paths ({spec_path})")
    _DOC = doc

    # Server / host resolution (3.x servers[] vs 2.0 host+basePath+schemes).
    servers = doc.get("servers") or []
    if servers and isinstance(servers[0], dict):
        su = servers[0].get("url") or ""
        pu = urlparse(su if "://" in su else "https://" + su)
        scheme, host, base_path = (
            pu.scheme or "https", pu.netloc, pu.path.rstrip("/"))
    else:
        scheme = (doc.get("schemes") or ["https"])[0]
        host = doc.get("host") or ""
        if not host:
            host = "localhost"
        base_path = (doc.get("basePath") or "").rstrip("/")

    seen: set[str] = set()
    targets: list[dict] = []
    for path, ops in (paths or {}).items():
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            params = list(op.get("parameters") or [])
            # Path-level parameters inherited by every operation.
            path_params = list((paths.get(path) or {}).get(
                "parameters") or [])
            all_params = params + [
                p for p in path_params
                if not any(p.get("name") == x.get("name")
                           and p.get("in") == x.get("in")
                           for x in params)]
            url = _target_url(scheme, host, base_path, path, all_params,
                              doc)
            if not url:
                continue

            # Request body -> data carrier.
            data = ""
            content_type = "application/x-www-form-urlencoded"
            rb = op.get("requestBody") or {}
            content = (rb.get("content")
                       if isinstance(rb, dict) else None) or {}
            if content:
                if "application/x-www-form-urlencoded" in content:
                    sch = content["application/x-www-form-urlencoded"].get(
                        "schema") or {}
                    sch = _deref(sch, doc)
                    props = sch.get("properties") or {}
                    data = urlencode({k: str(_sample_for_schema(
                        _deref(v, doc)) if _deref(v, doc) else "test")
                        for k, v in props.items()})
                elif "application/json" in content:
                    sch = content["application/json"].get("schema") or {}
                    sch = _deref(sch, doc)
                    sample = _sample_for_schema(sch)
                    if sample is not None:
                        data = json.dumps(sample)
                    content_type = "application/json"
            # Swagger 2.0 body parameter.
            elif any(p.get("in") == "body" for p in all_params):
                bp = next(p for p in all_params if p.get("in") == "body")
                sch = _deref(bp.get("schema") or {}, doc)
                sample = _sample_for_schema(sch)
                if sample is not None:
                    data = json.dumps(sample)
                content_type = "application/json"

            # Security -> headers (apiKey/header, apiKey/query, http bearer).
            headers: list[str] = []
            sec = op.get("security") or doc.get("security") or []
            if sec and isinstance(sec, list):
                schemes_map = (doc.get("components") or {}).get(
                    "securitySchemes") or (doc.get("securityDefinitions") or {})
                for req in sec:
                    if not isinstance(req, dict):
                        continue
                    for sname in req:
                        sdef = schemes_map.get(sname) or {}
                        stype = sdef.get("type")
                        if stype == "apiKey":
                            loc = sdef.get("in")
                            if loc == "header":
                                headers.append(
                                    f"{sdef.get('name', 'X-API-Key')}: "
                                    f"<{sname}>")
                            elif loc == "query":
                                # Attach as query param marker in URL later.
                                pass
                        elif stype == "http" and sdef.get(
                                "scheme") == "bearer":
                            headers.append("Authorization: Bearer <token>")
                        elif stype == "basic":
                            headers.append("Authorization: Basic <creds>")

            key = (f"{method.upper()} {url} {data} "
                   f"{';'.join(headers)}")
            if key in seen:
                continue
            seen.add(key)
            targets.append({
                "idx": len(targets),
                "method": method.upper(),
                "url": url,
                "data": data,
                "content_type": content_type,
                "cookies": [],
                "headers": headers,
            })
            if max_targets and len(targets) >= max_targets:
                break

    if not targets:
        raise OpenApiImportError(
            f"OpenAPI document yields no scannable operations ({spec_path})")
    return targets
