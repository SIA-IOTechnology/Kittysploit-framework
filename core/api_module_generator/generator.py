#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generate KittySploit API scanner/fuzzer modules from schemas or traffic."""

import json
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse


HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


@dataclass
class ApiEndpoint:
    method: str
    path: str
    summary: str = ""
    operation_id: str = ""
    parameters: List[str] = field(default_factory=list)
    request_body_fields: List[str] = field(default_factory=list)
    expected_statuses: List[int] = field(default_factory=list)
    content_types: List[str] = field(default_factory=list)


@dataclass
class ApiSpec:
    name: str
    source_type: str
    version: str = ""
    description: str = ""
    endpoints: List[ApiEndpoint] = field(default_factory=list)


@dataclass
class ApiModuleGenerationResult:
    module_files: List[Path]
    artifact_files: List[Path]
    manifest: Dict[str, Any]


class ApiModuleGenerator:
    """Generate scanners, fuzzers, fixtures and tests from API descriptions."""

    DEFAULT_MODULE_DIR = Path("modules") / "generated" / "api"
    DEFAULT_ARTIFACT_DIR = Path("artifacts") / "api_module_packs"

    def __init__(self, source: str, source_type: str = "auto", name: Optional[str] = None):
        self.source = Path(source)
        self.raw = self._load_source(self.source)
        self.spec = self._parse(self.raw, source_type=source_type, name=name)
        self.slug = self._slugify(name or self.spec.name or self.source.stem)

    def generate(
        self,
        module_dir: str = None,
        artifact_dir: str = None,
        kinds: Iterable[str] = ("scanner", "fuzzer"),
        force: bool = False,
    ) -> ApiModuleGenerationResult:
        kinds = {kind.strip().lower() for kind in kinds if kind.strip()}
        invalid = kinds - {"scanner", "fuzzer"}
        if invalid:
            raise ValueError(f"Unknown generation kind(s): {', '.join(sorted(invalid))}")

        module_root = Path(module_dir or self.DEFAULT_MODULE_DIR)
        artifact_root = Path(artifact_dir or self.DEFAULT_ARTIFACT_DIR) / self.slug
        module_root.mkdir(parents=True, exist_ok=True)
        artifact_root.mkdir(parents=True, exist_ok=True)
        self._ensure_package_dirs(module_root)

        module_files: List[Path] = []
        if "scanner" in kinds:
            scanner_path = module_root / f"{self.slug}_scanner.py"
            self._guard_overwrite(scanner_path, force)
            module_files.append(self._write_text(scanner_path, self.render_scanner()))

        if "fuzzer" in kinds:
            fuzzer_path = module_root / f"{self.slug}_fuzzer.py"
            self._guard_overwrite(fuzzer_path, force)
            module_files.append(self._write_text(fuzzer_path, self.render_fuzzer()))

        manifest = self.manifest(module_files, artifact_root)
        artifact_files = [
            self._write_json(artifact_root / "manifest.json", manifest),
            self._write_json(artifact_root / "fixtures.json", self.fixtures()),
            self._write_text(artifact_root / "README.md", self.render_readme()),
            self._write_text(artifact_root / "tests" / f"test_{self.slug}_generated_modules.py", self.render_tests(module_files)),
        ]
        return ApiModuleGenerationResult(module_files=module_files, artifact_files=artifact_files, manifest=manifest)

    def preview(self) -> str:
        methods = sorted({endpoint.method for endpoint in self.spec.endpoints})
        samples = ", ".join(f"{ep.method} {ep.path}" for ep in self.spec.endpoints[:8])
        return "\n".join([
            f"API: {self.spec.name}",
            f"Source type: {self.spec.source_type}",
            f"Endpoints: {len(self.spec.endpoints)}",
            f"Methods: {', '.join(methods) if methods else 'none'}",
            f"Sample: {samples or 'none'}",
            "Outputs: scanner module, fuzzer module, fixtures, tests, manifest",
        ])

    def render_scanner(self) -> str:
        endpoints = self._python_repr([self._endpoint_dict(ep) for ep in self.spec.endpoints])
        title = self._py_string(f"{self.spec.name} generated API scanner")
        description = self._py_string(f"Generated scanner for {self.spec.name} from {self.spec.source_type}.")
        return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generated API scanner for {self.spec.name}."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


ENDPOINTS = {endpoints}


def materialize_path(path):
    return path.replace("{{{{", "{{").replace("}}}}", "}}").format_map(_DefaultPathParam())


class _DefaultPathParam(dict):
    def __missing__(self, key):
        return "1"


class Module(Scanner, Http_client):

    __info__ = {{
        "name": {title},
        "description": {description},
        "author": "KittySploit API Module Generator",
        "severity": "info",
        "tags": ["web", "api", "generated", "scanner", {self._py_string(self.spec.source_type)}],
    }}

    def run(self):
        discovered = []
        for endpoint in ENDPOINTS:
            method = endpoint.get("method", "GET")
            path = materialize_path(endpoint.get("path", "/"))
            expected = endpoint.get("expected_statuses") or [200, 201, 202, 204, 301, 302, 400, 401, 403]
            try:
                response = self.http_request(method=method, path=path, allow_redirects=False, timeout=max(int(self.timeout or 10), 5))
            except Exception as exc:
                print_warning(f"{{method}} {{path}} failed: {{exc}}")
                continue
            if not response:
                continue
            status = int(getattr(response, "status_code", 0) or 0)
            if status in expected or (status and status != 404):
                discovered.append((method, path, status))
                print_success(f"{{method}} {{path}} -> HTTP {{status}}")

        if discovered:
            self.set_info(
                severity="info",
                reason=f"{{len(discovered)}} generated API endpoint(s) responded",
                endpoint_count=len(discovered),
            )
            return True
        return False
'''

    def render_fuzzer(self) -> str:
        endpoints = self._python_repr([self._endpoint_dict(ep) for ep in self.spec.endpoints])
        title = self._py_string(f"{self.spec.name} generated API fuzzer")
        description = self._py_string(f"Generated targeted fuzzer for {self.spec.name} from {self.spec.source_type}.")
        return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generated targeted API fuzzer for {self.spec.name}."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import json
import urllib.parse


ENDPOINTS = {endpoints}

FUZZ_PAYLOADS = [
    "' OR '1'='1",
    "../../../etc/passwd",
    "<script>alert(1)</script>",
    "{{\\"$ne\\": null}}",
    "$(id)",
    "%00",
]


def materialize_path(path):
    return path.replace("{{{{", "{{").replace("}}}}", "}}").format_map(_DefaultPathParam())


class _DefaultPathParam(dict):
    def __missing__(self, key):
        return "1"


class Module(Auxiliary, Http_client):

    __info__ = {{
        "name": {title},
        "description": {description},
        "author": "KittySploit API Module Generator",
        "tags": ["web", "api", "generated", "fuzzer", {self._py_string(self.spec.source_type)}],
    }}

    def _body_for(self, endpoint, payload):
        fields = endpoint.get("request_body_fields") or endpoint.get("parameters") or ["test"]
        return json.dumps({{field: payload for field in fields[:5]}})

    def _path_for(self, endpoint, payload):
        path = materialize_path(endpoint.get("path", "/"))
        params = endpoint.get("parameters") or ["test"]
        if endpoint.get("method") in ("GET", "DELETE", "HEAD", "OPTIONS"):
            sep = "&" if "?" in path else "?"
            return path + sep + urllib.parse.urlencode({{params[0]: payload}})
        return path

    def _interesting(self, response):
        if not response:
            return False, "no response"
        status = int(getattr(response, "status_code", 0) or 0)
        text = (getattr(response, "text", "") or "").lower()
        if status >= 500:
            return True, f"server error HTTP {{status}}"
        for marker in ("traceback", "exception", "sql", "syntax", "warning", "stack"):
            if marker in text:
                return True, f"error marker {{marker}}"
        return False, f"HTTP {{status}}"

    def run(self):
        findings = []
        for endpoint in ENDPOINTS[:25]:
            method = endpoint.get("method", "GET")
            for payload in FUZZ_PAYLOADS:
                path = self._path_for(endpoint, payload)
                headers = {{"Content-Type": "application/json"}}
                data = self._body_for(endpoint, payload) if method in ("POST", "PUT", "PATCH") else None
                try:
                    response = self.http_request(method=method, path=path, data=data, headers=headers, allow_redirects=False, timeout=max(int(self.timeout or 10), 5))
                except Exception as exc:
                    print_warning(f"{{method}} {{path}} failed: {{exc}}")
                    continue
                interesting, reason = self._interesting(response)
                if interesting:
                    finding = {{"method": method, "path": endpoint.get("path"), "payload": payload[:80], "reason": reason}}
                    findings.append(finding)
                    print_warning(f"Potential issue on {{method}} {{endpoint.get('path')}}: {{reason}}")

        print_info(f"Generated API fuzzer completed with {{len(findings)}} potential finding(s)")
        self.findings = findings
        return True
'''

    def fixtures(self) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "source": str(self.source),
            "source_type": self.spec.source_type,
            "api": {
                "name": self.spec.name,
                "version": self.spec.version,
                "description": self.spec.description,
            },
            "endpoints": [self._endpoint_dict(ep) for ep in self.spec.endpoints],
            "assertions": [
                {
                    "type": "module_contains_endpoint",
                    "minimum_endpoints": min(1, len(self.spec.endpoints)),
                },
                {
                    "type": "all_paths_start_with_slash",
                },
            ],
        }

    def manifest(self, module_files: List[Path], artifact_root: Path) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "pack_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"kittysploit:api:{self.slug}")),
            "name": self.spec.name,
            "source": str(self.source),
            "source_type": self.spec.source_type,
            "module_paths": [str(path) for path in module_files],
            "artifact_path": str(artifact_root),
            "endpoint_count": len(self.spec.endpoints),
            "methods": sorted({ep.method for ep in self.spec.endpoints}),
        }

    def render_readme(self) -> str:
        endpoint_lines = "\n".join(f"- `{ep.method} {ep.path}`" for ep in self.spec.endpoints[:50])
        if len(self.spec.endpoints) > 50:
            endpoint_lines += f"\n- ... {len(self.spec.endpoints) - 50} more endpoint(s)"
        return f"""# API Module Pack: {self.spec.name}

Generated from `{self.source}` ({self.spec.source_type}).

## Generated Assets

- Scanner module: checks schema-derived endpoints and records responsive surfaces.
- Fuzzer module: reuses schema parameters/body fields for targeted payload probes.
- `fixtures.json`: normalized endpoint inventory and assertions.
- `tests/`: stdlib validation for generated module content.

## Endpoints

{endpoint_lines or "- None"}
"""

    def render_tests(self, module_files: List[Path]) -> str:
        rel_files = [str(path) for path in module_files]
        return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import pathlib
import unittest


PACK_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = PACK_ROOT.parents[1]
MODULE_FILES = {self._python_repr(rel_files)}


class GeneratedApiModuleTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = json.loads((PACK_ROOT / "fixtures.json").read_text(encoding="utf-8"))

    def test_fixtures_have_endpoints(self):
        self.assertGreaterEqual(len(self.fixtures["endpoints"]), self.fixtures["assertions"][0]["minimum_endpoints"])
        for endpoint in self.fixtures["endpoints"]:
            self.assertTrue(endpoint["path"].startswith("/"))
            self.assertIn(endpoint["method"], ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"))

    def test_generated_modules_contain_endpoint_inventory(self):
        sample_paths = [endpoint["path"] for endpoint in self.fixtures["endpoints"][:5]]
        for module_file in MODULE_FILES:
            text = pathlib.Path(module_file).read_text(encoding="utf-8")
            self.assertIn("class Module", text)
            self.assertIn("ENDPOINTS", text)
            for path in sample_paths:
                self.assertIn(path, text)


if __name__ == "__main__":
    unittest.main()
'''

    def _parse(self, raw: Any, source_type: str, name: Optional[str]) -> ApiSpec:
        kind = self._detect_source_type(raw, source_type)
        if kind == "openapi":
            return self._parse_openapi(raw, name)
        if kind == "graphql":
            return self._parse_graphql(raw, name)
        if kind == "traffic":
            return self._parse_traffic(raw, name)
        raise ValueError(f"Unsupported API source type: {kind}")

    def _detect_source_type(self, raw: Any, source_type: str) -> str:
        if source_type and source_type != "auto":
            return source_type.lower()
        if isinstance(raw, dict):
            if "openapi" in raw or "swagger" in raw or "paths" in raw:
                return "openapi"
            if "__schema" in raw or ("data" in raw and isinstance(raw["data"], dict) and "__schema" in raw["data"]):
                return "graphql"
            if "log" in raw and "entries" in raw["log"]:
                return "traffic"
            if "requests" in raw or "entries" in raw:
                return "traffic"
        if isinstance(raw, list):
            return "traffic"
        return "openapi"

    def _parse_openapi(self, raw: Dict[str, Any], name: Optional[str]) -> ApiSpec:
        info = raw.get("info", {}) if isinstance(raw, dict) else {}
        spec = ApiSpec(
            name=name or info.get("title") or "generated_api",
            source_type="openapi",
            version=str(info.get("version", "")),
            description=info.get("description", ""),
        )
        paths = raw.get("paths", {}) if isinstance(raw, dict) else {}
        for path, operations in paths.items():
            if not isinstance(operations, dict):
                continue
            for method, operation in operations.items():
                upper = method.upper()
                if upper not in HTTP_METHODS:
                    continue
                operation = operation or {}
                parameters = self._openapi_parameters(operation, operations)
                body_fields, content_types = self._openapi_body_fields(operation)
                statuses = []
                for status in (operation.get("responses") or {}).keys():
                    if str(status).isdigit():
                        statuses.append(int(status))
                spec.endpoints.append(ApiEndpoint(
                    method=upper,
                    path=self._normalize_path(path),
                    summary=operation.get("summary", ""),
                    operation_id=operation.get("operationId", ""),
                    parameters=parameters,
                    request_body_fields=body_fields,
                    expected_statuses=statuses[:8],
                    content_types=content_types,
                ))
        spec.endpoints = self._dedupe_endpoints(spec.endpoints)
        return spec

    def _parse_graphql(self, raw: Dict[str, Any], name: Optional[str]) -> ApiSpec:
        schema = raw.get("__schema") or raw.get("data", {}).get("__schema", {})
        types = schema.get("types", []) if isinstance(schema, dict) else []
        operations = []
        for type_def in types:
            type_name = type_def.get("name", "")
            if type_name not in ("Query", "Mutation", "Subscription"):
                continue
            for field in type_def.get("fields") or []:
                operations.append(field.get("name", "operation"))
        endpoint = ApiEndpoint(
            method="POST",
            path="/graphql",
            summary="GraphQL introspection-derived endpoint",
            parameters=operations[:20] or ["query"],
            request_body_fields=["query", "variables"],
            expected_statuses=[200, 400, 401, 403],
            content_types=["application/json"],
        )
        return ApiSpec(
            name=name or "generated_graphql_api",
            source_type="graphql",
            description="Generated from GraphQL introspection",
            endpoints=[endpoint],
        )

    def _parse_traffic(self, raw: Any, name: Optional[str]) -> ApiSpec:
        entries = self._traffic_entries(raw)
        endpoints = []
        for entry in entries:
            method, path = self._traffic_method_path(entry)
            if not method or not path:
                continue
            endpoints.append(ApiEndpoint(
                method=method,
                path=self._normalize_path(path),
                summary="Imported from traffic",
                expected_statuses=[200, 201, 202, 204, 301, 302, 400, 401, 403, 404, 500],
            ))
        return ApiSpec(
            name=name or "generated_traffic_api",
            source_type="traffic",
            description="Generated from KittyProxy/HAR traffic",
            endpoints=self._dedupe_endpoints(endpoints),
        )

    def _traffic_entries(self, raw: Any) -> List[Any]:
        if isinstance(raw, list):
            return raw
        if isinstance(raw, dict):
            if "log" in raw and isinstance(raw["log"], dict):
                return raw["log"].get("entries", [])
            for key in ("entries", "requests", "flows", "traffic"):
                if isinstance(raw.get(key), list):
                    return raw[key]
        return []

    def _traffic_method_path(self, entry: Any) -> Tuple[Optional[str], Optional[str]]:
        if not isinstance(entry, dict):
            return None, None
        request = entry.get("request", entry)
        method = str(request.get("method", "")).upper()
        url = request.get("url") or request.get("path") or request.get("uri")
        if method not in HTTP_METHODS or not url:
            return None, None
        parsed = urlparse(str(url))
        path = parsed.path or str(url)
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return method, path

    def _openapi_parameters(self, operation: Dict[str, Any], path_item: Dict[str, Any]) -> List[str]:
        params = []
        for item in (path_item.get("parameters") or []) + (operation.get("parameters") or []):
            if isinstance(item, dict) and item.get("name"):
                params.append(str(item["name"]))
        return self._dedupe(params)

    def _openapi_body_fields(self, operation: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        request_body = operation.get("requestBody") or {}
        content = request_body.get("content") or {}
        fields: List[str] = []
        content_types = list(content.keys())
        for content_spec in content.values():
            schema = content_spec.get("schema") if isinstance(content_spec, dict) else {}
            fields.extend(self._schema_fields(schema))
        return self._dedupe(fields), content_types

    def _schema_fields(self, schema: Any) -> List[str]:
        if not isinstance(schema, dict):
            return []
        fields = []
        properties = schema.get("properties") or {}
        fields.extend(str(name) for name in properties.keys())
        for nested in properties.values():
            fields.extend(self._schema_fields(nested))
        items = schema.get("items")
        if items:
            fields.extend(self._schema_fields(items))
        return fields[:20]

    def _endpoint_dict(self, endpoint: ApiEndpoint) -> Dict[str, Any]:
        return {
            "method": endpoint.method,
            "path": endpoint.path,
            "summary": endpoint.summary,
            "operation_id": endpoint.operation_id,
            "parameters": endpoint.parameters,
            "request_body_fields": endpoint.request_body_fields,
            "expected_statuses": endpoint.expected_statuses,
            "content_types": endpoint.content_types,
        }

    def _load_source(self, path: Path) -> Any:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() in (".json", ".har"):
            return json.loads(text)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        try:
            import yaml
        except ImportError as exc:
            raise ValueError("YAML input requires PyYAML, or provide JSON/OpenAPI/HAR input") from exc
        return yaml.safe_load(text)

    def _normalize_path(self, path: str) -> str:
        if not path:
            return "/"
        path = str(path)
        if path.startswith("http://") or path.startswith("https://"):
            parsed = urlparse(path)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
        if not path.startswith("/"):
            path = "/" + path
        return path

    def _dedupe_endpoints(self, endpoints: List[ApiEndpoint]) -> List[ApiEndpoint]:
        seen = set()
        out = []
        for endpoint in endpoints:
            key = (endpoint.method, endpoint.path)
            if key in seen:
                continue
            seen.add(key)
            out.append(endpoint)
        return out

    def _dedupe(self, values: Iterable[str]) -> List[str]:
        seen = set()
        out = []
        for value in values:
            value = str(value)
            key = value.lower()
            if value and key not in seen:
                seen.add(key)
                out.append(value)
        return out

    def _slugify(self, value: str) -> str:
        slug = re.sub(r"[^A-Za-z0-9]+", "_", str(value)).strip("_").lower()
        return slug[:80] or "generated_api"

    def _python_repr(self, value: Any) -> str:
        return repr(value)

    def _py_string(self, value: str) -> str:
        return repr(str(value))

    def _guard_overwrite(self, path: Path, force: bool):
        if path.exists() and not force:
            raise FileExistsError(f"Refusing to overwrite {path}. Use --force.")

    def _write_text(self, path: Path, content: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def _write_json(self, path: Path, data: Dict[str, Any]) -> Path:
        return self._write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")

    def _ensure_package_dirs(self, module_root: Path):
        modules_dir = Path("modules")
        generated_dir = modules_dir / "generated"
        api_dir = generated_dir / "api"
        for directory in (generated_dir, api_dir, module_root):
            directory.mkdir(parents=True, exist_ok=True)
            init_file = directory / "__init__.py"
            if not init_file.exists():
                init_file.write_text("", encoding="utf-8")
