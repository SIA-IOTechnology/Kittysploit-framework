#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Create self-contained KittySploit marketplace module projects."""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from core.module_generator import MODULE_KINDS, ModuleSkeletonGenerator
from core.registry.manifest import ManifestParser

MARKETPLACE_CREATE_TYPES = (
    "scanner",
    "analysis",
    "auxiliary",
    "backdoor",
    "browser_auxiliary",
    "browser_exploit",
    "encoder",
    "exploit",
    "listener",
    "payload",
    "post",
    "shortcut",
    "transform",
    "workflow",
    "ui",
)

MARKETPLACE_CREATE_TYPE_ALIASES = {
    "analyses": "analysis",
    "analyzer": "analysis",
    "aux": "auxiliary",
    "backdoors": "backdoor",
    "browser": "browser_auxiliary",
    "browser_aux": "browser_auxiliary",
    "browser-aux": "browser_auxiliary",
    "browser_auxiliaries": "browser_auxiliary",
    "browser_exploits": "browser_exploit",
    "browser-exploit": "browser_exploit",
    "browser-exploits": "browser_exploit",
    "encoders": "encoder",
    "exploits": "exploit",
    "interface": "ui",
    "listeners": "listener",
    "obfuscator": "transform",
    "obfuscators": "transform",
    "payloads": "payload",
    "scan": "scanner",
    "scanners": "scanner",
    "shortcuts": "shortcut",
    "transforms": "transform",
    "workflows": "workflow",
}


@dataclass(frozen=True)
class MarketplaceScaffoldResult:
    """Files produced for a marketplace module project."""

    project_dir: Path
    manifest_path: Path
    module_path: Path
    readme_path: Path
    test_path: Path
    module_id: str
    module_type: str
    install_path: Optional[str]
    entry_point: str


class MarketplaceScaffoldGenerator:
    """Generate a publishable marketplace project around a module template."""

    DEFAULT_VERSION = "0.1.0"

    def __init__(
        self,
        module_id: str,
        *,
        module_type: str = "scanner",
        name: Optional[str] = None,
        description: Optional[str] = None,
        author: Optional[str] = None,
        version: str = DEFAULT_VERSION,
        subpath: Optional[str] = None,
        network_access: Optional[bool] = None,
        database_access: bool = False,
        price: float = 0.0,
        currency: str = "EUR",
        license_name: str = "MIT",
        kittysploit_min: str = "1.0.0",
        kittysploit_max: Optional[str] = None,
    ):
        self.module_id = self._normalize_market_id(module_id)
        self.module_slug = self.module_id.replace("-", "_")
        self.module_type = self._normalize_module_type(module_type)
        if self.module_type not in MARKETPLACE_CREATE_TYPES:
            supported = ", ".join(MARKETPLACE_CREATE_TYPES)
            raise ValueError(
                f"Unsupported module type {module_type!r}. Supported: {supported}"
            )

        self.version = str(version or "").strip()
        self.price = float(price)
        if self.price < 0:
            raise ValueError("Price must be greater than or equal to zero")

        self.currency = str(currency or "").strip().upper()
        if not re.fullmatch(r"[A-Z]{3}", self.currency):
            raise ValueError("Currency must be a three-letter code such as EUR or USD")

        self.license_name = str(license_name or "").strip()
        if not self.license_name:
            raise ValueError("License must not be empty")

        self.kittysploit_min = str(kittysploit_min or "").strip()
        self.kittysploit_max = (
            str(kittysploit_max).strip() if kittysploit_max else None
        )
        self.database_access = bool(database_access)
        if network_access is None:
            self.network_access = self.module_type in {
                "scanner",
                "exploit",
                "listener",
                "ui",
            }
        else:
            self.network_access = bool(network_access)

        self.module_generator = None
        self.entry_point = "src/module.py"
        self.install_path = None
        self.display_name = (name or self._title_from_slug(self.module_id)).strip()
        self.description = (
            description
            or f"KittySploit marketplace {self.module_type}: {self.display_name}"
        ).strip()
        self.authors = self._normalize_author(author or "Your Name")
        if self.module_type != "ui":
            self.module_generator = ModuleSkeletonGenerator(
                slug=self.module_slug,
                module_type=self.module_type,
                subpath=subpath,
                name=name,
                description=description,
                author=author,
            )
            self.display_name = self.module_generator.display_name
            self.description = self.module_generator.description
            self.authors = list(self.module_generator.author)
            self.install_path = (
                f"modules/{self.module_generator.subpath}/{self.module_slug}.py"
            )
        else:
            self.entry_point = "src/main.py"

        manifest = ManifestParser.parse_string(self.render_manifest())
        if manifest is None:
            raise ValueError("Unable to build extension.toml")
        valid, errors = ManifestParser.validate(manifest)
        if not valid:
            raise ValueError("Invalid generated manifest: " + "; ".join(errors))

    def generate(self, output_parent: str | Path = ".") -> MarketplaceScaffoldResult:
        """Create the project atomically and refuse to overwrite existing paths."""

        parent = Path(output_parent).expanduser().resolve()
        parent.mkdir(parents=True, exist_ok=True)
        project_dir = parent / self.module_id
        if project_dir.exists():
            raise FileExistsError(
                f"Refusing to overwrite existing directory: {project_dir}"
            )

        staging_dir = Path(
            tempfile.mkdtemp(prefix=f".{self.module_id}-", dir=str(parent))
        )
        try:
            (staging_dir / "src").mkdir()
            (staging_dir / "tests").mkdir()

            (staging_dir / "extension.toml").write_text(
                self.render_manifest(), encoding="utf-8"
            )
            (staging_dir / "README.md").write_text(
                self.render_readme(), encoding="utf-8"
            )
            (staging_dir / self.entry_point).write_text(
                self.render_entry_point(), encoding="utf-8"
            )
            (staging_dir / "tests" / "test_module.py").write_text(
                self.render_tests(), encoding="utf-8"
            )

            os.replace(staging_dir, project_dir)
        except Exception:
            shutil.rmtree(staging_dir, ignore_errors=True)
            raise

        return MarketplaceScaffoldResult(
            project_dir=project_dir,
            manifest_path=project_dir / "extension.toml",
            module_path=project_dir / self.entry_point,
            readme_path=project_dir / "README.md",
            test_path=project_dir / "tests" / "test_module.py",
            module_id=self.module_id,
            module_type=self.module_type,
            install_path=self.install_path,
            entry_point=self.entry_point,
        )

    def render_manifest(self) -> str:
        """Render the marketplace extension manifest."""

        compatibility_lines = [
            "[compatibility]",
            f"kittysploit_min = {json.dumps(self.kittysploit_min)}",
        ]
        if self.kittysploit_max:
            compatibility_lines.append(
                f"kittysploit_max = {json.dumps(self.kittysploit_max)}"
            )

        return "\n".join(
            [
                "# KittySploit marketplace module",
                f"id = {json.dumps(self.module_id)}",
                f"name = {json.dumps(self.display_name)}",
                f"version = {json.dumps(self.version)}",
                f"description = {json.dumps(self.description)}",
                f"author = {json.dumps(', '.join(self.authors))}",
                "",
                self._render_extension_type_line(),
                f"entry_point = {json.dumps(self.entry_point)}",
                *self._render_install_path_lines(),
                "",
                *compatibility_lines,
                "",
                "[permissions]",
                f"network_access = {str(self.network_access).lower()}",
                f"database_access = {str(self.database_access).lower()}",
                'sandbox_level = "standard"',
                "allowed_imports = []",
                "blocked_imports = []",
                "hooks = []",
                "events = []",
                "middlewares = []",
                "",
                "[metadata]",
                f"price = {self.price:.2f}",
                f"currency = {json.dumps(self.currency)}",
                f"license = {json.dumps(self.license_name)}",
                "",
            ]
        )

    def render_readme(self) -> str:
        """Render concise development and publishing instructions."""

        entry_file = self.entry_point.split("/", 1)[1]
        validation_lines = self._render_readme_validation()
        return f"""# {self.display_name}

{self.description}

## Structure

```text
{self.module_id}/
├── extension.toml
├── README.md
├── src/
│   └── {entry_file}
└── tests/
    └── test_module.py
```

## Local validation

```text
market install ./{self.module_id}
{validation_lines}
```

## Publish

```text
market publish ./{self.module_id}
```

Increment `version` in `extension.toml` before publishing an update.
"""

    def render_entry_point(self) -> str:
        """Render the source file for the scaffolded marketplace item."""
        if self.module_type == "ui":
            return self._render_ui_entry_point()
        return self.module_generator.render_module()

    def render_tests(self) -> str:
        """Render dependency-light contract tests for the generated project."""

        return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Static contract tests for the {self.module_id} marketplace module."""

import pathlib
import unittest

import toml


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST_PATH = PROJECT_ROOT / "extension.toml"
ENTRY_PATH = PROJECT_ROOT / {self.entry_point!r}


class MarketplaceModuleContractTests(unittest.TestCase):
    def test_manifest_identity_and_entry_point(self):
        manifest = toml.load(MANIFEST_PATH)
        self.assertEqual(manifest["id"], {self.module_id!r})
        self.assertEqual(manifest["entry_point"], {self.entry_point!r})
{self._render_install_path_test_assertion()}
        self.assertTrue((PROJECT_ROOT / manifest["entry_point"]).is_file())

    def test_entry_point_compiles(self):
        source = ENTRY_PATH.read_text(encoding="utf-8")
{self._render_source_contract_test_assertion()}
        compile(source, str(ENTRY_PATH), "exec")


if __name__ == "__main__":
    unittest.main()
'''

    @staticmethod
    def _normalize_market_id(value: str) -> str:
        module_id = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower())
        module_id = module_id.strip("-")
        if not module_id:
            raise ValueError("Module ID is required")
        if len(module_id) > 64:
            raise ValueError("Module ID must not exceed 64 characters")
        return module_id

    @staticmethod
    def _normalize_module_type(value: str) -> str:
        module_type = str(value or "scanner").strip().lower().replace("-", "_")
        return MARKETPLACE_CREATE_TYPE_ALIASES.get(module_type, module_type)

    @staticmethod
    def _normalize_author(value: str) -> list[str]:
        author = str(value or "").strip()
        return [author] if author else ["Your Name"]

    @staticmethod
    def _title_from_slug(value: str) -> str:
        return " ".join(part.capitalize() for part in re.split(r"[-_]+", value) if part)

    def _render_extension_type_line(self) -> str:
        if self.module_type == "ui":
            return 'extension_type = "UI"'
        return 'extension_type = "module"'

    def _render_install_path_lines(self) -> list[str]:
        if self.install_path:
            return [f"install_path = {json.dumps(self.install_path)}"]
        return []

    def _render_readme_validation(self) -> str:
        if self.module_type == "ui":
            return f"market launch {self.module_id}"
        return "\n".join(
            [
                f"use {self.module_generator.subpath}/{self.module_slug}",
                "show options",
                "run",
            ]
        )

    def _render_install_path_test_assertion(self) -> str:
        if self.install_path:
            return (
                f"        self.assertEqual(manifest[\"install_path\"], "
                f"{self.install_path!r})"
            )
        return '        self.assertNotIn("install_path", manifest)'

    def _render_source_contract_test_assertion(self) -> str:
        if self.module_type == "ui":
            return '        self.assertIn("def main", source)'
        return '        self.assertIn("class Module", source)'

    def _render_ui_entry_point(self) -> str:
        return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""{self.display_name}"""

import json
import sys
from pathlib import Path


DEFAULT_CONFIG = {{
    "host": "127.0.0.1",
    "port": 5000,
    "debug": False,
}}


def get_extension_base() -> Path:
    return Path(globals().get("__extension_base__", Path.cwd()))


def load_config() -> dict:
    config_path = get_extension_base() / "config.json"
    if not config_path.exists():
        return dict(DEFAULT_CONFIG)
    with config_path.open("r", encoding="utf-8") as handle:
        return {{**DEFAULT_CONFIG, **json.load(handle)}}


def main() -> int:
    config = load_config()
    extension_id = globals().get("__extension_id__", {self.module_id!r})
    print(f"Starting {{extension_id}} on http://{{config['host']}}:{{config['port']}}")
    print("Replace this stub with your Flask, FastAPI, or frontend launcher.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''
