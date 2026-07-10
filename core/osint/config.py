#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Dedicated OSINT configuration file loader (~/.kittysploit/osint.toml)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore

_DEFAULT_TEMPLATE = """# KittySploit OSINT / LE configuration
# Copy to ~/.kittysploit/osint.toml or ./config/osint.toml

[general]
audit_dir = "~/.kittysploit/osint"
data_controller = ""
default_tlp = "AMBER"
recipient_org = ""

[gdpr]
pii_days = 90
ioc_days = 365
audit_days = 730
pseudonymize_exports = true
legal_basis_required = true
lawful_basis_article = "Art. 6(1)(e) GDPR — public interest / official authority"
processing_purpose = "law_enforcement_osint_investigation"

[push]
enabled = true
max_attempts = 3
backoff_base = 1.5

[providers.intelx]
api_key = ""

[providers.telegram]
bot_token = ""

[providers.misp]
url = ""
api_key = ""

[providers.opencti]
url = ""
token = ""

[providers.sirius]
url = ""
token = ""
"""

# Logical keys used by providers.py -> (section, field)
_PROVIDER_FIELD_MAP: Dict[str, tuple[str, str]] = {
    "intelx": ("intelx", "api_key"),
    "telegram_bot": ("telegram", "bot_token"),
    "misp_url": ("misp", "url"),
    "misp_key": ("misp", "api_key"),
    "opencti_url": ("opencti", "url"),
    "opencti_token": ("opencti", "token"),
    "sirius_url": ("sirius", "url"),
    "sirius_token": ("sirius", "token"),
}


class OsintConfig:
    """Load and query ``osint.toml`` (providers, GDPR defaults, push settings)."""

    _instance: Optional["OsintConfig"] = None

    def __init__(self, config_file: Optional[str] = None) -> None:
        self.config_file = config_file or self._find_config_file()
        self._data: Dict[str, Any] = self._load()

    @staticmethod
    def default_config_path() -> Path:
        return Path.home() / ".kittysploit" / "osint.toml"

    @staticmethod
    def example_config_path() -> Path:
        return Path(__file__).resolve().parents[2] / "config" / "osint.toml.example"

    def _find_config_file(self) -> Optional[str]:
        override = os.environ.get("KITTYOSINT_CONFIG", "").strip()
        if override:
            return os.path.expanduser(override)

        cwd = Path.cwd()
        for directory in [cwd] + list(cwd.parents):
            for candidate in ("osint.toml", "config/osint.toml"):
                path = directory / candidate
                try:
                    if path.is_file():
                        return str(path)
                except OSError:
                    continue

        user_path = self.default_config_path()
        if user_path.is_file():
            return str(user_path)
        return None

    def _load(self) -> Dict[str, Any]:
        if tomllib is None or not self.config_file:
            return {}
        path = Path(self.config_file)
        if not path.is_file():
            return {}
        try:
            with open(path, "rb") as handle:
                data = tomllib.load(handle)
                return data if isinstance(data, dict) else {}
        except OSError:
            return {}

    @property
    def data(self) -> Dict[str, Any]:
        return self._data

    @property
    def is_loaded(self) -> bool:
        return bool(self._data) and bool(self.config_file)

    def get_section(self, name: str) -> Dict[str, Any]:
        block = self._data.get(name)
        return dict(block) if isinstance(block, dict) else {}

    def get_provider_value(self, logical_name: str) -> str:
        section_name, field = _PROVIDER_FIELD_MAP.get(logical_name, ("", ""))
        if not section_name:
            return ""
        providers = self.get_section("providers")
        section = providers.get(section_name)
        if not isinstance(section, dict):
            return ""
        return str(section.get(field) or "").strip()

    def audit_dir(self) -> str:
        general = self.get_section("general")
        raw = str(general.get("audit_dir") or "~/.kittysploit/osint").strip()
        return os.path.expanduser(raw)

    def push_settings(self) -> Dict[str, Any]:
        push = self.get_section("push")
        return {
            "enabled": bool(push.get("enabled", True)),
            "max_attempts": int(push.get("max_attempts", 3) or 3),
            "backoff_base": float(push.get("backoff_base", 1.5) or 1.5),
        }

    def gdpr_defaults(self) -> Dict[str, Any]:
        return dict(self.get_section("gdpr"))

    @classmethod
    def get_instance(cls, *, reload: bool = False) -> "OsintConfig":
        if cls._instance is None or reload:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def ensure_config_file(cls, path: Optional[str] = None) -> str:
        """Create default ``osint.toml`` when missing (explicit setup helper)."""
        target = Path(path) if path else cls.default_config_path()
        if not target.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            example = cls.example_config_path()
            if example.is_file():
                target.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
            else:
                target.write_text(_DEFAULT_TEMPLATE, encoding="utf-8")
        inst = cls(str(target))
        cls._instance = inst
        return str(target)


def get_osint_config(*, reload: bool = False) -> OsintConfig:
    return OsintConfig.get_instance(reload=reload)
