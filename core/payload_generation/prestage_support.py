#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Validation helpers for offline prestage scriptlets on payload modules."""

from __future__ import annotations

from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.payload_generation.scriptlets.registry import Scriptlet


class PrestStageNotSupportedError(ValueError):
    """Raised when a payload cannot embed offline prestage scriptlets."""


def payload_client_language(module) -> Optional[str]:
    return getattr(type(module), "CLIENT_LANGUAGE", None)


def payload_supports_prestage(module) -> bool:
    """Return True when this payload can embed offline prestage scriptlets."""
    explicit = getattr(type(module), "PRESTAGE_SUPPORTED", None)
    if explicit is not None:
        return bool(explicit)
    lang = payload_client_language(module)
    return lang in ("python", "zig", "powershell")


def payload_prestage_platform(module) -> str:
    info = getattr(type(module), "__info__", {}) or {}
    platform = info.get("platform")
    if hasattr(platform, "value"):
        return str(platform.value or "all").lower()
    return str(platform or "all").lower()


def payload_prestage_language(module) -> str:
    lang = payload_client_language(module)
    if lang:
        return str(lang).strip().lower()
    return "python"


def payload_prestage_unsupported_message(module) -> str:
    lang = payload_client_language(module) or "native compiled"
    name = getattr(module, "name", None) or getattr(type(module), "__name__", "payload")
    return (
        f"Payload '{name}' generates {lang} artifacts and cannot embed offline prestage scriptlets. "
        "Prestage is available on Python, Zig, and PowerShell Kitty payloads."
    )


def parse_prestage_names(raw: str) -> List[str]:
    return [part.strip() for part in str(raw or "").split(",") if part.strip()]


def validate_prestage_names(module, names: List[str]) -> List["Scriptlet"]:
    if not names:
        return []
    if not payload_supports_prestage(module):
        raise PrestStageNotSupportedError(payload_prestage_unsupported_message(module))
    from core.payload_generation.scriptlets.registry import resolve_scriptlet_names

    platform = payload_prestage_platform(module)
    context = getattr(module, "_build_prestage_context", lambda: {})()
    language = payload_prestage_language(module)
    scriptlets = resolve_scriptlet_names(
        names,
        platform=platform,
        language=language,
        framework=getattr(module, "framework", None),
        context=context,
    )

    zip_tokens = {"extract_zip", "prestage/zip/extract_embedded", "zip/extract_embedded"}
    requested = {n.lower() for n in names}
    if requested & zip_tokens and not str((context or {}).get("zip_b64") or "").strip():
        raise ValueError(
            "Prestage 'extract_zip' requires a valid ZIP file via 'set prestage_archive /path/to/archive.zip'"
        )
    return scriptlets


def validate_prestage_value(module, raw: str) -> List["Scriptlet"]:
    names = parse_prestage_names(raw)
    if not names:
        return []
    return validate_prestage_names(module, names)


def list_compatible_scriptlets(module):
    from core.payload_generation.scriptlets.registry import list_scriptlets

    if not payload_supports_prestage(module):
        return []
    return list_scriptlets(
        platform=payload_prestage_platform(module),
        language=payload_prestage_language(module),
    )
