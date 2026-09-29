#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Validation helpers for offline prestage scriptlets on payload modules."""

from __future__ import annotations

import os
from typing import List, Optional, TYPE_CHECKING

from core.payload_generation.prestage_loader import PrestageResolutionError

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
    signed_tokens = {"signed_config", "prestage/multi/signed_config"}
    requested = {n.lower() for n in names}
    requested_short = {n.lower().split("/")[-1] for n in names}
    if requested & zip_tokens and not str((context or {}).get("zip_b64") or "").strip():
        raise ValueError(
            "Prestage 'extract_zip' requires a valid ZIP file via 'set prestage_archive /path/to/archive.zip'"
        )
    if requested_short & {"signed_config"}:
        has_config = any(
            str((context or {}).get(key) or "").strip()
            for key in ("prestage_config", "config_json")
        )
        config_file = str((context or {}).get("prestage_config_file") or (context or {}).get("config_file") or "").strip()
        if not has_config and not (config_file and os.path.isfile(config_file)):
            raise ValueError(
                "Prestage 'signed_config' requires JSON via 'set prestage_config {...}' "
                "or 'set prestage_config_file /path/to/config.json'"
            )
    return scriptlets


def validate_prestage_selection(
    module,
    *,
    prestage: str = "",
    prestage_profile: str = "",
) -> List["Scriptlet"]:
    from core.payload_generation.prestage_profiles import resolve_prestage_selection

    names = resolve_prestage_selection(prestage=prestage, prestage_profile=prestage_profile)
    if not names:
        return []
    return validate_prestage_names(module, names)


def validate_prestage_value(module, raw: str) -> List["Scriptlet"]:
    profile = ""
    if hasattr(module, "_opt_str"):
        profile = module._opt_str("prestage_profile")
    else:
        opt = getattr(module, "prestage_profile", None)
        profile = str(getattr(opt, "value", opt) or "").strip()
    if not str(raw or "").strip() and not profile:
        return []
    return validate_prestage_selection(module, prestage=str(raw or ""), prestage_profile=profile)


def list_compatible_scriptlets(module):
    from core.payload_generation.scriptlets.registry import list_scriptlets

    if not payload_supports_prestage(module):
        return []
    return list_scriptlets(
        platform=payload_prestage_platform(module),
        language=payload_prestage_language(module),
    )
