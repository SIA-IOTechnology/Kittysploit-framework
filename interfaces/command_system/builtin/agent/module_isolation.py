#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Execution isolation for third-party and high-risk modules."""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Mapping, Optional, Sequence

SENSITIVE_ENV_PREFIXES: Sequence[str] = (
    "AWS_",
    "AZURE_",
    "GCP_",
    "GOOGLE_",
    "KITTYSPLOIT_",
    "OPENAI_",
    "ANTHROPIC_",
    "DATABASE_",
    "DB_",
    "API_KEY",
    "SECRET",
    "PASSWORD",
    "TOKEN",
    "PRIVATE_KEY",
)

SENSITIVE_ENV_EXACT: frozenset[str] = frozenset(
    {
        "HOME",
        "USERPROFILE",
        "SSH_AUTH_SOCK",
    }
)


def is_third_party_module(module_path: str, module_instance: Any = None) -> bool:
    """Return True when the module should run under isolation constraints."""
    path = str(module_path or "").lower().replace("\\", "/")
    if path.startswith("extensions/") or "/extensions/" in path:
        return True
    if module_instance is None:
        return False
    info = getattr(module_instance, "__info__", None)
    if not isinstance(info, dict):
        info = {}
    agent = info.get("agent") if isinstance(info.get("agent"), dict) else {}
    isolation = str(agent.get("isolation") or "").strip().lower()
    if isolation in {"required", "sandbox", "strict"}:
        return True
    for attr in ("_extension_manifest", "extension_metadata", "_registry_manifest"):
        if attr in getattr(module_instance, "__dict__", {}):
            return True
    return False


def should_use_runtime_kernel(framework: Any, module_path: str, module_instance: Any = None) -> bool:
    if not is_third_party_module(module_path, module_instance):
        return False
    return getattr(framework, "runtime_kernel", None) is not None


def isolation_profile(module_path: str, module_instance: Any = None) -> Dict[str, Any]:
    info = getattr(module_instance, "__info__", {}) or {}
    agent = info.get("agent") if isinstance(info, dict) else {}
    level = "none"
    if isinstance(agent, dict):
        level = str(agent.get("isolation") or "none").strip().lower()
    if is_third_party_module(module_path, module_instance) and level in {"", "none", "recommended"}:
        level = "required"
    return {
        "module_path": module_path,
        "isolation": level,
        "runtime_kernel": level in {"required", "sandbox", "strict"},
        "scrub_environment": level in {"required", "sandbox", "strict", "recommended"},
    }


@contextmanager
def scrub_sensitive_environment(*, keep_home: bool = True) -> Iterator[None]:
    """Temporarily remove sensitive environment variables during module execution."""
    saved: dict[str, str] = {}
    for key, value in list(os.environ.items()):
        upper = key.upper()
        if upper in SENSITIVE_ENV_EXACT and keep_home and upper == "HOME":
            continue
        if upper in SENSITIVE_ENV_EXACT and not keep_home:
            saved[key] = value
            del os.environ[key]
            continue
        if any(upper.startswith(prefix) or prefix in upper for prefix in SENSITIVE_ENV_PREFIXES):
            saved[key] = value
            del os.environ[key]
    try:
        yield
    finally:
        os.environ.update(saved)


def execution_isolation_context(
    framework: Any,
    module_path: str,
    module_instance: Any = None,
):
    """Combined env scrub (+ optional future kernel hooks) for module execution."""
    profile = isolation_profile(module_path, module_instance)
    if profile.get("scrub_environment"):
        return scrub_sensitive_environment()
    from contextlib import nullcontext

    return nullcontext()
