#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared payload generation contract for modules, CLI, API and KittyForge."""

from .adapter import (
    get_legacy_return_telemetry,
    normalize_payload_result,
    reset_legacy_return_telemetry,
)
from .scriptlets import (
    Scriptlet,
    build_prestage_block,
    get_scriptlet,
    list_scriptlets,
    reload_scriptlets,
    resolve_scriptlet_names,
    wrap_python_script,
)
from .models import (
    ARTIFACT_SCHEMA_VERSION,
    GeneratedArtifact,
    GenerationError,
    artifact_to_bytes,
)

__all__ = [
    "ARTIFACT_SCHEMA_VERSION",
    "GeneratedArtifact",
    "GenerationError",
    "Scriptlet",
    "artifact_to_bytes",
    "build_prestage_block",
    "get_legacy_return_telemetry",
    "get_scriptlet",
    "list_scriptlets",
    "normalize_payload_result",
    "reload_scriptlets",
    "reset_legacy_return_telemetry",
    "resolve_scriptlet_names",
    "wrap_python_script",
]
