#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared payload generation contract for modules, CLI, API and KittyForge."""

from .adapter import (
    get_legacy_return_telemetry,
    normalize_payload_result,
    reset_legacy_return_telemetry,
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
    "artifact_to_bytes",
    "get_legacy_return_telemetry",
    "normalize_payload_result",
    "reset_legacy_return_telemetry",
]
