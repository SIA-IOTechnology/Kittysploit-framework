#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Legacy payload return adapters with deprecation telemetry."""

from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Optional

from .models import GeneratedArtifact, GenerationError

logger = logging.getLogger(__name__)

_LEGACY_RETURN_TELEMETRY: Counter[str] = Counter()

_ARTIFACT_PATH_KEYS = (
    "binary_path",
    "binary",
    "path",
    "source",
    "compile_script",
    "payload_script",
    "output",
)


def get_legacy_return_telemetry() -> Dict[str, int]:
    return dict(_LEGACY_RETURN_TELEMETRY)


def reset_legacy_return_telemetry() -> None:
    _LEGACY_RETURN_TELEMETRY.clear()


def _record_legacy(return_type: str, module_path: str) -> str:
    _LEGACY_RETURN_TELEMETRY[return_type] += 1
    message = (
        f"Module '{module_path}' returned legacy type '{return_type}'. "
        "Return GeneratedArtifact or bytes/str instead."
    )
    logger.warning(message)
    return message


def _read_file_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        return b""


def _read_file_text(path: Path) -> bytes:
    try:
        return path.read_text(encoding="utf-8").encode("utf-8")
    except OSError:
        return b""


def _content_from_dict(result: Dict[str, Any]) -> tuple[bytes, bytes, str, Dict[str, str]]:
    artifacts: Dict[str, str] = {}
    for key, value in result.items():
        if value is None:
            continue
        if key in _ARTIFACT_PATH_KEYS or key.endswith("_path"):
            artifacts[key] = str(value)

    binary_keys = ("binary_path", "binary", "path", "output")
    for key in binary_keys:
        candidate = artifacts.get(key)
        if not candidate:
            continue
        path = Path(candidate)
        if path.is_file():
            content = _read_file_bytes(path)
            return content, content, "application/octet-stream", artifacts

    source = artifacts.get("source")
    if source and Path(source).is_file():
        source_bytes = _read_file_text(Path(source))
        return source_bytes, source_bytes, "text/plain", artifacts

    if result.get("content") is not None:
        raw = result["content"]
        if isinstance(raw, (bytes, bytearray)):
            content = bytes(raw)
            return content, content, str(result.get("content_type") or "application/octet-stream"), artifacts
        if isinstance(raw, str):
            content = raw.encode("utf-8", errors="surrogateescape")
            return content, content, "text/plain", artifacts

    summary = "\n".join(f"{key}: {value}" for key, value in sorted(artifacts.items()))
    if summary:
        encoded = summary.encode("utf-8")
        return encoded, encoded, "text/plain", artifacts

    raise GenerationError(
        "Dictionary payload result did not contain readable content or artifact paths",
        return_type="dict",
        details={"keys": sorted(result.keys())},
    )


def normalize_payload_result(
    result: Any,
    *,
    module_path: str = "",
) -> GeneratedArtifact:
    """Normalize legacy module return values into a GeneratedArtifact."""
    if result is None:
        raise GenerationError(
            "Payload generation returned empty result",
            module=module_path,
            return_type="NoneType",
        )

    if isinstance(result, GeneratedArtifact):
        return result

    legacy_type = type(result).__name__
    warning = _record_legacy(legacy_type, module_path)

    if isinstance(result, (bytes, bytearray)):
        content = bytes(result)
        return GeneratedArtifact(
            content=content,
            display_content=content,
            content_type="application/octet-stream",
            warnings=[warning],
            legacy_return_type=legacy_type,
        )

    if isinstance(result, str):
        content = result.encode("utf-8", errors="surrogateescape")
        return GeneratedArtifact(
            content=content,
            display_content=content,
            content_type="text/plain",
            warnings=[warning],
            legacy_return_type=legacy_type,
        )

    if isinstance(result, Path):
        path = result
        content = _read_file_bytes(path) if path.is_file() else b""
        return GeneratedArtifact(
            content=content,
            display_content=content,
            content_type="application/octet-stream",
            artifacts={"path": str(path)},
            warnings=[warning],
            legacy_return_type=legacy_type,
        )

    if isinstance(result, dict):
        content, display, content_type, artifacts = _content_from_dict(result)
        return GeneratedArtifact(
            content=content,
            display_content=display,
            content_type=content_type,
            artifacts=artifacts,
            metadata={k: v for k, v in result.items() if k not in artifacts},
            warnings=[warning],
            legacy_return_type=legacy_type,
        )

    if isinstance(result, tuple):
        if not result:
            raise GenerationError(
                "Payload generation returned empty tuple",
                module=module_path,
                return_type="tuple",
            )
        return normalize_payload_result(result[0], module_path=module_path)

    raise GenerationError(
        f"Module '{module_path}' returned unsupported type '{legacy_type}'",
        module=module_path,
        return_type=legacy_type,
    )
