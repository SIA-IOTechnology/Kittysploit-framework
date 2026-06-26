#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Versioned payload generation result models."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

ARTIFACT_SCHEMA_VERSION = "1.0"


@dataclass
class GeneratedArtifact:
    """Normalized result of a payload module ``generate()`` call."""

    content: bytes
    content_type: str = "application/octet-stream"
    display_content: Optional[bytes] = None
    artifacts: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    schema_version: str = ARTIFACT_SCHEMA_VERSION
    legacy_return_type: str = ""

    @property
    def output_bytes(self) -> bytes:
        """Bytes intended for the Output panel (excludes bare file paths)."""
        if self.display_content is not None:
            return self.display_content
        return self.content

    def to_dict(self, *, include_content: bool = False) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "schema_version": self.schema_version,
            "content_type": self.content_type,
            "content_size": len(self.content),
            "display_size": len(self.output_bytes),
            "artifacts": dict(self.artifacts),
            "metadata": dict(self.metadata),
            "warnings": list(self.warnings),
            "logs": list(self.logs),
            "legacy_return_type": self.legacy_return_type,
        }
        if include_content:
            payload["content_base64"] = base64.b64encode(self.content).decode("ascii")
            payload["display_base64"] = base64.b64encode(self.output_bytes).decode("ascii")
        return payload


class GenerationError(ValueError):
    """Raised when a module returns an unsupported or empty payload result."""

    def __init__(
        self,
        message: str,
        *,
        module: str = "",
        return_type: str = "",
        details: Optional[Dict[str, Any]] = None,
        code: str = "invalid_payload_return",
    ):
        super().__init__(message)
        self.message = message
        self.module = module
        self.return_type = return_type
        self.details = details or {}
        self.code = code

    def to_dict(self, *, request_id: str = "") -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "error": self.message,
            "module": self.module,
            "return_type": self.return_type,
            "details": self.details,
            "request_id": request_id,
        }


def artifact_to_bytes(artifact: GeneratedArtifact) -> bytes:
    return artifact.output_bytes
