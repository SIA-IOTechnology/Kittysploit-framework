#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Explain payload/listener/transform/prestage compatibility and sizing."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PayloadExplainReport:
    valid: bool = True
    payload_path: str = ""
    payload_language: str = ""
    listener_path: str = ""
    transform_path: str = ""
    prestage_profile: str = ""
    prestage_modules: List[str] = field(default_factory=list)
    estimated_size_bytes: int = 0
    issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    fallbacks: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "payload_path": self.payload_path,
            "payload_language": self.payload_language,
            "listener_path": self.listener_path,
            "transform_path": self.transform_path,
            "prestage_profile": self.prestage_profile,
            "prestage_modules": self.prestage_modules,
            "estimated_size_bytes": self.estimated_size_bytes,
            "issues": self.issues,
            "warnings": self.warnings,
            "dependencies": self.dependencies,
            "fallbacks": self.fallbacks,
            "notes": self.notes,
        }


def explain_payload_module(module, *, framework=None) -> PayloadExplainReport:
    """Analyze the current payload module configuration."""
    from core.payload_generation.compatibility_solver import solve_from_capabilities
    from core.payload_generation.prestage_profiles import resolve_prestage_selection
    from core.payload_generation.prestage_support import (
        payload_prestage_language,
        payload_prestage_platform,
        payload_supports_prestage,
        validate_prestage_selection,
    )

    report = PayloadExplainReport()
    report.payload_path = str(getattr(module, "module_path", "") or getattr(module, "name", ""))
    report.payload_language = str(payload_prestage_language(module) or getattr(type(module), "CLIENT_LANGUAGE", "") or "")

    listener = getattr(module, "listener", None)
    if listener is not None and hasattr(listener, "value"):
        report.listener_path = str(listener.value or "")
    elif listener:
        report.listener_path = str(listener)

    transform = getattr(module, "transform", None)
    if transform is not None and hasattr(transform, "value"):
        report.transform_path = str(transform.value or "")
    elif transform:
        report.transform_path = str(transform)

    if hasattr(module, "_opt_str"):
        report.prestage_profile = module._opt_str("prestage_profile")
        prestage_raw = module._opt_str("prestage")
    else:
        report.prestage_profile = str(getattr(getattr(module, "prestage_profile", None), "value", "") or "")
        prestage_raw = str(getattr(getattr(module, "prestage", None), "value", "") or "")

    try:
        report.prestage_modules = resolve_prestage_selection(
            prestage=prestage_raw,
            prestage_profile=report.prestage_profile,
        )
    except KeyError as exc:
        report.valid = False
        report.issues.append(str(exc))

    if payload_supports_prestage(module) and report.prestage_modules:
        try:
            scriptlets = validate_prestage_selection(
                module,
                prestage=prestage_raw,
                prestage_profile=report.prestage_profile,
            )
            report.dependencies = []
            for item in scriptlets:
                report.dependencies.extend(list(getattr(item, "dependencies", []) or []))
        except Exception as exc:
            report.valid = False
            report.issues.append(str(exc))
    elif report.prestage_modules and not payload_supports_prestage(module):
        report.valid = False
        report.issues.append("Selected prestages but payload language does not support prestage embedding")

    if report.transform_path and report.payload_language:
        try:
            from core.framework.transform import load_transform_chain

            xf = load_transform_chain(report.transform_path, framework=framework)
            langs = []
            if xf is not None:
                langs = list(
                    getattr(xf, "get_supported_client_languages", lambda: getattr(type(xf), "SUPPORTED_CLIENT_LANGUAGES", []))()
                )
            if langs and report.payload_language not in langs:
                report.valid = False
                report.issues.append(
                    f"Transform '{report.transform_path}' does not support client language '{report.payload_language}'"
                )
        except Exception as exc:
            report.warnings.append(f"Could not validate transform: {exc}")

    if hasattr(module, "generate"):
        try:
            out = module.generate()
            if isinstance(out, str):
                report.estimated_size_bytes = len(out.encode("utf-8", errors="replace"))
            else:
                report.estimated_size_bytes = len(bytes(out or b""))
            report.notes.append("Estimated size uses current module options (prestage may increase final script size)")
        except Exception as exc:
            report.warnings.append(f"generate() failed during sizing: {exc}")

    plan = solve_from_capabilities({}, framework=framework)
    report.fallbacks = plan.payload_paths[:3] + plan.listener_paths[:2]
    report.notes.append(f"Platform token for prestage: {payload_prestage_platform(module)}")
    return report


def format_payload_explain(report: PayloadExplainReport) -> str:
    lines = [
        f"Valid: {'yes' if report.valid else 'no'}",
        f"Payload: {report.payload_path or '(current)'}",
        f"Language: {report.payload_language or 'unknown'}",
        f"Listener: {report.listener_path or '(unset)'}",
        f"Transform: {report.transform_path or '(none)'}",
        f"Prestage profile: {report.prestage_profile or '(none)'}",
        f"Prestage modules: {', '.join(report.prestage_modules) or '(none)'}",
        f"Estimated size: {report.estimated_size_bytes} bytes",
    ]
    if report.dependencies:
        lines.append(f"Prestage dependencies: {', '.join(sorted(set(report.dependencies)))}")
    for label, items in (
        ("Issues", report.issues),
        ("Warnings", report.warnings),
        ("Fallbacks", report.fallbacks),
        ("Notes", report.notes),
    ):
        if items:
            lines.append(f"{label}:")
            lines.extend(f"  - {item}" for item in items)
    return "\n".join(lines)
