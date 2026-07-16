#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Validate golden-path module inventory and static contracts."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.golden_path_matrix import (
    GOLDEN_PATH_MATRIX,
    GoldenPath,
    list_golden_paths,
)
from interfaces.command_system.builtin.agent.module_contract_tests import run_module_contract_test


def golden_path_module_paths(*, os_name: str = "") -> List[str]:
    paths: List[str] = []
    for row in list_golden_paths(os_name=os_name):
        for step in row.steps:
            for candidate in (step.module_path, step.recovery_alternate):
                token = str(candidate or "").strip()
                if token and token not in paths:
                    paths.append(token)
    return paths


def validate_golden_path_catalog(
    discovered: Mapping[str, str],
    *,
    extract_metadata: Optional[Callable[[str], Dict[str, Any]]] = None,
    os_name: str = "",
    strict: bool = False,
) -> Dict[str, Any]:
    """Ensure golden-path modules exist on disk; optionally run strict contract tests."""
    missing: List[str] = []
    invalid: List[Dict[str, Any]] = []
    valid: List[str] = []
    rows: List[Dict[str, Any]] = []

    for path_id, golden in GOLDEN_PATH_MATRIX.items():
        if os_name and golden.os.lower() != str(os_name).lower():
            continue
        for step in golden.steps:
            for role, module_path in (
                ("primary", step.module_path),
                ("recovery", step.recovery_alternate),
            ):
                token = str(module_path or "").strip()
                if not token:
                    continue
                file_path = discovered.get(token)
                if not file_path or not Path(str(file_path)).is_file():
                    missing.append(token)
                    rows.append(
                        {
                            "golden_path": path_id,
                            "stage": step.stage,
                            "role": role,
                            "module_path": token,
                            "ok": False,
                            "reason": "missing_from_catalog",
                        }
                    )
                    continue
                ok = True
                issues: List[str] = []
                if strict and extract_metadata is not None:
                    contract_row = run_module_contract_test(
                        token,
                        str(file_path),
                        extract_metadata=extract_metadata,
                        strict=True,
                    )
                    ok = bool(contract_row.get("valid"))
                    issues = list(contract_row.get("issues") or [])
                rows.append(
                    {
                        "golden_path": path_id,
                        "stage": step.stage,
                        "role": role,
                        "module_path": token,
                        "ok": ok,
                        "issues": issues,
                    }
                )
                if ok:
                    if token not in valid:
                        valid.append(token)
                else:
                    invalid.append({"module_path": token, "issues": issues})

    return {
        "ok": not missing and not invalid,
        "missing": missing,
        "invalid": invalid,
        "valid": valid,
        "checked": len(rows),
        "rows": rows,
    }


def build_lab_module_checks(
    golden: GoldenPath,
    *,
    host: str,
    ports: Mapping[str, int],
    credentials: Optional[Mapping[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Build ``type=module`` lab checks for a golden path (live validation)."""
    creds = dict(credentials or {})
    checks: List[Dict[str, Any]] = []
    for step in golden.steps:
        module_path = str(step.module_path or "").strip()
        if not module_path:
            continue
        options: Dict[str, Any] = {}
        service = golden.service.lower()
        if service == "http":
            port = int(ports.get("http") or ports.get("web") or 80)
            options["target"] = f"http://{host}:{port}/"
        elif service == "ssh":
            port = int(ports.get("ssh") or 22)
            options["rhost"] = host
            options["rport"] = port
        elif service == "smb":
            port = int(ports.get("smb") or 445)
            options["rhost"] = host
            options["rport"] = port
        elif service == "ftp":
            port = int(ports.get("ftp") or 21)
            options["rhost"] = host
            options["rport"] = port
        elif service == "mysql":
            port = int(ports.get("mysql") or 3306)
            options["rhost"] = host
            options["rport"] = port
        elif service == "winrm":
            port = int(ports.get("winrm") or 5985)
            options["rhost"] = host
            options["rport"] = port
        if creds.get("username"):
            options.setdefault("username", creds["username"])
        if creds.get("password"):
            options.setdefault("password", creds["password"])
        checks.append(
            {
                "id": f"{golden.id}:{step.stage}",
                "type": "module",
                "module": module_path,
                "options": options,
                "stage": step.stage,
                "golden_path": golden.id,
            }
        )
    return checks
