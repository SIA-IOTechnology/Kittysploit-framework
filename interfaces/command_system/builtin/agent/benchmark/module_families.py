#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Benchmark/lab module families and golden-path expectations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.module_contract import (
    build_module_contract,
    validate_module_contract,
)
from interfaces.command_system.builtin.agent.chain_meta import normalize_chain_block
from interfaces.command_system.builtin.agent.metadata_chain_inference import chain_is_empty


@dataclass(frozen=True)
class ModuleFamilySpec:
    id: str
    description: str
    path_prefixes: Sequence[str]
    min_declared_compliance: float = 0.95
    min_chain_coverage: float = 0.95
    tags: Sequence[str] = field(default_factory=tuple)


BENCHMARK_MODULE_FAMILIES: Dict[str, ModuleFamilySpec] = {
    "http": ModuleFamilySpec(
        id="http",
        description="HTTP discovery, fingerprinting and web validation modules",
        path_prefixes=(
            "scanner/http/",
            "auxiliary/scanner/http/",
            "exploits/multi/http/",
            "exploits/unix/webapp/",
            "exploits/windows/http/",
        ),
        tags=("http", "web"),
    ),
    "tcp_service": ModuleFamilySpec(
        id="tcp_service",
        description="TCP/service fingerprinting and banner intelligence",
        path_prefixes=(
            "auxiliary/scanner/portscan/",
            "auxiliary/scanner/fingerprint/",
            "scanner/tcp/",
        ),
        tags=("tcp", "service"),
    ),
    "smb": ModuleFamilySpec(
        id="smb",
        description="SMB discovery, enumeration and session acquisition",
        path_prefixes=("auxiliary/scanner/smb/", "exploits/windows/smb/"),
        tags=("smb", "windows"),
    ),
    "ssh": ModuleFamilySpec(
        id="ssh",
        description="SSH discovery and authentication surfaces",
        path_prefixes=("auxiliary/scanner/ssh/", "exploits/linux/ssh/", "exploits/unix/ssh/"),
        tags=("ssh", "linux"),
    ),
    "ftp": ModuleFamilySpec(
        id="ftp",
        description="FTP enumeration modules",
        path_prefixes=("auxiliary/scanner/ftp/", "exploits/unix/ftp/"),
        tags=("ftp",),
    ),
    "database": ModuleFamilySpec(
        id="database",
        description="Database fingerprinting and validation modules",
        path_prefixes=(
            "auxiliary/scanner/db/",
            "auxiliary/scanner/mssql/",
            "auxiliary/scanner/mysql/",
            "auxiliary/scanner/postgres/",
        ),
        tags=("database", "sql"),
    ),
    "winrm": ModuleFamilySpec(
        id="winrm",
        description="WinRM/WSMAN discovery and access modules",
        path_prefixes=(
            "auxiliary/scanner/winrm/",
            "exploits/windows/winrm/",
            "auxiliary/scanner/tcp/winrm_",
            "scanner/tcp/winrm_",
            "post/winrm/",
        ),
        tags=("winrm", "windows"),
    ),
    "session": ModuleFamilySpec(
        id="session",
        description="Explicit session acquisition and stabilization modules",
        path_prefixes=(
            "auxiliary/scanner/smb/session_acquire",
            "auxiliary/scanner/ics/s7comm_session_acquire",
        ),
        min_declared_compliance=1.0,
        min_chain_coverage=1.0,
        tags=("session",),
    ),
}


def module_in_family(module_path: str, family: ModuleFamilySpec) -> bool:
    path = str(module_path or "").lower()
    return any(path.startswith(prefix.lower()) for prefix in family.path_prefixes)


def families_for_suite(suite_id: str) -> List[ModuleFamilySpec]:
    key = str(suite_id or "").strip().lower()
    if key == "synthetic-http-lab":
        return [BENCHMARK_MODULE_FAMILIES["http"]]
    if "linux" in key or "windows" in key or "metasploitable" in key:
        return [
            BENCHMARK_MODULE_FAMILIES[name]
            for name in ("http", "tcp_service", "smb", "ssh", "ftp", "database", "winrm", "session")
        ]
    return list(BENCHMARK_MODULE_FAMILIES.values())


def family_path_prefixes_for_suite(suite_id: str) -> tuple[str, ...]:
    prefixes: set[str] = set()
    for family in families_for_suite(suite_id):
        prefixes.update(str(prefix) for prefix in family.path_prefixes if str(prefix).strip())
    return tuple(sorted(prefixes))


def discovered_for_suite(
    discovered: Mapping[str, str],
    suite_id: str,
) -> Dict[str, str]:
    families = families_for_suite(suite_id)
    return {
        module_path: file_path
        for module_path, file_path in discovered.items()
        if any(module_in_family(module_path, family) for family in families)
    }


def format_family_audit_report(audit: Mapping[str, Any]) -> str:
    lines = [f"overall_ok={audit.get('overall_ok')}"]
    for family_id, row in sorted((audit.get("families") or {}).items()):
        if not isinstance(row, dict):
            continue
        lines.append(
            f"  {family_id}: total={row.get('total', 0)} "
            f"declared={row.get('declared_compliance_ratio', 0)} "
            f"chain={row.get('chain_on_disk_ratio', 0)} ok={row.get('ok')}"
        )
    return "\n".join(lines)


def audit_family_compliance(
    discovered: Mapping[str, str],
    *,
    extract_metadata: Any,
    families: Sequence[ModuleFamilySpec],
) -> Dict[str, Any]:
    """Measure declared on-disk compliance separately from runtime-enriched metadata."""
    rows: List[Dict[str, Any]] = []
    summary: Dict[str, Any] = {"families": {}, "overall_ok": True}

    for family in families:
        total = compliant = chain_ready = 0
        family_rows: List[Dict[str, Any]] = []
        for module_path, file_path in sorted(discovered.items()):
            if not module_in_family(module_path, family):
                continue
            total += 1
            meta = extract_metadata(file_path) if callable(extract_metadata) else {}
            static_agent = meta.get("agent") if isinstance(meta, dict) else None
            options_schema = {}
            if isinstance(meta, dict):
                options_schema = meta.get("options") or {}
            contract = build_module_contract(
                module_path,
                static_meta=meta if isinstance(meta, dict) else {},
                agent_meta=static_agent,
                options_schema=options_schema,
            )
            issues = validate_module_contract(contract) if contract is not None else ["missing agent metadata block"]
            chain_raw = (static_agent or {}).get("chain") if isinstance(static_agent, dict) else None
            has_chain = not chain_is_empty(normalize_chain_block(chain_raw))
            if not issues:
                compliant += 1
            if has_chain:
                chain_ready += 1
            if issues:
                family_rows.append({"path": module_path, "issues": issues})
        declared_ratio = round(compliant / total, 4) if total else 0.0
        chain_ratio = round(chain_ready / total, 4) if total else 0.0
        ok = (
            total > 0
            and declared_ratio >= family.min_declared_compliance
            and chain_ratio >= family.min_chain_coverage
        )
        summary["families"][family.id] = {
            "total": total,
            "declared_compliant": compliant,
            "declared_compliance_ratio": declared_ratio,
            "chain_on_disk_ratio": chain_ratio,
            "min_declared_compliance": family.min_declared_compliance,
            "min_chain_coverage": family.min_chain_coverage,
            "ok": ok,
            "sample_issues": family_rows[:8],
        }
        if total and not ok:
            summary["overall_ok"] = False
        rows.extend(family_rows[:8])

    summary["sample_issues"] = rows[:12]
    return summary
