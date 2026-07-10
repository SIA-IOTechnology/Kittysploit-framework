#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Automatic module inventory: metadata, coverage analysis, and gap detection."""

from __future__ import annotations

import ast
import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from core.attack_mapping.parser import parse_attack_mapping
from core.module_search import extract_search_facets, infer_protocol_from_module_path
from core.utils.module_static_metadata import (
    SUPPORTED_MODULE_TYPES,
    _find_module_info_dict,
    _literal_bool,
    _literal_strings,
    _string_ast_value,
    infer_module_type_from_path,
    parse_static_module_info,
    validate_static_module_contract,
)

EXPECTED_PROTOCOLS = (
    "http",
    "https",
    "ssh",
    "ftp",
    "smb",
    "ldap",
    "mysql",
    "redis",
    "tcp",
    "udp",
    "cloud",
    "dns",
    "mqtt",
)

MIN_PROTOCOL_COVERAGE = 3


@dataclass
class ModuleInventoryEntry:
    path: str
    file_path: str
    name: str
    description: str
    module_type: str
    protocol: str
    platform: str
    cve: str
    reliability: str
    tags: List[str] = field(default_factory=list)
    required_options: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    optional_dependencies: List[str] = field(default_factory=list)
    privileges: List[str] = field(default_factory=list)
    attack_techniques: List[str] = field(default_factory=list)
    valid: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InventoryAnalysis:
    entries: List[ModuleInventoryEntry]
    total: int
    by_type: Dict[str, int]
    by_protocol: Dict[str, int]
    by_platform: Dict[str, int]
    duplicates_by_name: Dict[str, List[str]]
    duplicates_by_cve: Dict[str, List[str]]
    duplicates_by_basename: Dict[str, List[str]]
    broken_modules: List[str]
    incomplete_modules: List[str]
    empty_categories: List[str]
    coverage_gaps: List[Dict[str, Any]]
    attack_technique_coverage: Dict[str, List[str]]
    high_potential_areas: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["entries"] = [entry.to_dict() for entry in self.entries]
        return payload


def _info_extras_from_file(file_path: str) -> Dict[str, Any]:
    extras: Dict[str, Any] = {
        "dependencies": [],
        "optional_dependencies": [],
        "requires_root": False,
        "required_privileges": [],
        "attack_techniques": [],
    }
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            tree = ast.parse(handle.read(), filename=file_path)
    except Exception:
        return extras

    info_node = _find_module_info_dict(tree)
    if info_node is None:
        return extras

    if isinstance(info_node, ast.Dict):
        try:
            evaluated = ast.literal_eval(info_node)
        except Exception:
            evaluated = None
        if isinstance(evaluated, dict):
            extras["dependencies"] = _string_list(evaluated.get("dependencies"))
            extras["optional_dependencies"] = _string_list(
                evaluated.get("optional_dependencies")
            )
            extras["requires_root"] = bool(evaluated.get("requires_root"))
            extras["required_privileges"] = _string_list(
                evaluated.get("required_privileges")
                or evaluated.get("privileges_required")
                or evaluated.get("privileges")
            )
            extras["attack_techniques"] = _string_list(
                evaluated.get("attack_techniques")
                or evaluated.get("mitre_techniques")
                or evaluated.get("techniques")
            )
            return extras

        for key_node, value_node in zip(info_node.keys, info_node.values):
            key = _string_ast_value(key_node)
            if not key:
                continue
            key_lower = key.lower()
            if key_lower == "dependencies":
                extras["dependencies"] = _literal_strings(value_node)
            elif key_lower == "optional_dependencies":
                extras["optional_dependencies"] = _literal_strings(value_node)
            elif key_lower == "requires_root":
                value = _literal_bool(value_node)
                if value is not None:
                    extras["requires_root"] = value
            elif key_lower in {
                "required_privileges",
                "privileges_required",
                "privileges",
            }:
                extras["required_privileges"] = _literal_strings(value_node)
            elif key_lower in {"attack_techniques", "mitre_techniques", "techniques"}:
                extras["attack_techniques"] = _literal_strings(value_node)
    return extras


def _normalize_cve(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        for item in value:
            text = str(item).strip().upper()
            if text:
                return text
        return ""
    return str(value or "").strip().upper()


def _string_list(value: Any) -> List[str]:
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def build_inventory_entry(module_path: str, file_path: str) -> ModuleInventoryEntry:
    contract = validate_static_module_contract(module_path, file_path)
    metadata = contract.get("metadata") or {}
    info = parse_static_module_info(file_path)
    extras = _info_extras_from_file(file_path)
    facets = extract_search_facets(info, module_path)

    options = metadata.get("options") or {}
    required_options = sorted(
        name for name, data in options.items() if data.get("required")
    )

    privileges: List[str] = []
    if extras.get("requires_root"):
        privileges.append("root")
    privileges.extend(extras.get("required_privileges") or [])

    references = info.get("references") or []
    if isinstance(references, str):
        references = [references]

    attack_mapping = parse_attack_mapping(module_path, file_path)
    attack_techniques = attack_mapping.all_techniques

    module_type = (
        metadata.get("module_type")
        or infer_module_type_from_path(module_path)
    )

    return ModuleInventoryEntry(
        path=module_path,
        file_path=file_path,
        name=str(info.get("name") or metadata.get("name") or "").strip(),
        description=str(info.get("description") or "").strip(),
        module_type=str(module_type or ""),
        protocol=facets.get("protocol") or "",
        platform=facets.get("platform") or "",
        cve=_normalize_cve(info.get("cve")),
        reliability=facets.get("reliability") or "",
        tags=[str(tag) for tag in (info.get("tags") or []) if str(tag).strip()],
        required_options=required_options,
        dependencies=list(extras.get("dependencies") or []),
        optional_dependencies=list(extras.get("optional_dependencies") or []),
        privileges=sorted(set(privileges)),
        attack_techniques=attack_techniques,
        valid=bool(contract.get("valid")),
        errors=list(contract.get("errors") or []),
        warnings=list(contract.get("warnings") or []),
    )


def build_module_inventory(
    discovered_modules: Dict[str, str],
    *,
    module_type: str = "",
    protocol: str = "",
) -> List[ModuleInventoryEntry]:
    entries: List[ModuleInventoryEntry] = []
    type_filter = (module_type or "").strip().lower()
    protocol_filter = (protocol or "").strip().lower()

    for module_path, file_path in sorted(discovered_modules.items()):
        entry = build_inventory_entry(module_path, file_path)
        if type_filter and entry.module_type.lower() != type_filter:
            continue
        if protocol_filter and entry.protocol.lower() != protocol_filter:
            continue
        entries.append(entry)
    return entries


def _duplicate_groups(
    entries: Iterable[ModuleInventoryEntry],
    key_fn,
) -> Dict[str, List[str]]:
    groups: Dict[str, List[str]] = defaultdict(list)
    for entry in entries:
        key = key_fn(entry)
        if not key:
            continue
        groups[key].append(entry.path)
    return {key: paths for key, paths in groups.items() if len(paths) > 1}


def _duplicate_cve_groups(entries: Iterable[ModuleInventoryEntry]) -> Dict[str, List[str]]:
    """Flag CVE collisions only within the same module type (scanner+exploit pairs are OK)."""
    groups: Dict[tuple[str, str], List[str]] = defaultdict(list)
    for entry in entries:
        cve = (entry.cve or "").strip().upper()
        if not cve:
            continue
        groups[(cve, entry.module_type or "unknown")].append(entry.path)
    return {
        cve: paths
        for (cve, _module_type), paths in groups.items()
        if len(paths) > 1
    }


def _is_incomplete(entry: ModuleInventoryEntry) -> bool:
    if entry.errors:
        return True
    if not entry.name or not entry.description:
        return True
    if entry.module_type in {"exploits", "scanner", "auxiliary"} and not entry.protocol:
        return True
    if entry.module_type in {"exploits", "post"} and not entry.platform:
        return True
    return False


def analyze_inventory(entries: List[ModuleInventoryEntry]) -> InventoryAnalysis:
    by_type: Counter[str] = Counter()
    by_protocol: Counter[str] = Counter()
    by_platform: Counter[str] = Counter()
    attack_technique_coverage: Dict[str, List[str]] = defaultdict(list)

    for entry in entries:
        by_type[entry.module_type or "unknown"] += 1
        if entry.protocol:
            by_protocol[entry.protocol] += 1
        if entry.platform:
            by_platform[entry.platform] += 1
        for technique in entry.attack_techniques:
            attack_technique_coverage[technique].append(entry.path)

    duplicates_by_name = _duplicate_groups(
        entries,
        lambda item: (item.name or "").strip().lower(),
    )
    duplicates_by_cve = _duplicate_cve_groups(entries)
    duplicates_by_basename = _duplicate_groups(
        entries,
        lambda item: item.path.rsplit("/", 1)[-1].lower(),
    )

    broken_modules = [entry.path for entry in entries if not entry.valid]
    incomplete_modules = [entry.path for entry in entries if _is_incomplete(entry)]
    empty_categories = sorted(
        category
        for category in sorted(SUPPORTED_MODULE_TYPES)
        if by_type.get(category, 0) == 0
    )

    coverage_gaps: List[Dict[str, Any]] = []
    for protocol_name in EXPECTED_PROTOCOLS:
        if protocol_name == "https":
            protocol_count = by_protocol.get("https", 0) + by_protocol.get("http", 0)
        else:
            protocol_count = by_protocol.get(protocol_name, 0)
        if protocol_count < MIN_PROTOCOL_COVERAGE:
            coverage_gaps.append(
                {
                    "kind": "protocol",
                    "value": protocol_name,
                    "count": protocol_count,
                    "threshold": MIN_PROTOCOL_COVERAGE,
                    "message": (
                        f"Only {protocol_count} module(s) tagged for protocol "
                        f"{protocol_name!r} (expected >= {MIN_PROTOCOL_COVERAGE})"
                    ),
                }
            )

    for module_type in ("exploits", "scanner", "post", "payloads", "listeners"):
        count = by_type.get(module_type, 0)
        if count == 0:
            coverage_gaps.append(
                {
                    "kind": "module_type",
                    "value": module_type,
                    "count": 0,
                    "message": f"No modules found for type {module_type!r}",
                }
            )

    high_potential_areas: List[Dict[str, Any]] = []
    exploit_protocols = {
        entry.protocol
        for entry in entries
        if entry.module_type == "exploits" and entry.protocol
    }
    scanner_protocols = {
        entry.protocol
        for entry in entries
        if entry.module_type == "scanner" and entry.protocol
    }
    for protocol_name in sorted(scanner_protocols - exploit_protocols):
        scanner_count = sum(
            1
            for entry in entries
            if entry.module_type == "scanner" and entry.protocol == protocol_name
        )
        if scanner_count >= MIN_PROTOCOL_COVERAGE:
            high_potential_areas.append(
                {
                    "kind": "exploit_gap",
                    "protocol": protocol_name,
                    "scanner_modules": scanner_count,
                    "exploit_modules": 0,
                    "message": (
                        f"Scanner coverage exists for {protocol_name!r} "
                        f"({scanner_count} modules) but no exploit modules were indexed"
                    ),
                }
            )

    return InventoryAnalysis(
        entries=entries,
        total=len(entries),
        by_type=dict(sorted(by_type.items())),
        by_protocol=dict(sorted(by_protocol.items())),
        by_platform=dict(sorted(by_platform.items())),
        duplicates_by_name=duplicates_by_name,
        duplicates_by_cve=duplicates_by_cve,
        duplicates_by_basename=duplicates_by_basename,
        broken_modules=broken_modules,
        incomplete_modules=incomplete_modules,
        empty_categories=empty_categories,
        coverage_gaps=coverage_gaps,
        attack_technique_coverage=dict(sorted(attack_technique_coverage.items())),
        high_potential_areas=high_potential_areas,
    )


def analyze_discovered_modules(
    discovered_modules: Dict[str, str],
    *,
    module_type: str = "",
    protocol: str = "",
) -> InventoryAnalysis:
    entries = build_module_inventory(
        discovered_modules,
        module_type=module_type,
        protocol=protocol,
    )
    return analyze_inventory(entries)


def export_inventory_json(analysis: InventoryAnalysis, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(analysis.to_dict(), handle, indent=2, sort_keys=True)
