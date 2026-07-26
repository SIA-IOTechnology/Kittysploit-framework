#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic contract tests runnable against benchmark module families."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.benchmark.module_families import (
    BENCHMARK_MODULE_FAMILIES,
    ModuleFamilySpec,
    audit_family_compliance,
    families_for_suite,
    module_in_family,
)
from interfaces.command_system.builtin.agent.module_contract import (
    build_contract_from_static_validation,
    build_module_contract,
    validate_module_contract,
)


def run_module_contract_test(
    module_path: str,
    file_path: str,
    *,
    extract_metadata: Optional[Callable[[str], Dict[str, Any]]] = None,
    strict: bool = False,
) -> Dict[str, Any]:
    """Validate one module's static contract without executing it."""
    meta = extract_metadata(file_path) if extract_metadata else {}
    payload = build_contract_from_static_validation(module_path, file_path, static_meta=meta)
    contract_dict = payload.get("contract")
    if contract_dict and strict:
        from interfaces.command_system.builtin.agent.module_contract import ModuleContract

        extra = validate_module_contract(ModuleContract.from_dict(contract_dict), strict=True)
        if extra:
            payload["valid"] = False
            payload["issues"] = list(payload.get("issues") or []) + extra
    return payload


def run_family_contract_tests(
    discovered: Mapping[str, str],
    *,
    extract_metadata: Callable[[str], Dict[str, Any]],
    families: Optional[Sequence[ModuleFamilySpec]] = None,
    limit_per_family: int = 0,
    strict: bool = False,
) -> Dict[str, Any]:
    """Run contract tests for all modules in the selected benchmark families."""
    selected = list(families or BENCHMARK_MODULE_FAMILIES.values())
    results: Dict[str, Any] = {"families": {}, "modules": [], "failed": 0, "passed": 0}

    for family in selected:
        tested = 0
        passed = 0
        failed = 0
        for module_path, file_path in sorted(discovered.items()):
            if not module_in_family(module_path, family):
                continue
            if limit_per_family and tested >= limit_per_family:
                break
            tested += 1
            row = run_module_contract_test(
                module_path,
                file_path,
                extract_metadata=extract_metadata,
                strict=strict,
            )
            results["modules"].append(row)
            if row.get("valid"):
                passed += 1
            else:
                failed += 1
        results["families"][family.id] = {
            "tested": tested,
            "passed": passed,
            "failed": failed,
        }
        results["passed"] += passed
        results["failed"] += failed

    results["compliance"] = audit_family_compliance(
        discovered,
        extract_metadata=extract_metadata,
        families=selected,
    )
    return results


def run_suite_contract_tests(
    discovered: Mapping[str, str],
    suite_id: str,
    *,
    extract_metadata: Callable[[str], Dict[str, Any]],
    limit_per_family: int = 0,
    strict: bool = False,
) -> Dict[str, Any]:
    return run_family_contract_tests(
        discovered,
        extract_metadata=extract_metadata,
        families=families_for_suite(suite_id),
        limit_per_family=limit_per_family,
        strict=strict,
    )


def run_priority_contract_tests(
    discovered: Mapping[str, str],
    *,
    extract_metadata: Callable[[str], Dict[str, Any]],
    families: Optional[Sequence[str]] = None,
    limit: int = 0,
    strict: bool = True,
) -> Dict[str, Any]:
    """Run strict contract tests for priority module families outside lab suites."""
    from interfaces.command_system.builtin.agent.metadata_annotator import (
        DEFAULT_FAMILIES,
        module_matches_families,
    )

    selected = tuple(families or DEFAULT_FAMILIES)
    rows: List[Dict[str, Any]] = []
    passed = failed = 0
    count = 0
    for module_path, file_path in sorted(discovered.items()):
        if not module_matches_families(module_path, selected):
            continue
        count += 1
        if limit > 0 and count > limit:
            break
        row = run_module_contract_test(
            module_path,
            file_path,
            extract_metadata=extract_metadata,
            strict=strict,
        )
        rows.append(row)
        if row.get("valid"):
            passed += 1
        else:
            failed += 1
    return {
        "families": list(selected),
        "strict": strict,
        "tested": len(rows),
        "passed": passed,
        "failed": failed,
        "ok": failed == 0 and passed > 0,
        "modules": rows[:50],
    }
