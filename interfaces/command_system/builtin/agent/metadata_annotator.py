#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Infer and inject ``__info__['agent']`` blocks into module sources."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.runtime_policy import assess_module_risk
from interfaces.command_system.builtin.agent.metadata_chain_inference import (
    chain_is_empty,
    enrich_agent_metadata,
    infer_chain_metadata,
    infer_requires_metadata,
)
from interfaces.command_system.builtin.agent.metadata_contract_inference import (
    apply_extended_contract_fields,
    missing_extended_contract_fields,
)

DEFAULT_FAMILIES: Sequence[str] = (
    "scanner",
    "auxiliary/scanner",
    "exploits",
    "post",
)

PRODUCES_BY_FAMILY: Dict[str, List[str]] = {
    "scanner": ["tech_hints", "risk_signals", "endpoints"],
    "auxiliary/scanner": ["tech_hints", "risk_signals", "endpoints", "params"],
    "exploits": ["exploit_paths", "risk_signals"],
    "post": ["risk_signals"],
    "payloads": ["risk_signals"],
}


def infer_agent_metadata(module_path: str, info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build a conservative agent block from module path and optional ``__info__``."""
    info = info if isinstance(info, dict) else {}
    tags = [str(tag).lower() for tag in (info.get("tags") or []) if str(tag).strip()]
    risk = assess_module_risk(
        {
            "tags": tags,
            "path": module_path,
            "description": str(info.get("description", "") or ""),
        },
        module_path,
    )
    family = module_path.split("/")[0] if "/" in module_path else "other"
    if module_path.startswith("auxiliary/scanner/"):
        family_key = "auxiliary/scanner"
    elif module_path.startswith("scanner/"):
        family_key = "scanner"
    elif module_path.startswith("exploits/"):
        family_key = "exploits"
    elif module_path.startswith("post/"):
        family_key = "post"
    elif module_path.startswith("payloads/"):
        family_key = "payloads"
    else:
        family_key = family
    produces = list(PRODUCES_BY_FAMILY.get(family_key, ["risk_signals"]))
    expected = max(1, int(risk.expected_requests or 1))
    if family_key in {"scanner", "auxiliary/scanner"} and expected < 2:
        expected = 2
    if family_key in {"exploits", "post"} and expected < 2:
        expected = 2
    effects = list(risk.effects) or (
        ["network_probe"] if risk.level in {"read", "active"} else ["active_exploitation"]
    )
    chain = infer_chain_metadata(module_path, info)
    requires = infer_requires_metadata(module_path, info)
    agent: Dict[str, Any] = {
        "risk": risk.level,
        "effects": effects,
        "expected_requests": expected,
        "reversible": bool(risk.reversible),
        "approval_required": bool(risk.approval_required),
        "produces": produces,
        "cost": "medium",
        "noise": "low" if family_key in {"scanner"} else "medium",
        "value": "high" if family_key in {"exploits", "post"} else "medium",
    }
    if not chain_is_empty(chain):
        agent["chain"] = chain
    if requires:
        agent["requires"] = requires
    return apply_extended_contract_fields(module_path, agent, info)


def _format_agent_block(agent: Dict[str, Any], indent: str = "        ") -> str:
    inner = indent + "    "
    lines = [
        f"{indent}'agent': {{",
        f"{inner}'risk': {agent['risk']!r},",
        f"{inner}'effects': {agent['effects']!r},",
        f"{inner}'expected_requests': {int(agent['expected_requests'])},",
        f"{inner}'reversible': {str(bool(agent['reversible']))},",
        f"{inner}'approval_required': {str(bool(agent['approval_required']))},",
        f"{inner}'produces': {agent['produces']!r},",
    ]
    for optional in ("cost", "noise", "value"):
        if optional in agent:
            lines.append(f"{inner}'{optional}': {agent[optional]!r},")
    if agent.get("idempotent") is not None:
        lines.append(f"{inner}'idempotent': {str(bool(agent['idempotent']))},")
    if agent.get("isolation"):
        lines.append(f"{inner}'isolation': {agent['isolation']!r},")
    for list_field in (
        "network_destinations",
        "privileges_required",
        "side_effects",
        "success_validators",
    ):
        if agent.get(list_field):
            lines.append(f"{inner}'{list_field}': {agent[list_field]!r},")
    if agent.get("requires"):
        lines.append(f"{inner}'requires': {_repr_dict(agent['requires'], inner)},")
    if agent.get("incompatible_when"):
        lines.append(f"{inner}'incompatible_when': {_repr_dict(agent['incompatible_when'], inner)},")
    if agent.get("chain"):
        lines.append(f"{inner}'chain': {_repr_dict(agent['chain'], inner)},")
    lines.append(f"{indent}}},")
    return "\n".join(lines)


def _repr_dict(value: Dict[str, Any], inner: str) -> str:
    import pprint

    rendered = pprint.pformat(value, width=100, sort_dicts=False)
    rendered_lines = rendered.splitlines()
    if len(rendered_lines) == 1:
        return rendered
    return "\n".join(inner + line for line in rendered_lines)


def _find_info_dict_node(tree: ast.AST) -> Optional[ast.Dict]:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "__info__":
                if isinstance(node.value, ast.Dict):
                    return node.value
                return None
    return None


def _info_dict_has_agent(info_node: ast.Dict) -> bool:
    for key in info_node.keys:
        if isinstance(key, ast.Constant) and str(key.value) == "agent":
            return True
    return False


def _partial_info_from_node(info_node: ast.Dict) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    for key, value in zip(info_node.keys, info_node.values):
        if not isinstance(key, ast.Constant):
            continue
        field = str(key.value)
        try:
            parsed = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            if isinstance(value, ast.Constant):
                parsed = value.value
            elif field == "description" and isinstance(value, ast.JoinedStr):
                parsed = ""
            else:
                continue
        info[field] = parsed
    return info


def _load_info_dict(source: str) -> Optional[Dict[str, Any]]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    info_node = _find_info_dict_node(tree)
    if info_node is None:
        return None
    try:
        value = ast.literal_eval(info_node)
    except (ValueError, SyntaxError):
        value = _partial_info_from_node(info_node)
    return value if isinstance(value, dict) else None


def _ensure_trailing_comma(lines: List[str], insert_at: int) -> None:
    prev_idx = insert_at - 1
    while prev_idx >= 0 and not lines[prev_idx].strip():
        prev_idx -= 1
    if prev_idx < 0:
        return
    prev = lines[prev_idx].rstrip()
    if prev and not prev.endswith(","):
        lines[prev_idx] = prev + ","


def repair_missing_comma_before_agent(source: str) -> Optional[str]:
    """Fix ``__info__`` dicts where an injected agent block omitted a comma."""
    lines = source.splitlines()
    changed = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("'agent'") and not stripped.startswith('"agent"'):
            continue
        prev_idx = index - 1
        while prev_idx >= 0 and not lines[prev_idx].strip():
            prev_idx -= 1
        if prev_idx < 0:
            continue
        prev = lines[prev_idx].rstrip()
        if prev and not prev.endswith(","):
            lines[prev_idx] = prev + ","
            changed = True
    if not changed:
        return None
    return "\n".join(lines) + ("\n" if source.endswith("\n") else "")


def inject_agent_into_source(source: str, module_path: str) -> Optional[str]:
    """Return updated source when an agent block was injected."""
    if "__info__" not in source:
        return None
    try:
        tree = ast.parse(source)
    except SyntaxError:
        repaired = repair_missing_comma_before_agent(source)
        if not repaired:
            return None
        source = repaired
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return None
    info_node = _find_info_dict_node(tree)
    if info_node is None or _info_dict_has_agent(info_node):
        return None
    info = _partial_info_from_node(info_node)
    if not info:
        info = {}
    agent = infer_agent_metadata(module_path, info)
    end_line = int(info_node.end_lineno or 0) - 1
    if end_line < 0:
        return None
    lines = source.splitlines()
    closing = lines[end_line]
    base_indent = closing[: len(closing) - len(closing.lstrip())]
    block = _format_agent_block(agent, base_indent)
    _ensure_trailing_comma(lines, end_line)
    lines.insert(end_line, block)
    return "\n".join(lines) + ("\n" if source.endswith("\n") else "")


def upgrade_agent_in_source(source: str, module_path: str) -> Optional[str]:
    """Inject or enrich chain/requires on an existing agent block."""
    if "__info__" not in source or "'agent'" not in source and '"agent"' not in source:
        return None
    info = _load_info_dict(source)
    if not isinstance(info, dict):
        return None
    existing = info.get("agent") if isinstance(info.get("agent"), dict) else {}
    enriched = apply_extended_contract_fields(module_path, enrich_agent_metadata(module_path, existing, info), info)
    from interfaces.command_system.builtin.agent.agent_module_meta import normalize_agent_block

    normalized_existing = normalize_agent_block(existing) or {}
    normalized_enriched = normalize_agent_block(enriched) or {}
    needs_chain = chain_is_empty(normalized_existing.get("chain")) and not chain_is_empty(
        normalized_enriched.get("chain")
    )
    needs_contract = bool(missing_extended_contract_fields(normalized_existing)) and not bool(
        missing_extended_contract_fields(normalized_enriched)
    )
    if not needs_chain and not needs_contract and normalized_existing == normalized_enriched:
        return None
    return _replace_agent_block(source, module_path, enriched, info)


def _replace_agent_block(
    source: str,
    module_path: str,
    agent: Dict[str, Any],
    info: Dict[str, Any],
) -> Optional[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    info_node = _find_info_dict_node(tree)
    if info_node is None or not _info_dict_has_agent(info_node):
        return inject_agent_into_source(source, module_path)
    start = int(info_node.lineno or 1) - 1
    end = int(info_node.end_lineno or start + 1)
    lines = source.splitlines()
    # Remove old agent key from __info__ dict text and append enriched block before closing brace
    closing_idx = end - 1
    closing = lines[closing_idx]
    base_indent = closing[: len(closing) - len(closing.lstrip())]
    # Strip lines belonging to agent sub-dict
    agent_start = None
    for idx in range(start, closing_idx + 1):
        stripped = lines[idx].strip()
        if stripped.startswith("'agent'") or stripped.startswith('"agent"'):
            agent_start = idx
            break
    if agent_start is None:
        return inject_agent_into_source(source, module_path)
    agent_end = agent_start + 1
    depth = 0
    for idx in range(agent_start, closing_idx + 1):
        line = lines[idx]
        depth += line.count("{") - line.count("}")
        if idx > agent_start and depth <= 0:
            agent_end = idx
            break
    else:
        agent_end = closing_idx
    block = _format_agent_block(agent, base_indent)
    new_lines = lines[:agent_start] + [block] + lines[agent_end + 1 :]
    return "\n".join(new_lines) + ("\n" if source.endswith("\n") else "")


def upgrade_module_file(file_path: Path, module_path: str, *, dry_run: bool = True) -> Tuple[bool, str]:
    source = file_path.read_text(encoding="utf-8", errors="ignore")
    if "'agent'" not in source and '"agent"' not in source:
        updated = inject_agent_into_source(source, module_path)
        action = "inject"
    else:
        updated = upgrade_agent_in_source(source, module_path)
        action = "upgrade"
    if not updated:
        return False, "skipped"
    if not dry_run:
        file_path.write_text(updated, encoding="utf-8")
    return True, action if not dry_run else f"would_{action}"


def annotate_module_file(file_path: Path, module_path: str, *, dry_run: bool = True) -> Tuple[bool, str]:
    source = file_path.read_text(encoding="utf-8", errors="ignore")
    repaired = repair_missing_comma_before_agent(source)
    if repaired and not dry_run:
        source = repaired
        file_path.write_text(source, encoding="utf-8")
    updated = inject_agent_into_source(source, module_path)
    if not updated:
        return False, "skipped"
    if not dry_run:
        file_path.write_text(updated, encoding="utf-8")
    return True, "updated" if not dry_run else "would_update"


def module_matches_families(module_path: str, families: Iterable[str]) -> bool:
    path = str(module_path or "")
    for family in families:
        token = str(family or "").strip()
        if not token:
            continue
        if token.endswith("/"):
            if path.startswith(token):
                return True
        elif path.startswith(f"{token}/") or path == token:
            return True
    return False


def module_matches_prefixes(module_path: str, prefixes: Iterable[str]) -> bool:
    path = str(module_path or "").lower()
    return any(path.startswith(str(prefix or "").lower()) for prefix in prefixes if str(prefix or "").strip())


def _filter_discovered(
    discovered: Dict[str, str],
    *,
    families: Iterable[str] = (),
    prefixes: Iterable[str] = (),
) -> Dict[str, str]:
    prefix_list = tuple(prefixes)
    family_list = tuple(families)
    if prefix_list:
        return {
            path: file_path
            for path, file_path in discovered.items()
            if module_matches_prefixes(path, prefix_list)
        }
    if family_list:
        return {
            path: file_path
            for path, file_path in discovered.items()
            if module_matches_families(path, family_list)
        }
    return dict(discovered)


def upgrade_catalog(
    discovered: Dict[str, str],
    extract_info: Any,
    *,
    families: Iterable[str] = DEFAULT_FAMILIES,
    prefixes: Iterable[str] = (),
    dry_run: bool = True,
    limit: int = 0,
) -> Dict[str, Any]:
    filtered = _filter_discovered(discovered, families=families, prefixes=prefixes)
    prefix_list = tuple(prefixes)
    family_list = tuple(families)
    updated = skipped = errors = 0
    rows: List[Dict[str, str]] = []
    count = 0
    for module_path in sorted(filtered):
        file_path = Path(filtered[module_path])
        if not file_path.is_file():
            skipped += 1
            continue
        count += 1
        if limit > 0 and count > limit:
            break
        try:
            ok, status = upgrade_module_file(file_path, module_path, dry_run=dry_run)
        except OSError as exc:
            errors += 1
            rows.append({"path": module_path, "status": f"error: {exc}"})
            continue
        if ok:
            updated += 1
            rows.append({"path": module_path, "status": status})
        else:
            skipped += 1
    return {
        "dry_run": dry_run,
        "mode": "upgrade",
        "families": list(family_list),
        "prefixes": list(prefix_list),
        "updated": updated,
        "skipped": skipped,
        "errors": errors,
        "sample": rows[:20],
    }


def annotate_catalog(
    discovered: Dict[str, str],
    extract_info: Any,
    *,
    families: Iterable[str] = DEFAULT_FAMILIES,
    prefixes: Iterable[str] = (),
    dry_run: bool = True,
    limit: int = 0,
) -> Dict[str, Any]:
    filtered = _filter_discovered(discovered, families=families, prefixes=prefixes)
    prefix_list = tuple(prefixes)
    family_list = tuple(families)
    updated = skipped = errors = 0
    rows: List[Dict[str, str]] = []
    count = 0
    for module_path in sorted(filtered):
        file_path = Path(filtered[module_path])
        if not file_path.is_file():
            skipped += 1
            continue
        count += 1
        if limit > 0 and count > limit:
            break
        try:
            ok, status = annotate_module_file(file_path, module_path, dry_run=dry_run)
        except OSError as exc:
            errors += 1
            rows.append({"path": module_path, "status": f"error: {exc}"})
            continue
        if ok:
            updated += 1
            rows.append({"path": module_path, "status": status})
        else:
            skipped += 1
    return {
        "dry_run": dry_run,
        "mode": "annotate",
        "families": list(family_list),
        "prefixes": list(prefix_list),
        "updated": updated,
        "skipped": skipped,
        "errors": errors,
        "sample": rows[:20],
    }


def annotate_benchmark_suite(
    discovered: Dict[str, str],
    extract_info: Any,
    suite_id: str,
    *,
    dry_run: bool = True,
    limit: int = 0,
) -> Dict[str, Any]:
    from interfaces.command_system.builtin.agent.benchmark.module_families import (
        family_path_prefixes_for_suite,
    )

    return annotate_catalog(
        discovered,
        extract_info,
        prefixes=family_path_prefixes_for_suite(suite_id),
        dry_run=dry_run,
        limit=limit,
    )


def upgrade_benchmark_suite(
    discovered: Dict[str, str],
    extract_info: Any,
    suite_id: str,
    *,
    dry_run: bool = True,
    limit: int = 0,
) -> Dict[str, Any]:
    from interfaces.command_system.builtin.agent.benchmark.module_families import (
        family_path_prefixes_for_suite,
    )

    return upgrade_catalog(
        discovered,
        extract_info,
        prefixes=family_path_prefixes_for_suite(suite_id),
        dry_run=dry_run,
        limit=limit,
    )
