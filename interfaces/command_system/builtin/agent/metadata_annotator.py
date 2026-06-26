#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Infer and inject ``__info__['agent']`` blocks into module sources."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.runtime_policy import assess_module_risk

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
    return {
        "risk": risk.level,
        "effects": effects,
        "expected_requests": expected,
        "reversible": bool(risk.reversible),
        "approval_required": bool(risk.approval_required),
        "produces": produces,
    }


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
        f"{indent}}},",
    ]
    return "\n".join(lines)


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


def annotate_catalog(
    discovered: Dict[str, str],
    extract_info: Any,
    *,
    families: Iterable[str] = DEFAULT_FAMILIES,
    dry_run: bool = True,
    limit: int = 0,
) -> Dict[str, Any]:
    families = tuple(families)
    updated = skipped = errors = 0
    rows: List[Dict[str, str]] = []
    count = 0
    for module_path in sorted(discovered):
        if families and not any(
            module_path.startswith(f"{family}/") or module_path == family for family in families
        ):
            continue
        file_path = Path(discovered[module_path])
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
        "families": list(families),
        "updated": updated,
        "skipped": skipped,
        "errors": errors,
        "sample": rows[:20],
    }
