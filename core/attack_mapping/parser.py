#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import ast
from typing import Any, Dict, List, Sequence, Set

from core.attack_mapping.constants import (
    MITRE_TECHNIQUE_RE,
    PATH_TECHNIQUE_HINTS,
    TACTIC_ALIASES,
    TACTIC_TOKEN_RE,
    TECHNIQUE_TOKEN_RE,
)
from core.attack_mapping.models import AttackModuleMapping
from core.utils.module_static_metadata import (
    _find_module_info_dict,
    _literal_strings,
    _string_ast_value,
    infer_module_type_from_path,
    parse_static_module_info,
)


def _string_list(value: Any) -> List[str]:
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def normalize_tactic_id(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if TACTIC_TOKEN_RE.fullmatch(text):
        return text.upper()
    alias = TACTIC_ALIASES.get(text.lower())
    if alias:
        return alias
    return text


def normalize_technique_id(value: str) -> str:
    text = str(value or "").strip().upper()
    if not text:
        return ""
    match = TECHNIQUE_TOKEN_RE.search(text)
    return match.group(0) if match else text


def _attack_block_from_info(info: Dict[str, Any]) -> Dict[str, Any]:
    attack = info.get("attack")
    if isinstance(attack, dict):
        return attack
    return {
        "tactics": info.get("attack_tactics") or info.get("tactics") or [],
        "techniques": info.get("attack_techniques")
        or info.get("mitre_techniques")
        or info.get("techniques")
        or [],
        "prerequisites": info.get("attack_prerequisites")
        or info.get("prerequisites")
        or [],
        "detections": info.get("attack_detections")
        or info.get("detections")
        or info.get("expected_detections")
        or [],
        "artifacts": info.get("attack_artifacts") or info.get("artifacts") or [],
    }


def _read_info_dict(file_path: str) -> Dict[str, Any]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            tree = ast.parse(handle.read(), filename=file_path)
    except Exception:
        return {}

    info_node = _find_module_info_dict(tree)
    if info_node is None:
        return {}

    if isinstance(info_node, ast.Dict):
        try:
            evaluated = ast.literal_eval(info_node)
        except Exception:
            evaluated = None
        if isinstance(evaluated, dict):
            return evaluated

        parsed: Dict[str, Any] = {}
        for key_node, value_node in zip(info_node.keys, info_node.values):
            key = _string_ast_value(key_node)
            if not key:
                continue
            if key == "attack" and isinstance(value_node, ast.Dict):
                block: Dict[str, Any] = {}
                for sub_key_node, sub_value_node in zip(value_node.keys, value_node.values):
                    sub_key = _string_ast_value(sub_key_node)
                    if sub_key:
                        block[sub_key] = _literal_strings(sub_value_node)
                parsed["attack"] = block
            else:
                parsed[key] = _literal_strings(value_node)
        return parsed
    return {}


def infer_techniques(
    *,
    module_path: str,
    references: Sequence[str],
    tags: Sequence[str],
    explicit: Sequence[str],
) -> List[str]:
    techniques: Set[str] = set()
    for item in explicit or []:
        normalized = normalize_technique_id(str(item))
        if normalized:
            techniques.add(normalized)
    for reference in references or []:
        techniques.update(MITRE_TECHNIQUE_RE.findall(str(reference)))
        techniques.update(normalize_technique_id(token) for token in TECHNIQUE_TOKEN_RE.findall(str(reference)))
    for tag in tags or []:
        techniques.update(
            normalize_technique_id(token)
            for token in TECHNIQUE_TOKEN_RE.findall(str(tag))
            if normalize_technique_id(token)
        )
    normalized_path = module_path.replace("\\", "/").lower()
    if normalized_path.startswith("modules/"):
        normalized_path = normalized_path[len("modules/") :]
    for prefix, technique in PATH_TECHNIQUE_HINTS:
        if prefix in normalized_path:
            techniques.add(technique)
    return sorted(techniques)


def parse_attack_mapping(module_path: str, file_path: str) -> AttackModuleMapping:
    info = parse_static_module_info(file_path)
    raw_info = _read_info_dict(file_path)
    attack_block = _attack_block_from_info(raw_info if raw_info else info)

    references = info.get("references") or []
    if isinstance(references, str):
        references = [references]

    declared_tactics = [
        normalize_tactic_id(item)
        for item in _string_list(attack_block.get("tactics"))
        if normalize_tactic_id(item)
    ]
    declared_techniques = [
        normalize_technique_id(item)
        for item in _string_list(attack_block.get("techniques"))
        if normalize_technique_id(item)
    ]
    prerequisites = _string_list(attack_block.get("prerequisites"))
    detections = _string_list(attack_block.get("detections"))
    artifacts = _string_list(attack_block.get("artifacts"))

    inferred = infer_techniques(
        module_path=module_path,
        references=references,
        tags=info.get("tags") or [],
        explicit=[],
    )
    inferred_only = [tech for tech in inferred if tech not in declared_techniques]

    declared = bool(
        declared_tactics
        or declared_techniques
        or prerequisites
        or detections
        or artifacts
    )

    return AttackModuleMapping(
        module_path=module_path,
        module_name=str(info.get("name") or module_path.rsplit("/", 1)[-1]),
        module_type=infer_module_type_from_path(module_path),
        tactics=sorted(set(declared_tactics)),
        techniques=sorted(set(declared_techniques)),
        prerequisites=prerequisites,
        detections=detections,
        artifacts=artifacts,
        declared=declared,
        inferred_techniques=inferred_only,
    )
