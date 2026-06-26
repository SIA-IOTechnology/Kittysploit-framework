#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from core.attack_mapping.constants import OFFENSIVE_MODULE_TYPES
from core.attack_mapping.models import AttackCatalog, AttackModuleMapping
from core.attack_mapping.parser import parse_attack_mapping


def build_attack_catalog(discovered_modules: Dict[str, str]) -> AttackCatalog:
    mappings: List[AttackModuleMapping] = []
    technique_index: Dict[str, List[str]] = defaultdict(list)
    tactic_index: Dict[str, List[str]] = defaultdict(list)
    offensive_techniques: Dict[str, List[str]] = defaultdict(list)
    defensive_techniques: Dict[str, List[str]] = defaultdict(list)

    declared_count = 0
    inferred_only_count = 0

    for module_path, file_path in sorted(discovered_modules.items()):
        mapping = parse_attack_mapping(module_path, file_path)
        mappings.append(mapping)
        if mapping.declared:
            declared_count += 1
        elif mapping.inferred_techniques:
            inferred_only_count += 1

        for tactic in mapping.tactics:
            if module_path not in tactic_index[tactic]:
                tactic_index[tactic].append(module_path)

        for technique in mapping.all_techniques:
            if module_path not in technique_index[technique]:
                technique_index[technique].append(module_path)
            if mapping.module_type in OFFENSIVE_MODULE_TYPES:
                if module_path not in offensive_techniques[technique]:
                    offensive_techniques[technique].append(module_path)
            if mapping.has_defensive_metadata:
                if module_path not in defensive_techniques[technique]:
                    defensive_techniques[technique].append(module_path)

    return AttackCatalog(
        mappings=mappings,
        technique_index=dict(sorted(technique_index.items())),
        tactic_index=dict(sorted(tactic_index.items())),
        offensive_techniques=dict(sorted(offensive_techniques.items())),
        defensive_techniques=dict(sorted(defensive_techniques.items())),
        declared_count=declared_count,
        inferred_only_count=inferred_only_count,
    )
