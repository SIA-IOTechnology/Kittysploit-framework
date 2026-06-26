#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class AttackModuleMapping:
    """ATT&CK metadata attached to one KittySploit module."""

    module_path: str
    module_name: str
    module_type: str
    tactics: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    detections: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    declared: bool = False
    inferred_techniques: List[str] = field(default_factory=list)

    @property
    def all_techniques(self) -> List[str]:
        seen: List[str] = []
        for technique in list(self.techniques) + list(self.inferred_techniques):
            if technique and technique not in seen:
                seen.append(technique)
        return seen

    @property
    def has_defensive_metadata(self) -> bool:
        return bool(self.detections or self.artifacts)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackCatalog:
    """Workspace-wide ATT&CK index built from module metadata."""

    mappings: List[AttackModuleMapping]
    technique_index: Dict[str, List[str]]
    tactic_index: Dict[str, List[str]]
    offensive_techniques: Dict[str, List[str]]
    defensive_techniques: Dict[str, List[str]]
    declared_count: int
    inferred_only_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "declared_count": self.declared_count,
            "inferred_only_count": self.inferred_only_count,
            "technique_index": self.technique_index,
            "tactic_index": self.tactic_index,
            "offensive_techniques": self.offensive_techniques,
            "defensive_techniques": self.defensive_techniques,
            "mappings": [mapping.to_dict() for mapping in self.mappings],
        }
