#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PlaybookPrerequisites:
    tech_any: List[str] = field(default_factory=list)
    signals_any: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)


@dataclass
class PlaybookChainStep:
    step_id: str
    capability: str
    module: Optional[str] = None
    optional: bool = False
    description: str = ""


@dataclass
class AttackPlaybook:
    playbook_id: str
    version: str = "1"
    name: str = ""
    source: str = ""
    domain: str = ""
    tags: List[str] = field(default_factory=list)
    description: str = ""
    prerequisites: PlaybookPrerequisites = field(default_factory=PlaybookPrerequisites)
    chain: List[PlaybookChainStep] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
