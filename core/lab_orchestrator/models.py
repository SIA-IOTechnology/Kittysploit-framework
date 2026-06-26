#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LabWalkthroughStep:
    step: int
    title: str
    body: str


@dataclass
class LabObjective:
    id: str
    title: str
    points: int
    check: Dict[str, Any]


@dataclass
class LabScenario:
    id: str
    name: str
    description: str
    environment: str
    difficulty: str = "beginner"
    max_score: int = 100
    tags: List[str] = field(default_factory=list)
    environment_options: Dict[str, Any] = field(default_factory=dict)
    objectives: List[LabObjective] = field(default_factory=list)
    walkthrough: List[LabWalkthroughStep] = field(default_factory=list)
    reset: Dict[str, Any] = field(default_factory=dict)
    source_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["objectives"] = [asdict(item) for item in self.objectives]
        payload["walkthrough"] = [asdict(item) for item in self.walkthrough]
        return payload


@dataclass
class LabObjectiveResult:
    objective_id: str
    title: str
    passed: bool
    points: int
    earned: int
    detail: str = ""


@dataclass
class LabRunResult:
    lab_id: str
    started: bool
    score: int
    max_score: int
    objectives: List[LabObjectiveResult] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def passed(self) -> bool:
        return self.score >= self.max_score and not self.error

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["objectives"] = [asdict(item) for item in self.objectives]
        payload["passed"] = self.passed
        return payload
