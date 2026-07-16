#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from core.lab_orchestrator.models import LabObjective, LabScenario, LabWalkthroughStep
from core.utils.paths import framework_root


def default_labs_dir() -> Path:
    root = framework_root()
    if root is None:
        return Path("labs")
    return root / "labs"


def discover_lab_scenarios(labs_dir: Path | None = None) -> List[LabScenario]:
    root = labs_dir or default_labs_dir()
    if not root.is_dir():
        return []
    scenarios: List[LabScenario] = []
    for path in sorted(root.glob("*.json")):
        try:
            scenarios.append(load_lab_scenario(path))
        except Exception:
            continue
    return scenarios


def load_lab_scenario(path: str | Path) -> LabScenario:
    file_path = Path(path)
    with open(file_path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)

    objectives = [
        LabObjective(
            id=str(item.get("id") or ""),
            title=str(item.get("title") or item.get("id") or ""),
            points=int(item.get("points") or 0),
            check=dict(item.get("check") or {}),
        )
        for item in raw.get("objectives") or []
    ]
    agent_objectives = [
        LabObjective(
            id=str(item.get("id") or ""),
            title=str(item.get("title") or item.get("id") or ""),
            points=int(item.get("points") or 0),
            check=dict(item.get("check") or {}),
        )
        for item in raw.get("agent_objectives") or []
    ]
    walkthrough = [
        LabWalkthroughStep(
            step=int(item.get("step") or index + 1),
            title=str(item.get("title") or ""),
            body=str(item.get("body") or ""),
        )
        for index, item in enumerate(raw.get("walkthrough") or [])
    ]

    lab_id = str(raw.get("id") or file_path.stem)
    return LabScenario(
        id=lab_id,
        name=str(raw.get("name") or lab_id),
        description=str(raw.get("description") or ""),
        environment=str(raw.get("environment") or ""),
        difficulty=str(raw.get("difficulty") or "beginner"),
        max_score=int(raw.get("max_score") or sum(obj.points for obj in objectives) or 100),
        tags=[str(tag) for tag in raw.get("tags") or []],
        environment_options=dict(raw.get("environment_options") or {}),
        objectives=objectives,
        agent_objectives=agent_objectives,
        walkthrough=walkthrough,
        reset=dict(raw.get("reset") or {}),
        manifest=str(raw.get("manifest") or ""),
        readiness_checks=[dict(item) for item in raw.get("readiness_checks") or []],
        source_path=str(file_path),
    )


def find_lab_scenario(lab_id: str, labs_dir: Path | None = None) -> LabScenario:
    for scenario in discover_lab_scenarios(labs_dir):
        if scenario.id == lab_id:
            return scenario
    candidate = (labs_dir or default_labs_dir()) / f"{lab_id}.json"
    if candidate.is_file():
        return load_lab_scenario(candidate)
    raise FileNotFoundError(f"Lab scenario not found: {lab_id}")
