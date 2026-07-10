#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

from core.playbooks.definition import AttackPlaybook, PlaybookChainStep, PlaybookPrerequisites

logger = logging.getLogger(__name__)

PLAYBOOK_LIBRARY_DIR = Path(__file__).resolve().parent / "library"


def _parse_prerequisites(raw: Any) -> PlaybookPrerequisites:
    if not isinstance(raw, dict):
        return PlaybookPrerequisites()
    return PlaybookPrerequisites(
        tech_any=[str(x).lower().strip() for x in (raw.get("tech_any") or []) if str(x).strip()],
        signals_any=[str(x).lower().strip() for x in (raw.get("signals_any") or []) if str(x).strip()],
        capabilities=[str(x).lower().strip() for x in (raw.get("capabilities") or []) if str(x).strip()],
        domains=[str(x).lower().strip() for x in (raw.get("domains") or []) if str(x).strip()],
    )


def _parse_chain(raw: Any) -> List[PlaybookChainStep]:
    steps: List[PlaybookChainStep] = []
    if not isinstance(raw, list):
        return steps
    for idx, row in enumerate(raw):
        if not isinstance(row, dict):
            continue
        step_id = str(row.get("id") or row.get("step_id") or f"step_{idx + 1}").strip()
        capability = str(row.get("capability") or "").strip().lower()
        module = row.get("module")
        module_path = str(module).strip() if module not in (None, "", "null") else None
        steps.append(
            PlaybookChainStep(
                step_id=step_id,
                capability=capability,
                module=module_path,
                optional=bool(row.get("optional", False)),
                description=str(row.get("description") or "").strip(),
            )
        )
    return steps


def parse_playbook_document(raw: Dict[str, Any], source: Optional[Path] = None) -> AttackPlaybook:
    playbook_id = str(raw.get("id") or raw.get("playbook_id") or "").strip()
    if not playbook_id and source:
        playbook_id = source.stem
    if not playbook_id:
        raise ValueError("Playbook document must define 'id'")

    tags = [str(x).strip() for x in (raw.get("tags") or []) if str(x).strip()]
    blockers = [str(x).strip() for x in (raw.get("blockers") or []) if str(x).strip()]
    references = [str(x).strip() for x in (raw.get("references") or []) if str(x).strip()]

    return AttackPlaybook(
        playbook_id=playbook_id,
        version=str(raw.get("version") or "1"),
        name=str(raw.get("name") or playbook_id),
        source=str(raw.get("source") or ""),
        domain=str(raw.get("domain") or "").strip().lower(),
        tags=tags,
        description=str(raw.get("description") or "").strip(),
        prerequisites=_parse_prerequisites(raw.get("prerequisites")),
        chain=_parse_chain(raw.get("chain")),
        blockers=blockers,
        references=references,
        raw=dict(raw),
    )


def load_playbook_file(path: Union[str, Path]) -> AttackPlaybook:
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError(f"Playbook file must contain a mapping: {file_path}")
    return parse_playbook_document(data, source=file_path)


def list_playbook_ids() -> List[str]:
    if not PLAYBOOK_LIBRARY_DIR.is_dir():
        return []
    ids: List[str] = []
    for path in sorted(PLAYBOOK_LIBRARY_DIR.glob("*.yaml")):
        try:
            playbook = load_playbook_file(path)
            ids.append(playbook.playbook_id)
        except Exception as exc:
            logger.warning("Skipping invalid playbook %s: %s", path.name, exc)
    return ids


def load_playbook_definition(playbook_id: str) -> AttackPlaybook:
    key = str(playbook_id or "").strip()
    if not key:
        raise ValueError("playbook_id is required")
    direct = PLAYBOOK_LIBRARY_DIR / f"{key}.yaml"
    if direct.is_file():
        return load_playbook_file(direct)
    for path in PLAYBOOK_LIBRARY_DIR.glob("*.yaml"):
        try:
            playbook = load_playbook_file(path)
            if playbook.playbook_id == key:
                return playbook
        except Exception:
            continue
    raise FileNotFoundError(f"Unknown playbook: {playbook_id}")


def load_all_playbooks() -> List[AttackPlaybook]:
    playbooks: List[AttackPlaybook] = []
    if not PLAYBOOK_LIBRARY_DIR.is_dir():
        return playbooks
    for path in sorted(PLAYBOOK_LIBRARY_DIR.glob("*.yaml")):
        try:
            playbooks.append(load_playbook_file(path))
        except Exception as exc:
            logger.warning("Skipping invalid playbook %s: %s", path.name, exc)
    return playbooks
