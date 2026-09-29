#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Three-level module confidence used by planning and exploit promotion.

``unverified`` modules stay in the catalog but weigh less. An exploit is
promoted only when the evidence gate passed and the module is at least
``detection``. ``lab_confirmed`` records the target version and the last
successful lab run.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

UNVERIFIED = "unverified"
DETECTION = "detection"
LAB_CONFIRMED = "lab_confirmed"

LEVELS = (UNVERIFIED, DETECTION, LAB_CONFIRMED)
_RANK = {UNVERIFIED: 0, DETECTION: 1, LAB_CONFIRMED: 2}
_WEIGHT = {UNVERIFIED: 0.35, DETECTION: 1.0, LAB_CONFIRMED: 1.45}


def normalize_module_path(path: str) -> str:
    text = str(path or "").strip().replace("\\", "/").lstrip("./")
    if text.startswith("modules/"):
        text = text[len("modules/") :]
    return text.lower()


def normalize_level(value: str) -> str:
    text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "detect": DETECTION,
        "detection_only": DETECTION,
        "verified": LAB_CONFIRMED,
        "lab": LAB_CONFIRMED,
        "confirmed": LAB_CONFIRMED,
    }
    text = aliases.get(text, text)
    if text not in _RANK:
        return UNVERIFIED
    return text


class ModuleConfidenceIndex:
    """Merged view of the shipped catalog and the workspace overlay."""

    _current: Optional["ModuleConfidenceIndex"] = None

    def __init__(self, entries: Optional[Mapping[str, Mapping[str, Any]]] = None) -> None:
        self.entries: Dict[str, Dict[str, Any]] = {}
        self.refused: set[str] = set()
        for path, row in (entries or {}).items():
            self._put(path, row)

    @classmethod
    def reset(cls) -> None:
        cls._current = None

    @classmethod
    def configure(cls, *directories: Any) -> "ModuleConfidenceIndex":
        cls._current = cls.load(*directories)
        return cls._current

    @classmethod
    def current(cls) -> "ModuleConfidenceIndex":
        if cls._current is None:
            default = Path(__file__).resolve().parents[4] / "data" / "module_confidence.json"
            cls._current = cls.load(default.parent)
        return cls._current

    @classmethod
    def load(cls, *directories: Any) -> "ModuleConfidenceIndex":
        index = cls()
        for directory in directories:
            if directory is None:
                continue
            path = Path(directory)
            if path.is_file():
                index.merge_file(path)
                continue
            candidate = path / "module_confidence.json"
            if candidate.is_file():
                index.merge_file(candidate)
        return index

    def merge_file(self, path: Path) -> None:
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        modules = payload.get("modules") if isinstance(payload, dict) else None
        if not isinstance(modules, dict):
            return
        for module_path, row in modules.items():
            if isinstance(row, dict):
                self._put(module_path, row)
            elif isinstance(row, str):
                self._put(module_path, {"level": row})

    def _put(self, module_path: str, row: Mapping[str, Any]) -> None:
        key = normalize_module_path(module_path)
        if not key:
            return
        self.entries[key] = {
            "level": normalize_level(str(row.get("level") or UNVERIFIED)),
            "target_version": str(row.get("target_version") or ""),
            "last_success_at": str(row.get("last_success_at") or ""),
        }

    def level(self, module_path: str) -> str:
        row = self.entries.get(normalize_module_path(module_path))
        if not row:
            return UNVERIFIED
        return str(row.get("level") or UNVERIFIED)

    def weight(self, module_path: str) -> float:
        return _WEIGHT[self.level(module_path)]

    def set_refusals(self, paths: Any) -> None:
        self.refused = {normalize_module_path(path) for path in (paths or []) if str(path or "").strip()}

    def is_refused(self, module_path: str) -> bool:
        key = normalize_module_path(module_path)
        return bool(key) and key in self.refused

    def record(self, module_path: str) -> Dict[str, Any]:
        key = normalize_module_path(module_path)
        return dict(self.entries.get(key) or {"level": UNVERIFIED, "target_version": "", "last_success_at": ""})


def exploit_promotion_block_reason(module_path: str, index: Optional[ModuleConfidenceIndex] = None) -> str:
    """Return a block reason when an exploit module is below detection confidence."""
    path = normalize_module_path(module_path)
    if not path:
        return ""
    catalog = index or ModuleConfidenceIndex.current()
    if catalog.is_refused(path):
        return "operator refused this module in the engagement graph"
    level = catalog.level(path)
    if _RANK[level] < _RANK[DETECTION]:
        return (
            f"module confidence is {level}; exploit promotion requires "
            "detection or lab_confirmed"
        )
    return ""


def record_verification(
    directory: Path,
    module_path: str,
    *,
    level: str,
    target_version: str = "",
    succeeded_at: str = "",
) -> Dict[str, Any]:
    """Persist one module's confidence in the workspace overlay."""
    normalized = normalize_level(level)
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    path = root / "module_confidence.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, json.JSONDecodeError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    modules = payload.get("modules")
    if not isinstance(modules, dict):
        modules = {}
    key = normalize_module_path(module_path)
    previous = modules.get(key) if isinstance(modules.get(key), dict) else {}
    stamp = succeeded_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    modules[key] = {
        "level": normalized,
        "target_version": str(target_version or previous.get("target_version") or ""),
        "last_success_at": stamp if normalized == LAB_CONFIRMED else str(previous.get("last_success_at") or ""),
    }
    payload["schema_version"] = "1.0"
    payload["modules"] = modules
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return modules[key]
