#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Load GPO detection rules from data/gpo_rules/."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

_RULES_ROOT = Path(__file__).resolve().parents[3] / "data" / "gpo_rules"


def _load_yaml(path: Path) -> Any:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required for GPO rule loading") from exc
    if not path.is_file():
        return {}
    with open(path, "r", encoding="utf-8") as fp:
        return yaml.safe_load(fp) or {}


def load_group_rules() -> Dict[str, Any]:
    """Privileged local groups and BloodHound edge mapping."""
    data = _load_yaml(_RULES_ROOT / "group.yaml")
    return data if isinstance(data, dict) else {}


def load_registry_rules() -> List[Dict[str, Any]]:
    """Registry misconfiguration detection rules."""
    data = _load_yaml(_RULES_ROOT / "registry.yaml")
    return data if isinstance(data, list) else []


def load_privilege_rules() -> Dict[str, Any]:
    """Dangerous User Rights Assignment rules."""
    data = _load_yaml(_RULES_ROOT / "privilege_rights.yaml")
    return data if isinstance(data, dict) else {}
