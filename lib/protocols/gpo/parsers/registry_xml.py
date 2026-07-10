#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Parse Registry.xml Group Policy Preferences files."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

_ACTION_MAP = {"D": "DELETE", "U": "UPDATE", "C": "CREATE", "R": "REPLACE"}


def _collect_registry_nodes(root: ET.Element) -> List[ET.Element]:
    nodes: List[ET.Element] = []
    for elem in root.iter():
        if elem.tag.endswith("Registry") or elem.tag == "Registry":
            nodes.append(elem)
    return nodes


def parse_registry_xml(text: str) -> Optional[Dict[str, Any]]:
    """Return normalized registry entries from Registry.xml."""
    if not text or not text.strip():
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None

    entries: List[Dict[str, str]] = []
    for registry in _collect_registry_nodes(root):
        props = registry.find("Properties")
        if props is None:
            continue
        hive = (props.get("hive") or "").strip()
        key = (props.get("key") or "").strip().strip("\\")
        name = (props.get("name") or "").strip()
        value = props.get("value") or props.get("defaultValue") or ""
        reg_type = (props.get("type") or "REG_SZ").strip()
        if reg_type == "REG_DWORD" and value:
            try:
                value = str(int(str(value), 16))
            except ValueError:
                pass
        full_key = f"{key}\\{name}" if name else key
        if not hive or not full_key:
            continue
        entries.append({
            "Hive": hive,
            "Key": full_key,
            "Type": reg_type,
            "Data": str(value),
            "Action": _ACTION_MAP.get((props.get("action") or "U").upper(), "UPDATE"),
        })

    if not entries:
        return None
    return {"Registry.xml": entries}
