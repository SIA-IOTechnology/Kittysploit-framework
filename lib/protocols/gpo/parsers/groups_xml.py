#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Parse Groups.xml Group Policy Preferences files."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional


_ACTION_MAP = {"D": "DELETE", "U": "UPDATE", "C": "CREATE", "R": "REPLACE"}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def parse_groups_xml(text: str) -> Optional[Dict[str, Any]]:
    """Return ``{"Groups.xml": {"Group": [...]}}`` or None."""
    if not text or not text.strip():
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None

    groups_out: List[Dict[str, Any]] = []
    for group_elem in root.findall("Group"):
        props = group_elem.find("Properties")
        if props is None:
            continue

        group_sid = (props.get("groupSid") or "").strip()
        group_name = (props.get("groupName") or "").strip()
        if not group_sid and not group_name:
            continue

        group_dict: Dict[str, Any] = {
            "sid": group_sid or None,
            "name": group_name or None,
        }
        if props.get("newName"):
            group_dict["newname"] = props.get("newName")
        if props.get("userAction"):
            group_dict["useraction"] = props.get("userAction")

        action = _ACTION_MAP.get((props.get("action") or "U").upper(), "UPDATE")
        members_out: List[Dict[str, Any]] = []
        members_parent = props.find("Members")
        if members_parent is not None:
            for member_elem in members_parent.findall("Member"):
                member_name = (member_elem.get("name") or "").strip()
                member_sid = (member_elem.get("sid") or "").strip()
                if not member_name and not member_sid:
                    continue
                members_out.append({
                    "sid": member_sid or None,
                    "name": member_name or None,
                    "action": (member_elem.get("action") or "ADD").upper(),
                })

        groups_out.append({
            "Group": group_dict,
            "Members": members_out,
            "Action": action,
            "DeleteUsers": props.get("deleteAllUsers") == "1",
            "DeleteGroups": props.get("deleteAllGroups") == "1",
        })

    if not groups_out:
        return None
    return {"Groups.xml": {"Group": groups_out}}
