#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Parse Group Membership sections from GptTmpl.inf."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

_SECTION_RE = re.compile(r"\[\s*(.*?)\s*\]")


def parse_gpttmpl_group_membership(text: str) -> Optional[Dict[str, Any]]:
    """Return ``{"GptTmpl.inf": {"Group Membership": {...}}}`` or None."""
    if not text or not text.strip():
        return None

    current_section: Optional[str] = None
    membership: Dict[str, Dict[str, List[str]]] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue

        section_match = _SECTION_RE.match(line)
        if section_match:
            current_section = section_match.group(1)
            continue

        if current_section != "Group Membership" or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip().strip('"')
        value = value.strip()
        if not value:
            continue

        members = [item.strip() for item in value.split(",") if item.strip()]
        if "__Members" in key:
            group_name = key.replace("__Members", "")
            bucket = "Members"
        elif "__Memberof" in key:
            group_name = key.replace("__Memberof", "")
            bucket = "Memberof"
        else:
            continue

        membership.setdefault(group_name, {}).setdefault(bucket, []).extend(members)

    if not membership:
        return None
    return {"GptTmpl.inf": {"Group Membership": membership}}


def parse_gpttmpl_privilege_rights(text: str) -> Optional[Dict[str, Any]]:
    """Return ``{"GptTmpl.inf": {"Privilege Rights": {...}}}`` or None."""
    if not text or not text.strip():
        return None

    current_section: Optional[str] = None
    privileges: Dict[str, List[str]] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue

        section_match = _SECTION_RE.match(line)
        if section_match:
            current_section = section_match.group(1)
            continue

        if current_section != "Privilege Rights" or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip().strip('"')
        trustees = [item.strip() for item in value.split(",") if item.strip()]
        if trustees:
            privileges[key] = trustees

    if not privileges:
        return None
    return {"GptTmpl.inf": {"Privilege Rights": privileges}}
