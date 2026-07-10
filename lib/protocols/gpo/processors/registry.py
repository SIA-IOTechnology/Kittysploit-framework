#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Normalize registry settings extracted from GPO files."""

from __future__ import annotations

from typing import Any, Dict, List


def build_registry_processed(parsed_files: Dict[str, Any], policy_type: str) -> Dict[str, Dict[str, List[Dict[str, str]]]]:
    processed: Dict[str, Dict[str, List[Dict[str, str]]]] = {}

    registry_xml = parsed_files.get("Registry.xml")
    if isinstance(registry_xml, list):
        processed.setdefault(policy_type, {}).setdefault("Registry.xml", []).extend(registry_xml)

    registry_pol = parsed_files.get("registry.pol")
    if isinstance(registry_pol, list):
        processed.setdefault(policy_type, {}).setdefault("registry.pol", []).extend(registry_pol)

    gpttmpl = parsed_files.get("GptTmpl.inf", {})
    if isinstance(gpttmpl, dict):
        for key, entry in (gpttmpl.get("Registry Values") or {}).items():
            if isinstance(entry, dict):
                row = dict(entry)
                row["Key"] = key
                processed.setdefault(policy_type, {}).setdefault("Registry Values", []).append(row)

    return processed
