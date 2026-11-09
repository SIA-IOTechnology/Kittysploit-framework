#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Merge core SSH scanners when port 22 (or 2222) is open."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

SSH_CORE_PATHS: tuple[str, ...] = (
    "scanner/ssh/ssh_auth_methods",
    "scanner/ssh/openssh_banner_detect",
    "scanner/ssh/ssh_hostkey",
)

SSH_PORTS = frozenset({22, 2222, 2223})


def augment_ssh_scan_modules(
    current: Sequence[Dict[str, Any]],
    ssh_catalog: Sequence[Mapping[str, Any]],
    open_ports: Sequence[int],
) -> List[Dict[str, Any]]:
    if not any(int(p) in SSH_PORTS for p in (open_ports or [])):
        return list(current)
    by_path: Dict[str, Dict[str, Any]] = {
        str(m.get("path") or ""): dict(m) for m in current if m.get("path")
    }
    catalog = {str(m.get("path") or ""): dict(m) for m in ssh_catalog if m.get("path")}
    for core in SSH_CORE_PATHS:
        row = catalog.get(core)
        if row:
            by_path.setdefault(core, row)
    return list(by_path.values())
