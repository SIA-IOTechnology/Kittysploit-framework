# -*- coding: utf-8 -*-
"""Parse masscan JSON (from -oJ - or a saved file) into structured host/service dicts."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple


def parse_masscan_json(text: str) -> Dict[str, Any]:
    """Return ``{"hosts": [...], "scanner": "masscan"}`` from masscan ``-oJ`` output."""
    hosts_map: Dict[str, Dict[str, Any]] = {}

    for obj in _iter_json_objects(text or ""):
        address = str(obj.get("ip") or obj.get("ipv4") or "").strip()
        if not address:
            continue
        host = hosts_map.setdefault(
            address,
            {
                "address": address,
                "hostname": None,
                "mac": None,
                "os": None,
                "status": "up",
                "services": [],
            },
        )
        for port_info in obj.get("ports") or []:
            try:
                port = int(port_info.get("port") or 0)
            except (TypeError, ValueError):
                continue
            if port < 1 or port > 65535:
                continue
            protocol = str(port_info.get("proto") or port_info.get("protocol") or "tcp").lower()
            if protocol not in ("tcp", "udp"):
                continue
            state = str(port_info.get("status") or port_info.get("state") or "open").lower()
            if state not in ("open", "closed", "filtered", "unknown"):
                state = "open" if "open" in state else "filtered"
            # Deduplicate port/proto
            existing = {
                (s.get("port"), s.get("protocol")) for s in host["services"]
            }
            if (port, protocol) in existing:
                continue
            host["services"].append(
                {
                    "port": port,
                    "protocol": protocol,
                    "state": state,
                    "name": None,
                    "version": None,
                    "banner": None,
                }
            )

    hosts = sorted(hosts_map.values(), key=lambda h: _sort_ip(h.get("address") or ""))
    return {"hosts": hosts, "scanner": "masscan"}


def to_port_scan_results(report: Dict[str, Any]) -> Dict[str, Dict[int, str]]:
    """Convert a parsed report to ``{host: {port: state}}`` for ``record_port_scan``."""
    results: Dict[str, Dict[int, str]] = {}
    for host in report.get("hosts") or []:
        address = host.get("address")
        if not address:
            continue
        for svc in host.get("services") or []:
            if (svc.get("state") or "") != "open":
                continue
            if (svc.get("protocol") or "tcp").lower() != "tcp":
                continue
            try:
                port = int(svc.get("port") or 0)
            except (TypeError, ValueError):
                continue
            if port:
                results.setdefault(address, {})[port] = "open"
    return results


def _iter_json_objects(text: str) -> List[Dict[str, Any]]:
    """Yield masscan JSON objects from array, NDJSON, or mixed comment output."""
    raw = (text or "").strip()
    if not raw:
        return []

    # Drop comment lines (#masscan …)
    lines = [ln for ln in raw.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    cleaned = "\n".join(lines).strip()
    if not cleaned:
        return []

    # Full JSON array / object
    try:
        data = json.loads(cleaned)
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    # Progressive / messy output: scan with raw_decode
    objs: List[Dict[str, Any]] = []
    decoder = json.JSONDecoder()
    idx = 0
    n = len(cleaned)
    while idx < n:
        while idx < n and cleaned[idx] not in "{[":
            idx += 1
        if idx >= n:
            break
        try:
            data, end = decoder.raw_decode(cleaned, idx)
        except json.JSONDecodeError:
            idx += 1
            continue
        idx = end
        if isinstance(data, dict) and ("ip" in data or "ports" in data):
            objs.append(data)
        elif isinstance(data, list):
            objs.extend(x for x in data if isinstance(x, dict))
    return objs


def _sort_ip(value: str) -> Tuple:
    try:
        parts = [int(p) for p in value.split(".")]
        while len(parts) < 4:
            parts.append(0)
        return tuple(parts[:4])
    except Exception:
        return (999, 999, 999, 999)
