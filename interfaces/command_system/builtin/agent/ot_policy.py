#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Agent policy helpers for OT/ICS modules — safe assessment guardrails."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from lib.protocols.ics.ot_intel import ICS_SERVICE_PORTS, build_ot_asset_record, merge_ot_asset_into_map


OT_DESTRUCTIVE_PATH_MARKERS: tuple[str, ...] = (
    "/dos/ics/",
    "stop_cpu",
    "plc_control",
    "quantum_plc",
    "schneider",
    "profinet_dcp_set_ip",
    "rpc_integer_overflow",
    "modbus_write",
    "write_register",
    "dnp3_write_enabled",
    "qconn_rce",
)

OT_RECON_PATH_MARKERS: tuple[str, ...] = (
    "auxiliary/scanner/ics/",
    "scanner/ics/",
    "analysis/reporting/ics",
    "post/ics/gather/",
)

OT_TECH_HINTS: tuple[str, ...] = (
    "modbus",
    "s7comm",
    "siemens",
    "bacnet",
    "iec104",
    "enip",
    "dnp3",
    "opcua",
    "scada",
    "plc",
    "ics",
    "ot",
    "profinet",
    "schneider",
    "vxworks",
    "qnx",
)


def is_ot_module_path(path: str) -> bool:
    lowered = str(path or "").lower()
    return "/ics/" in lowered or any(token in lowered for token in OT_TECH_HINTS)


def is_ot_destructive_module(path: str) -> bool:
    lowered = str(path or "").lower()
    if not is_ot_module_path(lowered):
        return False
    return any(marker in lowered for marker in OT_DESTRUCTIVE_PATH_MARKERS)


def is_ot_recon_module(path: str) -> bool:
    lowered = str(path or "").lower()
    return any(marker in lowered for marker in OT_RECON_PATH_MARKERS)


def ot_context_established(knowledge_base: Dict[str, Any] | None) -> bool:
    kb = knowledge_base if isinstance(knowledge_base, dict) else {}
    if bool(kb.get("ot_context_established")):
        return True
    assets = kb.get("ot_assets") or {}
    return isinstance(assets, dict) and len(assets) > 0


def ot_module_block_reason(
    *,
    module_path: str,
    safety_profile: str,
    knowledge_base: Dict[str, Any] | None,
    risk_approved: bool = False,
) -> str:
    path = str(module_path or "")
    if not is_ot_destructive_module(path):
        return ""

    profile = str(safety_profile or "normal").strip().lower()
    if profile in {"safe", "discreet"}:
        return "OT destructive module blocked in safe/discreet profile — use internal-lab + explicit approval"

    if risk_approved:
        return ""

    if not ot_context_established(knowledge_base):
        return (
            "OT destructive module requires prior recon "
            "(run workflow ot-safe-assessment or auxiliary/scanner/ics/* first)"
        )
    return ""


def merge_ot_context_from_results(
    knowledge_base: Dict[str, Any],
    results: Iterable[Any] | None,
    module_paths: Iterable[str] | None = None,
) -> None:
    if not isinstance(knowledge_base, dict):
        return

    assets: Dict[str, Any] = dict(knowledge_base.get("ot_assets") or {})
    tech_hints = set(knowledge_base.get("tech_hints") or [])
    risk_signals = set(knowledge_base.get("risk_signals") or [])
    purdue_levels: List[int] = []

    for path in module_paths or []:
        if is_ot_recon_module(str(path)):
            knowledge_base["ot_recon_modules_run"] = sorted(
                set(knowledge_base.get("ot_recon_modules_run") or []) | {str(path)}
            )

    for result in results or []:
        if not isinstance(result, dict):
            continue
        path = str(result.get("path") or result.get("module") or "")
        if not is_ot_module_path(path):
            continue

        tech_hints.update(OT_TECH_HINTS)
        message = str(result.get("message") or "")
        details = result.get("details") if isinstance(result.get("details"), dict) else {}
        host = str(details.get("target") or details.get("host") or knowledge_base.get("target") or "").strip()

        if result.get("vulnerable") or result.get("status") in {"success", "completed", "ok"}:
            knowledge_base["ot_context_established"] = True

        if "protection" in path or "unprotected" in message.lower():
            risk_signals.add("s7_unprotected")
        if "write_enabled" in path or "write" in message.lower():
            risk_signals.add("modbus_write_exposed")
        if "default credential" in message.lower() or "valid credentials" in message.lower():
            risk_signals.add("ot_default_credentials")

        port = details.get("port")
        protocol = str(details.get("protocol") or "")
        if not protocol and port:
            try:
                protocol = ICS_SERVICE_PORTS.get(int(port), "")
            except (TypeError, ValueError):
                protocol = ""

        if "passive_sniffer" in path:
            protos = details.get("protocols") or []
            if isinstance(protos, list) and protos:
                knowledge_base["ot_passive_protocols"] = ",".join(str(p) for p in protos[:16])
            knowledge_base["ot_passive_report"] = str(details.get("report_path") or "")

        if host:
            record = build_ot_asset_record(
                host,
                port=int(port) if port else None,
                protocol=protocol,
                vendor=str(details.get("vendor") or ""),
                mac=str(details.get("mac") or ""),
                modbus_units=details.get("modbus_units") or details.get("unit_ids"),
                s7_slot=details.get("slot") or details.get("s7_slot"),
                protection_level=details.get("protection_level"),
                device_type=str(details.get("device_type") or ""),
            )
            merge_ot_asset_into_map(assets, record)
            level = int(record.get("purdue_level") or 0)
            if level:
                purdue_levels.append(level)

    if assets:
        knowledge_base["ot_assets"] = assets
        knowledge_base["ot_context_established"] = True

    if purdue_levels:
        knowledge_base["ot_purdue_levels"] = sorted(set(purdue_levels))
        knowledge_base["ot_primary_purdue_level"] = min(purdue_levels)

    if tech_hints:
        knowledge_base["tech_hints"] = sorted(set(knowledge_base.get("tech_hints") or []) | tech_hints)
    if risk_signals:
        knowledge_base["risk_signals"] = sorted(set(knowledge_base.get("risk_signals") or []) | risk_signals)


OT_PROTOCOL_HANDOFF: Dict[str, str] = {
    "modbus": "auxiliary/scanner/ics/modbus_identify",
    "modbus tcp": "auxiliary/scanner/ics/modbus_identify",
    "s7comm": "auxiliary/scanner/ics/s7comm_identify",
    "s7": "auxiliary/scanner/ics/s7comm_identify",
    "dnp3": "auxiliary/scanner/ics/dnp3_identify",
    "bacnet": "auxiliary/scanner/ics/bacnet_whois",
    "iec104": "auxiliary/scanner/ics/iec104_interrogate",
    "enip": "auxiliary/scanner/ics/enip_list_identity",
    "profinet": "auxiliary/scanner/ics/profinet_dcp",
}


def suggest_ot_active_handoff(knowledge_base: Dict[str, Any] | None) -> List[str]:
    """
    Map passive OT recon (protocols/assets) to active identify modules.
    """
    kb = knowledge_base if isinstance(knowledge_base, dict) else {}
    suggested: List[str] = []
    assets = kb.get("ot_assets") if isinstance(kb.get("ot_assets"), dict) else {}
    protocols: set[str] = set()

    for _host, record in assets.items():
        if not isinstance(record, dict):
            continue
        proto = str(record.get("protocol") or "").strip().lower()
        if proto:
            protocols.add(proto)
        for p in record.get("protocols") or []:
            protocols.add(str(p).strip().lower())

    details_proto = str(kb.get("ot_passive_protocols") or "")
    for token in details_proto.split(","):
        if token.strip():
            protocols.add(token.strip().lower())

    for proto in sorted(protocols):
        for key, module in OT_PROTOCOL_HANDOFF.items():
            if key in proto and module not in suggested:
                suggested.append(module)

    if kb.get("ot_context_established") and not suggested:
        suggested.extend([
            "auxiliary/scanner/ics/modbus_identify",
            "auxiliary/scanner/ics/s7comm_identify",
        ])
    return suggested[:8]
