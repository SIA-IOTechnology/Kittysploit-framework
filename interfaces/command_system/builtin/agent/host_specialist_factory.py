#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Host/protocol-scoped specialist factory with atomic global budget and scope gates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.campaign_world import campaign_world_from_kb
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.scope_lateral import build_scope_index
from interfaces.command_system.builtin.agent.specialist_registry import (
    MAX_FAN_OUT,
    SpecialistProfile,
    SpecialistRegistry,
)

SCHEMA_VERSION = "1.0"
MAX_HOST_SPECIALISTS = 6
DEFAULT_HOST_BUDGET = 3

PROTOCOL_BASE_SPECIALIST: Dict[str, str] = {
    "ssh": "ssh_service",
    "http": "web_recon",
    "https": "web_recon",
    "ftp": "scanner",
    "smb": "smb_service",
    "mysql": "scanner",
    "winrm": "recon",
}

PROTOCOL_MODULE_FAMILIES: Dict[str, Tuple[str, ...]] = {
    "ssh": ("auxiliary/scanner/ssh", "scanner"),
    "http": ("auxiliary/scanner/http", "scanner"),
    "https": ("auxiliary/scanner/http", "scanner"),
    "ftp": ("auxiliary/scanner/ftp", "scanner"),
    "smb": ("auxiliary/scanner/smb", "scanner"),
    "mysql": ("auxiliary/scanner/mysql", "scanner"),
    "winrm": ("auxiliary/scanner/winrm", "scanner"),
}


@dataclass(frozen=True)
class HostSpecialistInstance:
    specialist_key: str
    host_id: str
    hostname: str
    protocol: str
    service_id: str
    port: int
    base_specialist: str
    in_scope: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "specialist_key": self.specialist_key,
            "host_id": self.host_id,
            "hostname": self.hostname,
            "protocol": self.protocol,
            "service_id": self.service_id,
            "port": self.port,
            "base_specialist": self.base_specialist,
            "in_scope": self.in_scope,
        })


def _ledger(kb: MutableMapping[str, Any]) -> Dict[str, Any]:
    store = kb.setdefault("specialist_lease", {})
    if not isinstance(store, dict):
        store = {}
        kb["specialist_lease"] = store
    store.setdefault("schema_version", SCHEMA_VERSION)
    store.setdefault("reserved_requests", 0)
    store.setdefault("spawned", 0)
    store.setdefault("blocked", [])
    return store


def reserve_specialist_budget(
    state: Any,
    kb: MutableMapping[str, Any],
    cost: int,
) -> Tuple[bool, str]:
    ledger = _ledger(kb)
    reserve = max(1, int(cost or 1))
    budget = int(getattr(state, "request_budget", 0) or 0)
    metrics = getattr(state, "metrics", None)
    network_used = int(getattr(metrics, "network_units_used", 0) or 0) if metrics is not None else 0
    already = int(ledger.get("reserved_requests") or 0)
    if budget > 0 and network_used + already + reserve > budget:
        return False, "global_budget_exhausted"
    ledger["reserved_requests"] = already + reserve
    return True, "reserved"


def gate_host_specialist(
    state: Any,
    profile: SpecialistProfile,
    kb: Mapping[str, Any],
) -> Tuple[bool, str]:
    if not str(profile.key or "").startswith("host/"):
        return True, "not_host_specialist"
    instances = kb.get("host_specialists") if isinstance(kb.get("host_specialists"), dict) else {}
    inst = instances.get(profile.key)
    if not isinstance(inst, dict):
        return False, "unknown_host_specialist"
    if not inst.get("in_scope", True):
        return False, "outside_scope"
    hostname = str(inst.get("hostname") or "")
    port_raw = inst.get("port")
    port = int(port_raw) if port_raw is not None and str(port_raw).strip().isdigit() else None
    index = build_scope_index(kb, state=state)
    allowed, reason = index.allows(hostname, port)
    if not allowed:
        if isinstance(kb, MutableMapping):
            ledger = _ledger(kb)
            events = list(ledger.get("blocked") or [])
            events.append({"specialist": profile.key, "reason": reason})
            ledger["blocked"] = events[-12:]
        return False, reason
    if not isinstance(kb, MutableMapping):
        return False, "kb_not_mutable"
    ok, budget_reason = reserve_specialist_budget(state, kb, profile.budget_requests)
    if not ok:
        return False, budget_reason
    return True, "approved"


def profile_from_instance(instance: Mapping[str, Any]) -> SpecialistProfile:
    protocol = str(instance.get("protocol") or "tcp").lower()
    families = PROTOCOL_MODULE_FAMILIES.get(protocol, ("scanner",))
    hostname = str(instance.get("hostname") or instance.get("host_id") or "target")
    return SpecialistProfile(
        key=str(instance.get("specialist_key") or ""),
        name=f"{protocol.upper()} specialist @ {hostname}",
        description=f"Host/protocol specialist scoped to {instance.get('service_id') or protocol}.",
        capabilities=(protocol, "host_scoped"),
        module_families=families,
        triggers=(
            f"host:{instance.get('host_id')}",
            f"protocol:{protocol}",
            f"service:{instance.get('service_id')}",
        ),
        inputs=("knowledge_base", "catalog_actions", "host_service"),
        outputs=("specialist_proposal",),
        budget_requests=DEFAULT_HOST_BUDGET,
        read_only=True,
        maturity="stable",
    )


def sync_host_specialists(
    kb: MutableMapping[str, Any],
    *,
    state: Any = None,
    registry: Optional[SpecialistRegistry] = None,
) -> Dict[str, Any]:
    registry = registry or SpecialistRegistry()
    world = campaign_world_from_kb(kb)
    index = build_scope_index(kb, state=state)
    store = kb.setdefault("host_specialists", {})
    if not isinstance(store, dict):
        store = {}
        kb["host_specialists"] = store

    for host in world.hosts.values():
        hostname = str(host.hostname or host.ip or host.host_id).strip()
        for svc in host.services.values():
            if len(store) >= MAX_HOST_SPECIALISTS:
                break
            protocol = str(svc.protocol or svc.label or "tcp").lower()
            port = int(svc.port) if svc.port is not None else 0
            specialist_key = f"host/{host.host_id}/{protocol}/{port or svc.service_id}"
            if specialist_key in store:
                continue
            in_scope, _reason = index.allows(hostname, port or None)
            base = PROTOCOL_BASE_SPECIALIST.get(protocol, "scanner")
            if registry.get(base) is None:
                base = "scanner"
            store[specialist_key] = HostSpecialistInstance(
                specialist_key=specialist_key,
                host_id=host.host_id,
                hostname=hostname,
                protocol=protocol,
                service_id=svc.service_id,
                port=port,
                base_specialist=base,
                in_scope=in_scope,
            ).to_dict()

    ledger = _ledger(kb)
    ledger["spawned"] = len(store)
    kb["host_specialist_index"] = sanitize_nested({
        "schema_version": SCHEMA_VERSION,
        "count": len(store),
        "keys": sorted(store.keys())[:MAX_HOST_SPECIALISTS],
    })
    return store


def host_specialist_profiles(
    kb: Mapping[str, Any],
    *,
    state: Any = None,
    limit: int = MAX_FAN_OUT,
) -> List[SpecialistProfile]:
    if isinstance(kb, MutableMapping):
        sync_host_specialists(kb, state=state)
    store = kb.get("host_specialists") if isinstance(kb.get("host_specialists"), dict) else {}
    profiles: List[SpecialistProfile] = []
    for row in store.values():
        if not isinstance(row, dict):
            continue
        if not row.get("in_scope", True):
            continue
        profiles.append(profile_from_instance(row))
        if len(profiles) >= max(1, int(limit or MAX_FAN_OUT)):
            break
    return profiles


def collect_specialists_for_phase(
    registry: SpecialistRegistry,
    state: Any,
    observation: Mapping[str, Any],
    *,
    limit: int = MAX_FAN_OUT,
) -> List[SpecialistProfile]:
    kb = observation.get("knowledge_base") if isinstance(observation.get("knowledge_base"), dict) else {}
    if not isinstance(kb, dict):
        kb = {}
    phase = str(getattr(state, "current_phase", "") or observation.get("phase") or "reason")
    builtin = registry.match(phase=phase, kb=kb, limit=limit)
    if not isinstance(getattr(state, "knowledge_base", None), dict):
        state.knowledge_base = kb  # type: ignore[union-attr]
    elif isinstance(state.knowledge_base, dict):
        kb = state.knowledge_base
    remaining = max(0, int(limit or MAX_FAN_OUT) - len(builtin))
    host_rows = host_specialist_profiles(kb, state=state, limit=remaining) if remaining else []
    merged: List[SpecialistProfile] = []
    seen: set[str] = set()
    for row in builtin + host_rows:
        if row.key in seen:
            continue
        seen.add(row.key)
        merged.append(row)
    return merged[: max(1, int(limit or MAX_FAN_OUT))]


def path_matches_host_specialist(profile: SpecialistProfile, path: str) -> bool:
    if not str(profile.key or "").startswith("host/"):
        return False
    low = str(path or "").lower()
    parts = str(profile.key).split("/")
    protocol = parts[2].lower() if len(parts) > 2 else ""
    if protocol and protocol in low:
        return True
    for family in profile.module_families:
        token = str(family or "").lower()
        if token and token in low:
            return True
    return False
