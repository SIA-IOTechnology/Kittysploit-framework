#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Campaign world graph: Host → Service as the authoritative multi-surface model."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.action_catalog import CAPABILITY_LADDER, current_capability_rung
from interfaces.command_system.builtin.agent.redaction import sanitize_nested

SCHEMA_VERSION = "1.0"
SERVICE_TOKEN_RE = re.compile(r"^(?P<label>[a-z0-9._-]+)(?::(?P<port>\d+))?$", re.I)


@dataclass
class CampaignService:
    service_id: str
    protocol: str = ""
    port: Optional[int] = None
    label: str = ""
    capability_rung: str = ""
    initial_target: bool = False
    verified: bool = False
    tech_hints: List[str] = field(default_factory=list)
    risk_signals: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "service_id": self.service_id,
            "protocol": self.protocol,
            "port": self.port,
            "label": self.label,
            "capability_rung": self.capability_rung,
            "initial_target": self.initial_target,
            "verified": self.verified,
            "tech_hints": self.tech_hints[:8],
            "risk_signals": self.risk_signals[:8],
        })

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CampaignService":
        port = data.get("port")
        return cls(
            service_id=str(data.get("service_id") or ""),
            protocol=str(data.get("protocol") or ""),
            port=int(port) if port is not None and str(port).strip().isdigit() else None,
            label=str(data.get("label") or ""),
            capability_rung=str(data.get("capability_rung") or ""),
            initial_target=bool(data.get("initial_target", False)),
            verified=bool(data.get("verified", False)),
            tech_hints=[str(item) for item in (data.get("tech_hints") or [])[:8]],
            risk_signals=[str(item) for item in (data.get("risk_signals") or [])[:8]],
        )


@dataclass
class CampaignHost:
    host_id: str
    hostname: str = ""
    ip: str = ""
    initial_target: bool = False
    services: Dict[str, CampaignService] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "host_id": self.host_id,
            "hostname": self.hostname,
            "ip": self.ip,
            "initial_target": self.initial_target,
            "services": {sid: svc.to_dict() for sid, svc in sorted(self.services.items())},
        })

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CampaignHost":
        services: Dict[str, CampaignService] = {}
        raw = data.get("services") if isinstance(data.get("services"), dict) else {}
        for sid, row in raw.items():
            if isinstance(row, dict):
                services[str(sid)] = CampaignService.from_dict(row)
        return cls(
            host_id=str(data.get("host_id") or ""),
            hostname=str(data.get("hostname") or ""),
            ip=str(data.get("ip") or ""),
            initial_target=bool(data.get("initial_target", False)),
            services=services,
        )


@dataclass
class CampaignSession:
    session_id: str
    host_id: str = ""
    service_id: str = ""
    session_type: str = ""
    verified: bool = False
    status: str = "registered"
    capability_rung: str = "session"

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "session_id": self.session_id,
            "host_id": self.host_id,
            "service_id": self.service_id,
            "session_type": self.session_type,
            "verified": self.verified,
            "status": self.status,
            "capability_rung": self.capability_rung,
        })

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CampaignSession":
        return cls(
            session_id=str(data.get("session_id") or ""),
            host_id=str(data.get("host_id") or ""),
            service_id=str(data.get("service_id") or ""),
            session_type=str(data.get("session_type") or ""),
            verified=bool(data.get("verified", False)),
            status=str(data.get("status") or "registered"),
            capability_rung=str(data.get("capability_rung") or "session"),
        )


@dataclass
class CampaignWorld:
    schema_version: str = SCHEMA_VERSION
    hosts: Dict[str, CampaignHost] = field(default_factory=dict)
    sessions: Dict[str, CampaignSession] = field(default_factory=dict)
    active_host_id: str = ""
    active_service_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "schema_version": self.schema_version,
            "hosts": {hid: host.to_dict() for hid, host in sorted(self.hosts.items())},
            "sessions": {sid: row.to_dict() for sid, row in sorted(self.sessions.items())},
            "active_host_id": self.active_host_id,
            "active_service_id": self.active_service_id,
        })

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CampaignWorld":
        hosts: Dict[str, CampaignHost] = {}
        raw = data.get("hosts") if isinstance(data.get("hosts"), dict) else {}
        for hid, row in raw.items():
            if isinstance(row, dict):
                hosts[str(hid)] = CampaignHost.from_dict(row)
        sessions: Dict[str, CampaignSession] = {}
        raw_sessions = data.get("sessions") if isinstance(data.get("sessions"), dict) else {}
        for sid, row in raw_sessions.items():
            if isinstance(row, dict):
                sessions[str(sid)] = CampaignSession.from_dict(row)
        return cls(
            schema_version=str(data.get("schema_version") or SCHEMA_VERSION),
            hosts=hosts,
            sessions=sessions,
            active_host_id=str(data.get("active_host_id") or ""),
            active_service_id=str(data.get("active_service_id") or ""),
        )


def _host_id(hostname: str) -> str:
    token = str(hostname or "").strip().lower()[:120]
    return f"host:{token or 'target'}"


def service_id_from(protocol: str, port: Optional[int] = None, *, label: str = "") -> str:
    proto = str(protocol or label or "unknown").strip().lower()
    if port is not None:
        return f"{proto}/{int(port)}"
    return proto


def parse_service_token(token: str) -> Tuple[str, Optional[int], str]:
    text = str(token or "").strip()
    if not text:
        return "", None, ""
    if "/" in text:
        left, right = text.split("/", 1)
        if right.isdigit():
            return left.lower(), int(right), left.lower()
    match = SERVICE_TOKEN_RE.match(text.replace("/", ":"))
    if match:
        label = str(match.group("label") or "").lower()
        port_raw = match.group("port")
        port = int(port_raw) if port_raw else None
        return label, port, label
    return text.lower(), None, text.lower()


def campaign_world_from_kb(kb: Mapping[str, Any]) -> CampaignWorld:
    raw = kb.get("campaign_world") if isinstance(kb.get("campaign_world"), dict) else {}
    if not raw:
        return CampaignWorld()
    return CampaignWorld.from_dict(raw)


def _resolve_hostname(state: Any, kb: Mapping[str, Any], hostname: str = "") -> str:
    if hostname:
        return str(hostname).strip()
    target_info = getattr(state, "target_info", {}) if state is not None else {}
    if isinstance(target_info, dict):
        for key in ("host", "hostname", "ip", "target"):
            token = str(target_info.get(key) or "").strip()
            if token:
                return token[:200]
    token = str(getattr(state, "raw_target", "") if state is not None else "").strip()
    if token:
        return token[:200]
    return str(kb.get("target_hostname") or kb.get("target_host") or "target").strip()[:200]


def _resolve_initial_port(state: Any, target_info: Mapping[str, Any], protocol: str) -> Optional[int]:
    for source in (target_info, getattr(state, "target_info", {}) if state is not None else {}):
        if not isinstance(source, dict):
            continue
        for key in ("port", "target_port"):
            raw = source.get(key)
            if raw is not None and str(raw).strip().isdigit():
                return int(raw)
    raw_target = str(getattr(state, "raw_target", "") if state is not None else "")
    if "://" in raw_target and ":" in raw_target.split("://", 1)[-1]:
        try:
            from urllib.parse import urlparse

            parsed = urlparse(raw_target)
            if parsed.port:
                return int(parsed.port)
        except Exception:
            pass
    defaults = {"http": 80, "https": 443, "ssh": 22, "smb": 445, "ftp": 21}
    if protocol in defaults:
        return defaults[protocol]
    return None


def _merge_service(
    host: CampaignHost,
    *,
    protocol: str,
    port: Optional[int],
    label: str = "",
    capability_rung: str = "",
    initial_target: bool = False,
    tech_hints: Optional[Sequence[str]] = None,
    risk_signals: Optional[Sequence[str]] = None,
) -> Tuple[CampaignService, bool]:
    sid = service_id_from(protocol, port, label=label)
    created = sid not in host.services
    existing = host.services.get(sid)
    svc = existing or CampaignService(service_id=sid)
    svc.protocol = protocol or svc.protocol or label
    svc.port = port if port is not None else svc.port
    svc.label = label or svc.label or protocol
    if capability_rung:
        svc.capability_rung = capability_rung
    if initial_target:
        svc.initial_target = True
    if tech_hints:
        merged = sorted(set(svc.tech_hints) | {str(item) for item in tech_hints if str(item).strip()})
        svc.tech_hints = merged[:8]
    if risk_signals:
        merged = sorted(set(svc.risk_signals) | {str(item) for item in risk_signals if str(item).strip()})
        svc.risk_signals = merged[:8]
    host.services[sid] = svc
    return svc, created


def _ingest_fingerprint(
    host: CampaignHost,
    row: Mapping[str, Any],
    *,
    default_rung: str,
    initial_protocol: str = "",
    initial_port: Optional[int] = None,
) -> int:
    if not isinstance(row, dict):
        return 0
    protocol = str(row.get("protocol") or row.get("service") or row.get("name") or "").strip().lower()
    port_raw = row.get("port")
    port = int(port_raw) if port_raw is not None and str(port_raw).strip().isdigit() else None
    label = str(row.get("service") or row.get("name") or protocol or "").strip().lower()
    if not protocol and not label:
        return 0
    initial_target = bool(
        initial_protocol
        and protocol == initial_protocol
        and (initial_port is None or port is None or port == initial_port)
    )
    _, created = _merge_service(
        host,
        protocol=protocol or label,
        port=port,
        label=label or protocol,
        capability_rung=default_rung,
        initial_target=initial_target,
    )
    return 1 if created else 0


def _ingest_service_token(host: CampaignHost, token: str, *, default_rung: str, initial_protocol: str = "") -> int:
    protocol, port, label = parse_service_token(token)
    if not protocol:
        return 0
    initial_target = bool(initial_protocol and protocol == initial_protocol)
    _, created = _merge_service(
        host,
        protocol=protocol,
        port=port,
        label=label,
        capability_rung=default_rung,
        initial_target=initial_target,
    )
    return 1 if created else 0


def _ingest_results(host: CampaignHost, results: Sequence[Mapping[str, Any]], *, default_rung: str) -> int:
    delta = 0
    for row in results:
        if not isinstance(row, dict):
            continue
        for key in ("open_ports", "ports", "services"):
            values = row.get(key)
            if not isinstance(values, list):
                continue
            for item in values:
                if isinstance(item, dict):
                    delta += _ingest_fingerprint(host, item, default_rung=default_rung)
                elif isinstance(item, (int, str)) and str(item).strip().isdigit():
                    _, created = _merge_service(
                        host,
                        protocol="tcp",
                        port=int(item),
                        label="tcp",
                        capability_rung=default_rung,
                    )
                    if created:
                        delta += 1
                elif isinstance(item, str):
                    delta += _ingest_service_token(host, item, default_rung=default_rung)
    return delta


def build_campaign_world_from_sources(
    kb: Mapping[str, Any],
    *,
    state: Any = None,
    hostname: str = "",
    host_profile: Optional[Mapping[str, Any]] = None,
    protocol: str = "",
    results: Optional[Sequence[Mapping[str, Any]]] = None,
) -> CampaignWorld:
    world = campaign_world_from_kb(kb)
    host_name = _resolve_hostname(state, kb, hostname)
    hid = _host_id(host_name)
    host = world.hosts.get(hid) or CampaignHost(host_id=hid, hostname=host_name, initial_target=True)
    if hid not in world.hosts:
        world.hosts[hid] = host

    target_info = getattr(state, "target_info", {}) if state is not None else {}
    if not isinstance(target_info, dict):
        target_info = {}
    initial_protocol = str(
        protocol
        or (getattr(state, "protocol", "") if state is not None else "")
        or kb.get("protocol")
        or ""
    ).strip().lower()
    initial_port = _resolve_initial_port(state, target_info, initial_protocol)
    default_rung = current_capability_rung(kb if isinstance(kb, dict) else {})

    if initial_protocol:
        _merge_service(
            host,
            protocol=initial_protocol,
            port=initial_port,
            label=initial_protocol,
            capability_rung=default_rung,
            initial_target=True,
            tech_hints=kb.get("tech_hints") if isinstance(kb.get("tech_hints"), list) else None,
            risk_signals=kb.get("risk_signals") if isinstance(kb.get("risk_signals"), list) else None,
        )

    profile = host_profile if isinstance(host_profile, dict) else {}
    if not profile and state is not None:
        profile = getattr(state, "host_profile", {}) or {}
    if isinstance(profile, dict):
        for row in profile.get("service_fingerprints") or []:
            _ingest_fingerprint(
                host,
                row if isinstance(row, dict) else {},
                default_rung=default_rung,
                initial_protocol=initial_protocol,
                initial_port=initial_port,
            )

    for token in kb.get("identified_services") or []:
        _ingest_service_token(host, str(token), default_rung=default_rung, initial_protocol=initial_protocol)
    for token in kb.get("services") or []:
        _ingest_service_token(host, str(token), default_rung=default_rung, initial_protocol=initial_protocol)

    if results:
        _ingest_results(host, results, default_rung=default_rung)

    if not world.active_host_id:
        world.active_host_id = hid
    return world


def select_focus_service(
    world: CampaignWorld,
    *,
    active_service_id: str = "",
    active_host_id: str = "",
) -> Tuple[str, str]:
    """Return (host_id, service_id) for the next planner focus."""
    host_id = str(active_host_id or world.active_host_id or "").strip()
    service_id = str(active_service_id or world.active_service_id or "").strip()
    if host_id and service_id:
        host = world.hosts.get(host_id)
        if host is not None and service_id in host.services:
            return host_id, service_id

    candidates: List[Tuple[int, str, str, CampaignService]] = []
    for hid, host in world.hosts.items():
        for sid, svc in host.services.items():
            rank = 0
            if svc.initial_target:
                rank -= 100
            if svc.capability_rung:
                try:
                    rank += CAPABILITY_LADDER.index(svc.capability_rung)
                except ValueError:
                    rank += 1
            else:
                rank += 2
            candidates.append((rank, hid, sid, svc))

    if not candidates:
        return host_id, service_id

    candidates.sort(key=lambda item: (item[0], item[2]))
    _, hid, sid, _svc = candidates[0]
    return hid, sid


def sync_campaign_world(
    kb: MutableMapping[str, Any],
    *,
    state: Any = None,
    hostname: str = "",
    host_profile: Optional[Mapping[str, Any]] = None,
    protocol: str = "",
    results: Optional[Sequence[Mapping[str, Any]]] = None,
) -> int:
    """Merge host/service intelligence into ``kb['campaign_world']`` without dropping prior surfaces."""
    if not isinstance(kb, MutableMapping):
        return 0

    prev = campaign_world_from_kb(kb)
    prev_services = sum(len(host.services) for host in prev.hosts.values())

    world = build_campaign_world_from_sources(
        kb,
        state=state,
        hostname=hostname,
        host_profile=host_profile,
        protocol=protocol,
        results=results,
    )

    active_service_id = str(getattr(state, "active_service_id", "") if state is not None else "")
    active_host_id = str(getattr(state, "active_host_id", "") if state is not None else "")
    focus_host, focus_service = select_focus_service(
        world,
        active_service_id=active_service_id,
        active_host_id=active_host_id,
    )
    world.active_host_id = focus_host
    world.active_service_id = focus_service

    new_services = sum(len(host.services) for host in world.hosts.values())
    delta = max(0, new_services - prev_services)

    kb["campaign_world"] = world.to_dict()
    kb["campaign_world_stats"] = sanitize_nested({
        "hosts": len(world.hosts),
        "services": new_services,
        "sessions": len(world.sessions),
        "delta": delta,
        "active_host_id": world.active_host_id,
        "active_service_id": world.active_service_id,
    })
    return delta


def attach_session_to_world(
    kb: MutableMapping[str, Any],
    records: Sequence[Any],
    *,
    state: Any = None,
) -> None:
    """Merge broker session records into ``kb['campaign_world'].sessions``."""
    if not isinstance(kb, MutableMapping):
        return
    world = campaign_world_from_kb(kb)
    if not world.hosts:
        sync_campaign_world(kb, state=state)

    world = campaign_world_from_kb(kb)
    default_host_id = str(world.active_host_id or "")
    default_service_id = str(world.active_service_id or "")

    for record in records:
        session_id = str(getattr(record, "session_id", "") or (record.get("session_id") if isinstance(record, dict) else "") or "")
        if not session_id:
            continue
        host_id = str(getattr(record, "host_id", "") or (record.get("host_id") if isinstance(record, dict) else "") or default_host_id)
        service_id = str(getattr(record, "service_id", "") or (record.get("service_id") if isinstance(record, dict) else "") or default_service_id)
        session_type = str(getattr(record, "session_type", "") or (record.get("session_type") if isinstance(record, dict) else "") or "")
        verified = bool(getattr(record, "verified", False) if not isinstance(record, dict) else record.get("verified", False))
        status = str(getattr(record, "status", "") or (record.get("status") if isinstance(record, dict) else "") or "registered")
        world.sessions[session_id] = CampaignSession(
            session_id=session_id,
            host_id=host_id,
            service_id=service_id,
            session_type=session_type,
            verified=verified,
            status=status,
        )
        if verified and host_id and host_id in world.hosts and service_id:
            host = world.hosts[host_id]
            svc = host.services.get(service_id)
            if svc is not None:
                svc.capability_rung = "session"
                svc.verified = True

    kb["campaign_world"] = world.to_dict()
    stats = kb.get("campaign_world_stats") if isinstance(kb.get("campaign_world_stats"), dict) else {}
    stats["sessions"] = len(world.sessions)
    kb["campaign_world_stats"] = stats


def get_service_context_slice(
    world: CampaignWorld,
    *,
    host_id: str = "",
    service_id: str = "",
) -> Optional[CampaignService]:
    hid = str(host_id or world.active_host_id or "").strip()
    sid = str(service_id or world.active_service_id or "").strip()
    host = world.hosts.get(hid)
    if host is None:
        return None
    return host.services.get(sid)


def list_host_services(world: CampaignWorld, host_id: str = "") -> List[str]:
    hid = str(host_id or world.active_host_id or "").strip()
    host = world.hosts.get(hid)
    if host is None:
        return []
    labels: List[str] = []
    for svc in host.services.values():
        if svc.port is not None:
            labels.append(f"{svc.label or svc.protocol}:{svc.port}")
        else:
            labels.append(svc.label or svc.protocol or svc.service_id)
    return labels[:12]
