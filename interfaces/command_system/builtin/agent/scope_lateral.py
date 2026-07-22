#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Scope-bound credential reuse and lateral movement proposals."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Tuple
from urllib.parse import urlparse

from interfaces.command_system.builtin.agent.campaign_world import (
    CampaignWorld,
    campaign_world_from_kb,
    service_id_from,
)
from interfaces.command_system.builtin.agent.redaction import sanitize_nested

SCHEMA_VERSION = "1.0"

LATERAL_PATH_MARKERS = (
    "pivot",
    "lateral",
    "psexec",
    "wmiexec",
    "smb_login",
    "ssh_login",
    "ftp_login",
    "mysql_login",
    "crackmapexec",
    "pass_the_hash",
    "autoroute",
)

TARGET_OPTION_KEYS = (
    "RHOST",
    "RHOSTS",
    "HOST",
    "HOSTNAME",
    "HttpHost",
    "http_host",
    "target",
    "target_host",
)
PORT_OPTION_KEYS = ("RPORT", "PORT", "HttpPort", "http_port", "target_port")

PROTOCOL_MODULE_HINTS: Dict[str, str] = {
    "ssh": "auxiliary/scanner/ssh/ssh_login",
    "ftp": "auxiliary/scanner/ftp/ftp_login",
    "smb": "auxiliary/scanner/smb/smb_login",
    "mysql": "auxiliary/scanner/mysql/mysql_login",
    "http": "auxiliary/scanner/http/login/admin_login_bruteforce",
    "https": "auxiliary/scanner/http/login/admin_login_bruteforce",
}


def _normalize_host(host: str) -> str:
    token = str(host or "").strip().lower().rstrip(".")
    if token in {"localhost", "::1"}:
        return "127.0.0.1"
    return token


def _hosts_match(left: str, right: str) -> bool:
    a = _normalize_host(left)
    b = _normalize_host(right)
    return bool(a and b and a == b)


@dataclass(frozen=True)
class ScopeDestination:
    host: str
    port: int
    protocol: str = ""
    service_id: str = ""
    source: str = "manifest"

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service_id": self.service_id,
            "source": self.source,
        })


@dataclass
class ScopeManifestIndex:
    manifest_id: str = ""
    strict: bool = False
    destinations: List[ScopeDestination] = field(default_factory=list)

    def allows(self, host: str, port: Optional[int] = None, *, protocol: str = "") -> Tuple[bool, str]:
        del protocol
        host_norm = _normalize_host(host)
        if not host_norm:
            return False, "empty_host"
        port_val = int(port) if port is not None and str(port).strip().isdigit() else None
        for dest in self.destinations:
            if not _hosts_match(host_norm, dest.host):
                continue
            if port_val is None or int(dest.port or 0) == port_val:
                return True, "in_scope"
        if self.strict:
            return False, "outside_lab_manifest"
        if self.destinations and port_val is not None:
            return False, "host_port_not_in_scope"
        if self.destinations and any(_hosts_match(host_norm, item.host) for item in self.destinations):
            return True, "host_in_scope"
        return False, "outside_campaign_scope"


@dataclass
class ScopedCredential:
    credential_id: str
    username: str = ""
    password_handle: str = ""
    source_module: str = ""
    source_host: str = ""
    protocol_hint: str = ""
    origin: str = "discovered"

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "credential_id": self.credential_id,
            "username": self.username,
            "password_handle": self.password_handle,
            "source_module": self.source_module,
            "source_host": self.source_host,
            "protocol_hint": self.protocol_hint,
            "origin": self.origin,
        })


@dataclass
class LateralProposal:
    action: str
    target_host: str
    target_port: int
    protocol: str
    service_id: str
    credential_id: str
    module_hint: str
    in_scope: bool = True
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "action": self.action,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "protocol": self.protocol,
            "service_id": self.service_id,
            "credential_id": self.credential_id,
            "module_hint": self.module_hint,
            "in_scope": self.in_scope,
            "reason": self.reason,
        })


def _credential_id(username: str, protocol: str, source: str) -> str:
    digest = hashlib.sha256(f"{username}|{protocol}|{source}".encode("utf-8", errors="replace")).hexdigest()
    return digest[:16]


def build_scope_index(kb: Mapping[str, Any], *, state: Any = None) -> ScopeManifestIndex:
    manifest = kb.get("lab_manifest") if isinstance(kb.get("lab_manifest"), dict) else {}
    manifest_id = str(manifest.get("id") or "")
    destinations: List[ScopeDestination] = []
    seen: set[Tuple[str, int]] = set()

    def _add(host: str, port: Optional[int], *, protocol: str = "", service_id: str = "", source: str = "manifest") -> None:
        host_norm = _normalize_host(host)
        if not host_norm:
            return
        port_val = int(port) if port is not None and str(port).strip().isdigit() else 0
        key = (host_norm, port_val)
        if key in seen:
            return
        seen.add(key)
        destinations.append(ScopeDestination(
            host=host_norm,
            port=port_val,
            protocol=str(protocol or "").lower(),
            service_id=service_id or service_id_from(protocol, port_val if port_val else None),
            source=source,
        ))

    if manifest:
        network = manifest.get("network") if isinstance(manifest.get("network"), dict) else {}
        host_bind = str(network.get("host_bind") or "127.0.0.1").strip()
        session = manifest.get("session") if isinstance(manifest.get("session"), dict) else {}
        session_host = str(session.get("host") or host_bind).strip()
        session_port = session.get("port")
        if session_host:
            _add(
                session_host,
                int(session_port) if session_port is not None and str(session_port).isdigit() else None,
                protocol=str(session.get("protocol") or ""),
                service_id=str(session.get("protocol") or "session"),
                source="manifest_session",
            )
        for row in manifest.get("services") or []:
            if not isinstance(row, dict):
                continue
            service_id = str(row.get("id") or "")
            host_port = row.get("host_port") or row.get("port")
            _add(
                host_bind or session_host or "127.0.0.1",
                int(host_port) if host_port is not None and str(host_port).isdigit() else None,
                protocol=service_id,
                service_id=service_id,
                source="manifest_service",
            )
        for row in manifest.get("expected_paths") or []:
            if not isinstance(row, dict):
                continue
            port = row.get("port")
            url = str(row.get("url") or "")
            if url:
                parsed = urlparse(url)
                if parsed.hostname:
                    _add(parsed.hostname, parsed.port, protocol=str(row.get("family") or ""), source="manifest_path")
            elif port is not None and str(port).isdigit():
                _add(host_bind or session_host or "127.0.0.1", int(port), source="manifest_path")

    if not destinations:
        world = campaign_world_from_kb(kb)
        target_info = getattr(state, "target_info", {}) if state is not None else {}
        if not isinstance(target_info, dict):
            target_info = {}
        for host in world.hosts.values():
            host_name = str(host.hostname or host.ip or "").strip()
            if not host_name:
                continue
            for svc in host.services.values():
                _add(
                    host_name,
                    svc.port,
                    protocol=str(svc.protocol or svc.label or ""),
                    service_id=svc.service_id,
                    source="campaign_world",
                )
        for key in ("host", "hostname", "ip", "target"):
            token = str(target_info.get(key) or "").strip()
            if token:
                port_raw = target_info.get("port") or target_info.get("target_port")
                _add(
                    token,
                    int(port_raw) if port_raw is not None and str(port_raw).isdigit() else None,
                    protocol=str(getattr(state, "protocol", "") if state is not None else ""),
                    source="target_info",
                )
                break

    return ScopeManifestIndex(
        manifest_id=manifest_id,
        strict=bool(manifest),
        destinations=destinations,
    )


def _protocol_from_row(row: Mapping[str, Any]) -> str:
    for key in ("protocol_hint", "protocol", "service", "login_path"):
        token = str(row.get(key) or "").strip().lower()
        if token in PROTOCOL_MODULE_HINTS:
            return token
        if "ssh" in token:
            return "ssh"
        if "ftp" in token:
            return "ftp"
        if "smb" in token:
            return "smb"
        if "mysql" in token:
            return "mysql"
        if token.startswith("/") or "http" in token:
            return "http"
    module = str(row.get("source_module") or "").lower()
    for proto in PROTOCOL_MODULE_HINTS:
        if proto in module:
            return proto
    return ""


def index_credentials(kb: Mapping[str, Any], *, state: Any = None) -> List[ScopedCredential]:
    rows: List[ScopedCredential] = []
    seen: set[str] = set()
    source_host = ""
    target_info = getattr(state, "target_info", {}) if state is not None else {}
    if isinstance(target_info, dict):
        for key in ("host", "hostname", "ip", "target"):
            token = str(target_info.get(key) or "").strip()
            if token:
                source_host = token
                break

    def _append(row: Mapping[str, Any], *, origin: str) -> None:
        username = str(row.get("username") or row.get("authenticated_as") or "").strip()
        password = str(row.get("password") or row.get("authenticated_password") or "").strip()
        if not username and not password:
            return
        protocol = _protocol_from_row(row)
        cid = _credential_id(username or password[:8], protocol, origin)
        if cid in seen:
            return
        seen.add(cid)
        rows.append(ScopedCredential(
            credential_id=cid,
            username=username,
            password_handle=password if password.startswith("vault:") else "",
            source_module=str(row.get("source_module") or "")[:200],
            source_host=str(row.get("source_host") or source_host)[:200],
            protocol_hint=protocol,
            origin=origin,
        ))

    for row in kb.get("credential_store") or []:
        if isinstance(row, dict):
            _append(row, origin="discovered")
    active = kb.get("active_auth_context")
    if isinstance(active, dict):
        _append(active, origin="active")

    # Ground-truth lab_manifest credentials are never indexed here — that would
    # fake live campaigns. Benchmarks inject discovered/vault creds explicitly.

    return rows[:12]


def _service_has_session(world: CampaignWorld, service_id: str) -> bool:
    for row in world.sessions.values():
        if row.service_id == service_id and row.verified:
            return True
    return False


def propose_credential_reuse(
    kb: Mapping[str, Any],
    *,
    state: Any = None,
    scope_index: Optional[ScopeManifestIndex] = None,
    credentials: Optional[Sequence[ScopedCredential]] = None,
) -> List[LateralProposal]:
    index = scope_index or build_scope_index(kb, state=state)
    creds = list(credentials or index_credentials(kb, state=state))
    if not index.destinations or not creds:
        return []

    world = campaign_world_from_kb(kb)
    attempted = {
        str(item)
        for item in (kb.get("scope_lateral") or {}).get("attempted", [])
        if str(item).strip()
    }
    proposals: List[LateralProposal] = []

    for dest in index.destinations:
        if dest.port <= 0:
            continue
        allowed, allow_reason = index.allows(dest.host, dest.port, protocol=dest.protocol)
        if not allowed:
            continue
        service_id = dest.service_id or service_id_from(dest.protocol, dest.port)
        if _service_has_session(world, service_id):
            continue
        for cred in creds:
            protocol = dest.protocol or cred.protocol_hint or "tcp"
            if cred.protocol_hint and dest.protocol and cred.protocol_hint not in {dest.protocol, "tcp"}:
                continue
            proposal_key = f"{cred.credential_id}:{dest.host}:{dest.port}"
            if proposal_key in attempted:
                continue
            action = "credential_reuse" if _hosts_match(cred.source_host, dest.host) else "lateral_movement"
            if action == "lateral_movement" and index.strict:
                if not _hosts_match(cred.source_host, dest.host):
                    continue
            module_hint = PROTOCOL_MODULE_HINTS.get(protocol, PROTOCOL_MODULE_HINTS.get(cred.protocol_hint, ""))
            proposals.append(LateralProposal(
                action=action,
                target_host=dest.host,
                target_port=dest.port,
                protocol=protocol,
                service_id=service_id,
                credential_id=cred.credential_id,
                module_hint=module_hint,
                in_scope=True,
                reason=allow_reason,
            ))
    proposals.sort(key=lambda item: (0 if item.action == "credential_reuse" else 1, item.target_port))
    return proposals[:8]


def sync_scope_lateral(
    kb: MutableMapping[str, Any],
    *,
    state: Any = None,
    structured_details: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    if structured_details and isinstance(structured_details, dict):
        username = str(structured_details.get("authenticated_as") or structured_details.get("username") or "").strip()
        password = str(structured_details.get("password") or structured_details.get("authenticated_password") or "").strip()
        if username or password:
            from interfaces.command_system.builtin.agent.auth_operations import AuthContextOperations

            AuthContextOperations(lambda value: str(value or "").strip()).merge_auth_context(
                kb,
                {
                    "source_module": str(structured_details.get("source_module") or "outcome"),
                    "username": username,
                    "password": password,
                    "login_path": str(structured_details.get("login_path") or ""),
                    "final_path": str(structured_details.get("final_path") or ""),
                },
                state=state,
            )

    index = build_scope_index(kb, state=state)
    credentials = index_credentials(kb, state=state)
    proposals = propose_credential_reuse(kb, state=state, scope_index=index, credentials=credentials)
    snapshot = sanitize_nested({
        "schema_version": SCHEMA_VERSION,
        "manifest_id": index.manifest_id,
        "strict_scope": index.strict,
        "destinations": [item.to_dict() for item in index.destinations[:16]],
        "credentials": [item.to_dict() for item in credentials[:12]],
        "proposals": [item.to_dict() for item in proposals[:8]],
        "credential_reuse_ready": bool(proposals),
        "attempted": list((kb.get("scope_lateral") or {}).get("attempted") or [])[:24],
    })
    kb["scope_lateral"] = snapshot
    if proposals:
        kb["credential_reuse_ready"] = True
    return snapshot


def _module_options(module_instance: Any) -> Dict[str, Any]:
    getter = getattr(module_instance, "get_options", None)
    if callable(getter):
        try:
            payload = getter()
            if isinstance(payload, dict):
                return dict(payload)
        except Exception:
            pass
    options: Dict[str, Any] = {}
    for key in TARGET_OPTION_KEYS + PORT_OPTION_KEYS:
        for attr in (key, key.lower()):
            if hasattr(module_instance, attr):
                try:
                    value = getattr(module_instance, attr)
                except Exception:
                    continue
                if value not in (None, ""):
                    options[key] = value
    return options


def extract_module_destination(module_instance: Any) -> Tuple[str, Optional[int], str]:
    options = _module_options(module_instance)
    host = ""
    for key in TARGET_OPTION_KEYS:
        token = str(options.get(key) or "").strip()
        if token:
            host = token.split(",")[0].strip()
            break
    if "://" in host:
        parsed = urlparse(host)
        host = parsed.hostname or host
        port = parsed.port
        protocol = (parsed.scheme or "").lower()
        return _normalize_host(host), port, protocol
    port: Optional[int] = None
    for key in PORT_OPTION_KEYS:
        raw = options.get(key)
        if raw is not None and str(raw).strip().isdigit():
            port = int(raw)
            break
    return _normalize_host(host), port, ""


def is_lateral_module_path(module_path: str) -> bool:
    low = str(module_path or "").lower()
    return any(marker in low for marker in LATERAL_PATH_MARKERS)


def gate_lateral_execution(
    state: Any,
    module_path: str,
    module_instance: Any,
) -> Optional[str]:
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return None
    index = build_scope_index(kb, state=state)
    if not index.destinations:
        return None
    host, port, _protocol = extract_module_destination(module_instance)
    if not host:
        return None
    allowed, reason = index.allows(host, port)
    if allowed:
        return None
    if index.strict or is_lateral_module_path(module_path):
        metrics = getattr(state, "metrics", None)
        if metrics is not None:
            metrics.scope_blocks = int(getattr(metrics, "scope_blocks", 0)) + 1
        return reason
    return None


def mark_lateral_attempt(kb: MutableMapping[str, Any], proposal: Mapping[str, Any]) -> None:
    store = kb.setdefault("scope_lateral", {})
    if not isinstance(store, dict):
        store = {}
        kb["scope_lateral"] = store
    attempted = list(store.get("attempted") or [])
    key = "|".join([
        str(proposal.get("credential_id") or ""),
        str(proposal.get("target_host") or ""),
        str(proposal.get("target_port") or ""),
    ])
    if key.strip("|") and key not in attempted:
        attempted.append(key)
    store["attempted"] = attempted[-24:]
