#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Discover open loopback services when the operator passes a bare host.

This is intentionally *not* a lab cheat sheet: we probe common ports and may
seed observed ports into the knowledge base. We only rewrite the target when
the default web port is closed (remapped lab) or the operator explicitly asked
for a shell/SSH path. When ``:80`` is open we keep the bare host so the agent
scans it — we do not prefer alternate HTTP ports over ``:80``.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

from core.lab_orchestrator.manifest import (
    LabGroundTruthManifest,
    default_manifests_dir,
    load_ground_truth_manifest,
)


LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

# Common remapped / soft-target ports — used as probe candidates only.
COMMON_SSH_PORTS = (22, 2222, 2223, 2200, 2022)
COMMON_HTTP_PORTS = (80, 8080, 8880, 8000, 8008, 8888, 443, 8443)
DEFAULT_HTTP_PORTS = frozenset({80, 443})


@dataclass
class LabTargetHint:
    """Port-discovery hint. ``lab_id`` is kept for compatibility but left empty for live runs."""

    lab_id: str
    host: str
    target: str
    protocol: str
    goal: str
    open_services: List[str] = field(default_factory=list)
    message: str = ""
    knowledge_base: Dict[str, Any] = field(default_factory=dict)
    rewritten: bool = False


def _is_loopback_host(host: str) -> bool:
    token = str(host or "").strip().lower()
    if token in LOOPBACK_HOSTS:
        return True
    try:
        return bool(ipaddress.ip_address(token).is_loopback)
    except ValueError:
        return False


def _extract_host_port(raw_target: str) -> Tuple[str, Optional[int], bool]:
    """Return (host, explicit_port, has_scheme_or_path)."""
    text = str(raw_target or "").strip()
    if not text:
        return "", None, False
    if "://" in text:
        parsed = urlsplit(text)
        return str(parsed.hostname or "").lower(), parsed.port, True
    if "/" in text or "?" in text or "#" in text:
        authority = text.split("/", 1)[0]
        host, port, _ = _split_host_port(authority)
        return host, port, True
    host, port, _ = _split_host_port(text)
    return host, port, False


def _split_host_port(authority: str) -> Tuple[str, Optional[int], str]:
    value = str(authority or "").strip()
    if value.startswith("[") and "]" in value:
        closing = value.index("]")
        host = value[1:closing]
        rest = value[closing + 1 :]
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
        return host.lower(), port, ""
    try:
        ipaddress.ip_address(value)
        return value.lower(), None, ""
    except ValueError:
        pass
    if value.count(":") == 1:
        host, raw_port = value.rsplit(":", 1)
        if raw_port.isdigit():
            return host.lower(), int(raw_port), ""
    return value.lower(), None, ""


def _port_open(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def _looks_like_ssh(host: str, port: int, timeout: float = 0.6) -> bool:
    """Banner-sniff SSH without relying on lab metadata."""
    if int(port) in COMMON_SSH_PORTS:
        # Still prefer a banner when possible; fall back to port heuristic.
        pass
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(64)
    except Exception:
        return int(port) in COMMON_SSH_PORTS
    text = banner.decode("utf-8", errors="ignore").lower()
    return text.startswith("ssh-") or "openssh" in text


def list_lab_manifests(manifests_dir: Optional[Path] = None) -> List[LabGroundTruthManifest]:
    root = manifests_dir or default_manifests_dir()
    if not root.is_dir():
        return []
    rows: List[LabGroundTruthManifest] = []
    for path in sorted(root.glob("*.json")):
        try:
            rows.append(load_ground_truth_manifest(path))
        except Exception:
            continue
    return rows


def _candidate_ports(manifests_dir: Optional[Path] = None) -> Set[int]:
    ports: Set[int] = set(COMMON_SSH_PORTS) | set(COMMON_HTTP_PORTS)
    for manifest in list_lab_manifests(manifests_dir):
        for service in manifest.services:
            host_port = int(service.host_port or service.port or 0)
            if host_port > 0:
                ports.add(host_port)
    return ports


def _kb_from_open_ports(
    *,
    host: str,
    open_ports: Sequence[int],
    ssh_port: Optional[int],
    http_port: Optional[int],
) -> Dict[str, Any]:
    """Seed only observed ports — never lab id or ground-truth credentials."""
    identified = [f"tcp/{port}" for port in sorted(int(p) for p in open_ports)]
    kb: Dict[str, Any] = {
        "identified_services": identified,
        "discovered_open_ports": sorted(int(p) for p in open_ports),
        # Explicit anti-cheat marker for tests / audits.
        "loopback_discovery_mode": "port_probe",
    }
    if http_port:
        kb["loopback_http_url"] = f"http://{host}:{int(http_port)}/"
    if ssh_port:
        kb["loopback_ssh_endpoint"] = f"{host}:{int(ssh_port)}"
    return kb


def _wants_shell_entry(protocol: Optional[str], goal: Optional[str]) -> bool:
    """True when the operator explicitly asked for a shell / SSH path."""
    proto = str(protocol or "").strip().lower()
    if proto == "ssh":
        return True
    normalized = str(goal or "").strip().lower().replace("_", "-")
    return normalized in {
        "obtain-shell",
        "shell",
        "get-shell",
        "reverse-shell",
    }


def _pick_http_port(open_ports: Sequence[int]) -> Optional[int]:
    """Prefer default web ports; only fall back to remaps when those are closed."""
    for port in open_ports:
        if int(port) in DEFAULT_HTTP_PORTS:
            return int(port)
    for port in open_ports:
        if int(port) in COMMON_HTTP_PORTS:
            return int(port)
    return None


def detect_loopback_lab_hint(
    raw_target: str,
    *,
    protocol: Optional[str] = None,
    goal: Optional[str] = None,
    resolver: Any = None,
    manifests_dir: Optional[Path] = None,
) -> Optional[LabTargetHint]:
    """
    Probe bare loopback for open services.

    Keeps the bare host when ``:80``/``:443`` is reachable so the agent scans
    the host. Rewrites only for explicit shell goals (SSH) or when the default
    web port is closed but a remapped HTTP port is open.

    Does **not** identify a lab or inject ground-truth credentials.
    """
    host, explicit_port, had_url_form = _extract_host_port(raw_target)
    if not host or not _is_loopback_host(host):
        return None
    # Explicit non-default ports / URLs are respected — only bare IP/hostname rewrites.
    if explicit_port is not None or had_url_form:
        return None
    if str(protocol or "").strip().lower() not in {"", "http", "https", "ssh", "tcp"}:
        return None

    prefer_shell = _wants_shell_entry(protocol, goal)
    probe = resolver.is_port_open if resolver is not None and hasattr(resolver, "is_port_open") else _port_open

    open_ports: List[int] = []
    for port in sorted(_candidate_ports(manifests_dir)):
        if probe(host, port):
            open_ports.append(port)

    if not open_ports:
        return None

    ssh_port: Optional[int] = None
    for port in open_ports:
        if _looks_like_ssh(host, port):
            ssh_port = port
            break
    if ssh_port is None:
        for port in open_ports:
            if port in COMMON_SSH_PORTS:
                ssh_port = port
                break

    http_port = _pick_http_port(open_ports)
    open_services = [f"tcp/{p}" for p in open_ports]
    selected_goal = str(goal or "").strip()
    raw = str(raw_target or "").strip() or host

    if prefer_shell and ssh_port:
        target = f"{host}:{ssh_port}"
        proto = "ssh"
        selected_goal = selected_goal or "obtain-shell"
        message = (
            f"Open loopback services detected ({', '.join(open_services)}). "
            f"Rewriting bare `{raw}` → `{target}` (SSH)."
        )
        rewritten = True
    elif http_port is not None and http_port not in DEFAULT_HTTP_PORTS:
        # Default web port closed — remapped lab (e.g. Metasploitable3 on :8880).
        target = f"http://{host}:{http_port}/"
        proto = "http"
        selected_goal = selected_goal or "recon"
        ssh_note = f" SSH also open on :{ssh_port}." if ssh_port else ""
        message = (
            f"Open loopback services detected ({', '.join(open_services)}). "
            f"Rewriting bare `{raw}` → `{target}` "
            f"(default web port closed).{ssh_note}"
        )
        rewritten = True
    else:
        # :80/:443 open (or no HTTP) — keep bare host; agent scans.
        target = raw
        proto = str(protocol or "").strip()
        selected_goal = selected_goal
        ssh_note = f" SSH also open on :{ssh_port}." if ssh_port else ""
        message = (
            f"Open loopback services detected ({', '.join(open_services)}). "
            f"Keeping bare `{raw}` — agent will scan the host.{ssh_note}"
        )
        rewritten = False

    return LabTargetHint(
        lab_id="",
        host=host,
        target=target,
        protocol=proto,
        goal=selected_goal,
        open_services=open_services,
        message=message,
        knowledge_base=_kb_from_open_ports(
            host=host,
            open_ports=open_ports,
            ssh_port=ssh_port,
            http_port=http_port,
        ),
        rewritten=rewritten,
    )
