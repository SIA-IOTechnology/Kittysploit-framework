#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Resolve a routable callback/listener lhost for reverse payloads."""

from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
from typing import Any, Iterable, Optional


def is_loopback_or_unspecified_host(value: str) -> bool:
    raw = str(value or "").strip().lower()
    if not raw:
        return True
    if raw in {"localhost", "::1", "0.0.0.0", "::"}:
        return True
    return raw.startswith("127.")


def _is_usable_lan_ip(value: str) -> bool:
    ip = str(value or "").strip()
    if not ip or is_loopback_or_unspecified_host(ip):
        return False
    if ip.startswith("169.254."):
        return False
    return True


def is_docker_bridge_host(value: str) -> bool:
    """True for typical Docker/compose bridge addresses (RFC1918 docker ranges)."""
    raw = str(value or "").strip()
    if not raw:
        return False
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return False
    if not isinstance(addr, ipaddress.IPv4Address):
        return False
    # Default docker0 is 172.17.0.0/16; compose often uses 172.18-31.x
    return addr in ipaddress.ip_network("172.16.0.0/12")


def discover_primary_lan_ip() -> str:
    """Best-effort primary routable IPv4 on the local machine (e.g. 192.168.x.x)."""
    for probe_host, probe_port in (("8.8.8.8", 53), ("1.1.1.1", 53)):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect((probe_host, int(probe_port)))
            ip = str(sock.getsockname()[0] or "").strip()
            sock.close()
        except Exception:
            ip = ""
        if _is_usable_lan_ip(ip):
            return ip

    try:
        result = subprocess.run(
            ["hostname", "-I"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if result.returncode == 0:
            for ip in result.stdout.strip().split():
                if _is_usable_lan_ip(ip):
                    return ip
    except Exception:
        pass

    try:
        hostname = socket.gethostname()
        _, _, addresses = socket.gethostbyname_ex(hostname)
        for ip in addresses:
            if _is_usable_lan_ip(ip):
                return ip
    except Exception:
        pass

    return ""


def _docker_client():
    try:
        import docker  # type: ignore
    except Exception:
        return None
    try:
        return docker.from_env()
    except Exception:
        return None


def resolve_docker_gateway_for_container_ip(target_ip: Any) -> str:
    """Return the bridge gateway for a container that owns ``target_ip``."""
    wanted = str(target_ip or "").strip()
    if not wanted:
        return ""
    client = _docker_client()
    if client is None:
        return ""
    try:
        containers = client.containers.list()
    except Exception:
        return ""

    for container in containers:
        try:
            container.reload()
            networks = container.attrs.get("NetworkSettings", {}).get("Networks", {}) or {}
        except Exception:
            continue
        for _network_name, network in networks.items():
            if not isinstance(network, dict):
                continue
            ip = str(network.get("IPAddress") or "").strip()
            if ip != wanted:
                continue
            gateway = str(network.get("Gateway") or "").strip()
            if _is_usable_lan_ip(gateway):
                return gateway
    return ""


def resolve_docker_gateway_for_port(target_port: Any) -> str:
    """When the target is published from Docker, return the bridge gateway IP."""
    try:
        port = int(target_port)
    except Exception:
        return ""

    client = _docker_client()
    if client is None:
        return ""

    try:
        containers = client.containers.list()
    except Exception:
        return ""

    port_label = str(port)
    for container in containers:
        try:
            container.reload()
            ports = container.attrs.get("NetworkSettings", {}).get("Ports", {}) or {}
        except Exception:
            continue

        matched_binding = False
        for _container_port, bindings in ports.items():
            if not bindings:
                continue
            for binding in bindings:
                if not isinstance(binding, dict):
                    continue
                host_port = str(binding.get("HostPort") or "").strip()
                host_ip = str(binding.get("HostIp") or "").strip()
                if host_port != port_label:
                    continue
                if host_ip in ("", "0.0.0.0", "::", "127.0.0.1", "::1", "localhost"):
                    matched_binding = True
                    break
            if matched_binding:
                break

        if not matched_binding:
            continue

        try:
            networks = container.attrs.get("NetworkSettings", {}).get("Networks", {}) or {}
        except Exception:
            networks = {}

        for _network_name, network in networks.items():
            if not isinstance(network, dict):
                continue
            gateway = str(network.get("Gateway") or "").strip()
            if _is_usable_lan_ip(gateway):
                return gateway

    return ""


def resolve_callback_lhost(
    target_host: Any,
    target_port: Any = None,
    *,
    explicit_lhost: Optional[str] = None,
) -> str:
    """
    Pick an lhost suitable for reverse callbacks.

    Priority:
    1. explicit override / KITTYSPLOIT_LHOST
    2. Docker bridge gateway when the target is a container IP or loopback publish
    3. primary LAN IP (user-facing network address)
    4. outbound interface toward a non-loopback target
    """
    for candidate in _explicit_lhost_candidates(explicit_lhost):
        if _is_usable_lan_ip(candidate):
            return candidate

    target = str(target_host or "").strip()
    loopback_target = is_loopback_or_unspecified_host(target)
    docker_target = is_docker_bridge_host(target)

    # Containers on 172.17/16 cannot reliably callback to the host LAN IP
    # (192.168.x.x). Prefer the bridge gateway (typically 172.17.0.1).
    if docker_target or loopback_target:
        gateway = ""
        if docker_target:
            gateway = resolve_docker_gateway_for_container_ip(target)
        if not gateway:
            gateway = resolve_docker_gateway_for_port(target_port)
        if gateway:
            return gateway
        if docker_target:
            # Fallback when docker SDK is unavailable: common docker0 gateway.
            return "172.17.0.1"

    lan_ip = discover_primary_lan_ip()
    if lan_ip:
        return lan_ip

    if target and not loopback_target:
        for probe_port in (80, 443):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.connect((target, probe_port))
                ip = str(sock.getsockname()[0] or "").strip()
                sock.close()
            except Exception:
                ip = ""
            if _is_usable_lan_ip(ip):
                return ip

    return ""


def _explicit_lhost_candidates(explicit_lhost: Optional[str]) -> Iterable[str]:
    if explicit_lhost and str(explicit_lhost).strip():
        yield str(explicit_lhost).strip()
    env = str(os.environ.get("KITTYSPLOIT_LHOST", "") or "").strip()
    if env:
        yield env
