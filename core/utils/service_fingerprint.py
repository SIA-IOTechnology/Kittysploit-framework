#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Lightweight TCP service fingerprinting and module suggestions."""

from __future__ import annotations

import re
import socket
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

PORT_SERVICE_HINTS: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    636: "ldaps",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "http",
    8443: "https",
}

# Primary scanner per service (used by campaign graph builder).
SERVICE_SCANNER_MODULES: Dict[str, str] = {
    "http": "scanner/http/server_banner_detect",
    "https": "scanner/http/server_banner_detect",
    "ftp": "auxiliary/scanner/ftp/ftp_enum",
    "redis": "scanner/redis/redis_info_detect",
    "mysql": "scanner/mysql/mysql_info_detect",
    "smb": "scanner/smb/null_session",
    "ldap": "scanner/ldap/password_policy",
}

# Extended follow-up modules shown by network_discover.
SERVICE_MODULE_SUGGESTIONS: Dict[str, Tuple[str, ...]] = {
    "http": (
        "scanner/http/server_banner_detect",
        "auxiliary/scanner/http/robots",
        "auxiliary/scanner/http/login_page_detector",
        "scanner/http/security_headers_detect",
    ),
    "https": (
        "scanner/http/server_banner_detect",
        "auxiliary/scanner/http/robots",
        "scanner/http/security_headers_detect",
    ),
    "ftp": ("auxiliary/scanner/ftp/ftp_enum",),
    "ssh": ("auxiliary/osint/ip_reverse_dns",),
    "smtp": ("auxiliary/osint/ip_reverse_dns",),
    "mysql": ("scanner/mysql/mysql_info_detect",),
    "redis": ("scanner/redis/redis_info_detect",),
    "smb": ("scanner/smb/null_session", "scanner/smb/smbv1_detect"),
    "ldap": ("scanner/ldap/password_policy",),
}

BANNER_MODULE_HINTS: Tuple[Tuple[str, str], ...] = (
    ("nginx", "auxiliary/scanner/http/nginx_vuln_scanner"),
    ("apache", "auxiliary/scanner/http/apache_vuln_scanner"),
    ("wordpress", "auxiliary/scanner/http/wordpress_scanner"),
    ("jenkins", "scanner/http/jenkins_detect"),
    ("graphql", "scanner/http/graphql_detect"),
    ("drupal", "auxiliary/scanner/http/drupal_scanner"),
    ("joomla", "auxiliary/scanner/http/joomla_scanner"),
    ("grafana", "scanner/http/grafana_detect"),
    ("elasticsearch", "scanner/http/elasticsearch_detect"),
    ("tomcat", "scanner/http/tomcat_detect"),
)

_SERVICE_ENTRY_RE = re.compile(r"^(?P<protocol>tcp|udp)/(?P<port>\d+)$", re.IGNORECASE)
_VERSION_RE = re.compile(r"(?P<product>[A-Za-z][\w.-]+)/(?P<version>[\d][\w._-]*)")


def service_hint_from_port(port: int) -> str:
    return PORT_SERVICE_HINTS.get(int(port), "")


def parse_service_entry(entry: Any) -> Optional[Dict[str, Any]]:
    if isinstance(entry, dict):
        return entry
    if not isinstance(entry, str):
        return None
    match = _SERVICE_ENTRY_RE.match(entry.strip())
    if not match:
        return None
    port = int(match.group("port"))
    protocol = match.group("protocol").lower()
    return {
        "port": port,
        "protocol": protocol,
        "name": service_hint_from_port(port) or protocol,
    }


def _probe_bytes(port: int) -> Optional[bytes]:
    if port in (80, 8080, 8000, 8888):
        return b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    if port in (443, 8443):
        return None
    if port == 6379:
        return b"PING\r\n"
    return None


def grab_banner(host: str, port: int, timeout: float = 1.0) -> str:
    """Grab a short TCP banner or HTTP response snippet."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        probe = _probe_bytes(port)
        if probe:
            sock.sendall(probe)
        data = sock.recv(2048)
        return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""
    finally:
        sock.close()


def _parse_http_server(banner: str) -> Tuple[str, str, str]:
    service = "http"
    product = ""
    version = ""
    for line in banner.splitlines():
        lower = line.lower()
        if lower.startswith("server:"):
            value = line.split(":", 1)[1].strip()
            match = _VERSION_RE.search(value)
            if match:
                product = match.group("product")
                version = match.group("version")
            else:
                product = value.split()[0] if value else ""
    return service, product, version


def identify_service(port: int, protocol: str, banner: str = "") -> Dict[str, str]:
    """Infer service name, product and version from port and banner."""
    banner = (banner or "").strip()
    lowered = banner.lower()
    name = ""
    product = ""
    version = ""

    if lowered.startswith("ssh-"):
        name = "ssh"
        match = re.search(r"ssh-[\d.]+-(\S+)", banner, re.IGNORECASE)
        if match:
            product = match.group(1)
    elif lowered.startswith("220"):
        name = "ftp" if "ftp" in lowered else "smtp"
    elif lowered.startswith("+ok"):
        name = "pop3"
    elif lowered.startswith("* ok"):
        name = "imap"
    elif lowered.startswith("http/"):
        name, product, version = _parse_http_server(banner)
    elif lowered.startswith("-err") or lowered.startswith("+pong") or lowered == "pong":
        name = "redis"
    elif "mysql" in lowered or lowered.startswith("\x00"):
        name = "mysql"
    elif "postgresql" in lowered:
        name = "postgres"

    if not name:
        name = service_hint_from_port(port) or protocol

    if port in (443, 8443) and name == "http":
        name = "https"

    return {
        "name": name,
        "product": product,
        "version": version,
        "banner": banner[:240] if banner else "",
    }


def suggest_modules(
    service: Dict[str, Any],
    *,
    limit: int = 6,
) -> List[str]:
    name = (service.get("name") or "").lower()
    banner_blob = " ".join(
        str(service.get(key) or "")
        for key in ("banner", "product", "version")
    ).lower()

    seen: Set[str] = set()
    ordered: List[str] = []

    def add(path: str) -> None:
        if not path or path in seen:
            return
        seen.add(path)
        ordered.append(path)

    primary = SERVICE_SCANNER_MODULES.get(name)
    if primary:
        add(primary)

    for path in SERVICE_MODULE_SUGGESTIONS.get(name, ()):
        add(path)

    for needle, path in BANNER_MODULE_HINTS:
        if needle in banner_blob:
            add(path)

    return ordered[:limit]


def format_service_label(service: Dict[str, Any]) -> str:
    """Human-readable label for a fingerprinted service."""
    protocol = service.get("protocol", "tcp")
    port = service.get("port", "?")
    name = service.get("name") or protocol
    product = service.get("product") or ""
    version = service.get("version") or ""
    detail = product
    if version:
        detail = f"{product}/{version}" if product else version
    if detail:
        return f"{name}/{port} ({detail})"
    return f"{name}/{port}"


def fingerprint_services(
    host: str,
    services: Sequence[Any],
    *,
    timeout: float = 1.0,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Fingerprint open ports and derive module suggestions.

    Returns (fingerprints, suggested_modules).
    """
    fingerprints: List[Dict[str, Any]] = []
    suggested: List[str] = []
    seen_ports: Set[Tuple[str, int]] = set()

    for entry in services:
        parsed = parse_service_entry(entry)
        if not parsed:
            continue
        key = (parsed["protocol"], int(parsed["port"]))
        if key in seen_ports:
            continue
        seen_ports.add(key)

        if parsed["protocol"] != "tcp":
            fingerprints.append(parsed)
            suggested.extend(suggest_modules(parsed))
            continue

        port = int(parsed["port"])
        banner = grab_banner(host, port, timeout=timeout)
        identified = identify_service(port, parsed["protocol"], banner)
        fingerprint = {
            "port": port,
            "protocol": parsed["protocol"],
            **identified,
        }
        fingerprints.append(fingerprint)
        suggested.extend(suggest_modules(fingerprint))

    deduped: List[str] = []
    seen_modules: Set[str] = set()
    for path in suggested:
        if path in seen_modules:
            continue
        seen_modules.add(path)
        deduped.append(path)

    return fingerprints, deduped
