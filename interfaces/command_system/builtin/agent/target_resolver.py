#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Normalize agent targets without losing ports, paths, queries, IDNs, or IPv6."""

import ipaddress
import socket
import ssl
from urllib.parse import urlsplit, urlunsplit


class TargetResolver:
    """Prefer HTTPS for bare hostnames when 443 is reachable."""

    def normalize_target_input(self, raw_target: str, protocol: str = None) -> str:
        target = (raw_target or "").strip()
        if not target:
            return raw_target

        explicit_protocol = str(protocol or "").strip().lower()
        if explicit_protocol and explicit_protocol not in {"http", "https"}:
            return target

        parsed = urlsplit(target)
        if parsed.scheme and parsed.netloc:
            return self._normalize_url(parsed)

        host, port, suffix = self._split_bare_target(target)
        if not host:
            return target
        display_host = self._display_host(host)
        if port is not None:
            scheme = "https" if explicit_protocol == "https" or (
                not explicit_protocol and self.supports_tls(host, port, timeout=1.0)
            ) else "http"
            return f"{scheme}://{display_host}:{port}{suffix}"

        scheme = explicit_protocol or (
            "https" if self.supports_tls(host, 443, timeout=1.0) else "http"
        )
        return f"{scheme}://{display_host}{suffix}"

    def _normalize_url(self, parsed) -> str:
        host = parsed.hostname or ""
        normalized_host = self._display_host(host)
        userinfo = ""
        if parsed.username:
            userinfo = parsed.username
            if parsed.password:
                userinfo += f":{parsed.password}"
            userinfo += "@"
        port = f":{parsed.port}" if parsed.port else ""
        netloc = f"{userinfo}{normalized_host}{port}"
        return urlunsplit(
            (
                parsed.scheme.lower(),
                netloc,
                parsed.path or "/",
                parsed.query,
                parsed.fragment,
            )
        )

    def _split_bare_target(self, target: str):
        suffix = ""
        authority = target
        for marker in ("/", "?", "#"):
            index = authority.find(marker)
            if index >= 0:
                suffix = authority[index:]
                authority = authority[:index]
                break
        authority = authority.strip()
        if authority.startswith("[") and "]" in authority:
            closing = authority.index("]")
            host = authority[1:closing]
            remainder = authority[closing + 1 :]
            port = int(remainder[1:]) if remainder.startswith(":") and remainder[1:].isdigit() else None
            return host, port, suffix or "/"
        try:
            ipaddress.ip_address(authority)
            return authority, None, suffix or "/"
        except ValueError:
            pass
        if authority.count(":") == 1:
            host, raw_port = authority.rsplit(":", 1)
            if raw_port.isdigit() and 1 <= int(raw_port) <= 65535:
                return self._idna(host), int(raw_port), suffix or "/"
        return self._idna(authority), None, suffix or "/"

    @staticmethod
    def _idna(host: str) -> str:
        try:
            return str(host or "").encode("idna").decode("ascii").lower()
        except UnicodeError:
            return str(host or "").lower()

    @staticmethod
    def _display_host(host: str) -> str:
        try:
            value = ipaddress.ip_address(host)
            return f"[{value.compressed}]" if value.version == 6 else value.compressed
        except ValueError:
            return TargetResolver._idna(host)

    def is_port_open(self, host: str, port: int, timeout: float = 1.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    def supports_tls(self, host: str, port: int, timeout: float = 1.0) -> bool:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host):
                    return True
        except Exception:
            return False
