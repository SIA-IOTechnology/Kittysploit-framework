#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared target/port helpers for active ICS scanner modules."""

from __future__ import annotations

import socket
from typing import Any

from core.framework.base_module import BaseModule
from core.framework.option import OptInteger, OptPort, OptString
from lib.scanner.target_utils import normalize_scanner_target


def _get_opt(instance: Any, name: str, default: Any = None) -> Any:
    value = getattr(instance, name, default)
    if hasattr(value, "value"):
        return value.value
    return value


class Ics_scanner_client(BaseModule):
    target = OptString("", "Target IP or hostname", True)
    port = OptPort(502, "Target TCP/UDP port", True)
    timeout = OptInteger(5, "Connection timeout in seconds", False, advanced=True)

    def _host(self) -> str:
        host = str(_get_opt(self, "target", "") or "").strip()
        host, _, _ = normalize_scanner_target(host)
        if not host:
            return ""
        try:
            return socket.gethostbyname(host)
        except OSError:
            return host

    def _port(self) -> int:
        return int(_get_opt(self, "port", 502) or 502)

    def _timeout(self) -> float:
        return float(_get_opt(self, "timeout", 5) or 5)

    def is_tcp_open(self, host: str | None = None, port: int | None = None, timeout: float | None = None) -> bool:
        target = host or self._host()
        service_port = int(port if port is not None else self._port())
        wait = float(timeout if timeout is not None else self._timeout())
        if not target or not service_port:
            return False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(wait)
            return sock.connect_ex((target, service_port)) == 0
        except OSError:
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def is_udp_open(self, host: str | None = None, port: int | None = None, timeout: float | None = None) -> bool:
        """Best-effort UDP reachability — sends an empty datagram and ignores ICMP unreachable."""
        target = host or self._host()
        service_port = int(port if port is not None else self._port())
        wait = float(timeout if timeout is not None else self._timeout())
        if not target or not service_port:
            return False
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(wait)
            sock.sendto(b"\x00", (target, service_port))
            try:
                sock.recvfrom(1024)
            except socket.timeout:
                pass
            return True
        except OSError:
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def sync_workspace_ics(
        self,
        *,
        port: int | None = None,
        protocol: str = "",
        vendor: str = "",
        mac: str = "",
        device_type: str = "",
        purdue_level: int = 0,
        modbus_units: list | None = None,
        s7_slot: int | None = None,
        protection_level: int | None = None,
        source: str = "",
    ) -> bool:
        host = self._host()
        if not host:
            return False
        framework = getattr(self, "framework", None)
        if not framework:
            return False
        store = getattr(framework, "workspace_intel", None)
        if store is None:
            from core.workspace_intel import WorkspaceIntelStore

            store = WorkspaceIntelStore(framework)
        return store.record_ics_asset(
            host,
            port=port or self._port(),
            protocol=protocol or "",
            vendor=vendor,
            mac=mac,
            device_type=device_type,
            purdue_level=purdue_level,
            modbus_units=modbus_units,
            s7_slot=s7_slot,
            protection_level=protection_level,
            source=source or getattr(self, "module_path", ""),
        )
