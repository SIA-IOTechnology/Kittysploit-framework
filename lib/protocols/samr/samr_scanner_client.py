#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared options/helpers for SAMR auxiliary/scanner modules."""

from __future__ import annotations

import socket
from typing import Any, Tuple

from core.framework.base_module import BaseModule
from core.framework.option import OptPort, OptString


def _get_opt(instance: Any, name: str) -> Any:
    value = getattr(instance, name, None)
    if hasattr(value, "value"):
        return value.value
    return value


class SamrScannerClient(BaseModule):
    target = OptString("", "Domain controller or member host", True)
    port = OptPort(445, "SMB/SAMR port", True)
    username = OptString("", "Username (DOMAIN\\user or user@domain)", False)
    password = OptString("", "Password", False)
    domain = OptString("", "AD domain (optional if included in username)", False)
    timeout = OptPort(15, "RPC timeout in seconds", False, advanced=True)

    def _host(self) -> str:
        host = str(_get_opt(self, "target") or "").strip()
        if not host:
            return ""
        try:
            return socket.gethostbyname(host)
        except Exception:
            return host

    def _port(self) -> int:
        return int(_get_opt(self, "port") or 445)

    def _timeout(self) -> int:
        return max(int(_get_opt(self, "timeout") or 15), 3)

    def _parse_credentials(self) -> Tuple[str, str, str]:
        user = str(_get_opt(self, "username") or "").strip()
        password = str(_get_opt(self, "password") or "")
        dom = str(_get_opt(self, "domain") or "").strip()
        if "@" in user and not dom:
            dom = user.split("@", 1)[1]
        elif "\\" in user:
            dom, user = user.split("\\", 1)
        return user, password, dom
