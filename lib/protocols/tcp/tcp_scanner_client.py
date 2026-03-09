# -*- coding: utf-8 -*-
"""Client TCP pour modules scanner : options target/port, test de connectivité."""

import socket
from typing import Any

from core.framework.option import OptString, OptPort
from core.framework.base_module import BaseModule


def _get_opt(instance: Any, name: str) -> Any:
    v = getattr(instance, name, None)
    if hasattr(v, "value"):
        return v.value
    return v


class Tcp_scanner_client(BaseModule):
    """Client pour scanners TCP : target, port, timeout ; test connectivité."""

    target = OptString("", "Target hostname or IP", True)
    port = OptPort(3868, "Target port (e.g. 3868 Diameter)", True)
    timeout = OptPort(3, "Probe timeout (seconds)", False, advanced=True)

    def __init__(self, framework=None):
        super().__init__(framework)

    def _host(self) -> str:
        host = _get_opt(self, "target") or ""
        if not host:
            return ""
        try:
            return socket.gethostbyname(host)
        except Exception:
            return host

    def _port(self) -> int:
        return int(_get_opt(self, "port") or 3868)

    def _timeout(self) -> float:
        return float(_get_opt(self, "timeout") or 3)

    def is_tcp_open(self, host: str = None, port: int = None, timeout: float = None) -> bool:
        """True si le port TCP est ouvert."""
        h = host or self._host()
        p = port if port is not None else self._port()
        t = timeout if timeout is not None else self._timeout()
        if not h or not p:
            return False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(t)
            result = s.connect_ex((h, p))
            s.close()
            return result == 0
        except Exception:
            return False
