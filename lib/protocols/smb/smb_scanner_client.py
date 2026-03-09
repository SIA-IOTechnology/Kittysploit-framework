# -*- coding: utf-8 -*-
"""Client SMB pour les modules scanner : options target/port, sondes SMBv1/signing/null session."""

import socket
from typing import Tuple, Optional, Any

from core.framework.option import OptString, OptPort
from core.framework.base_module import BaseModule

from lib.protocols.smb.smb_probes import (
    smb1_negotiate,
    check_smb_signing,
    check_null_session,
)


def _get_opt(instance: Any, name: str) -> Any:
    v = getattr(instance, name, None)
    if hasattr(v, "value"):
        return v.value
    return v


class Smb_scanner_client(BaseModule):
    """Client pour scanners SMB : target, port ; sondes sans authentification."""

    target = OptString("", "Target hostname or IP", True)
    port = OptPort(445, "SMB port", True)
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
        return int(_get_opt(self, "port") or 445)

    def _timeout(self) -> float:
        return float(_get_opt(self, "timeout") or 3)

    def smb1_enabled(self) -> bool:
        """True si le serveur répond au SMBv1 Negotiate."""
        return smb1_negotiate(self._host(), self._port(), self._timeout())

    def smb_signing_status(self) -> Tuple[str, Optional[str]]:
        """(status, version) : required | enabled_not_required | disabled | smb2_disabled | unreachable | error."""
        return check_smb_signing(self._host(), self._port(), self._timeout())

    def null_session_accepted(self) -> bool:
        """True si null session (anonyme) est acceptée."""
        return check_null_session(self._host(), self._port(), self._timeout())
