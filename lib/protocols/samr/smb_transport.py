# -*- coding: utf-8 -*-
"""Transport SMB named pipe pour DCE/RPC (pysmb, sans Impacket)."""

from __future__ import annotations

from typing import Optional

try:
    from smb.SMBConnection import SMBConnection

    PYSMB_AVAILABLE = True
except ImportError:
    SMBConnection = None  # type: ignore
    PYSMB_AVAILABLE = False


class SmbPipeTransport:
    """Connexion IPC$ + named pipe DCE/RPC via pysmb."""

    def __init__(
        self,
        host: str,
        port: int = 445,
        username: str = "",
        password: str = "",
        domain: str = "",
        remote_name: str = "",
        pipe_name: str = "samr",
        timeout: int = 15,
    ) -> None:
        if not PYSMB_AVAILABLE:
            raise ImportError(
                "pysmb is required for SAMR enumeration. Install with: pip install pysmb"
            )
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.domain = domain
        self.remote_name = remote_name or host
        self.pipe_name = (pipe_name or "samr").strip("\\").split("\\")[-1]
        self.timeout = timeout
        self._conn: Optional[SMBConnection] = None
        self._tid: int = 0
        self._fid: int = 0

    def connect(self) -> None:
        self._conn = SMBConnection(
            username=self.username,
            password=self.password,
            my_name="KITTYSPLOIT",
            remote_name=self.remote_name,
            domain=self.domain,
            use_ntlm_v2=True,
            is_direct_tcp=True,
        )
        ok = self._conn.connect(self.host, self.port, timeout=self.timeout)
        if not ok:
            raise ConnectionError(f"SMB connect failed to {self.host}:{self.port}")
        self._tid = self._conn.connectTree("IPC$")
        self._fid = self._conn.openFile(self._tid, self.pipe_name)

    def disconnect(self) -> None:
        if self._conn and self._tid and self._fid:
            try:
                self._conn.closeFile(self._tid, self._fid)
            except Exception:
                pass
            try:
                self._conn.disconnectTree(self._tid)
            except Exception:
                pass
            try:
                self._conn.close()
            except Exception:
                pass
        self._conn = None
        self._tid = 0
        self._fid = 0

    def send(self, data: bytes) -> None:
        if not self._conn:
            raise RuntimeError("SMB pipe not connected")
        self._conn.writeFile(self._tid, self._fid, data)

    def recv(self) -> bytes:
        if not self._conn:
            raise RuntimeError("SMB pipe not connected")
        return self._conn.readFile(self._tid, self._fid)
