#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass
from typing import List, Dict, Any, Optional

from core.framework.base_module import BaseModule
from core.framework.option import OptString, OptPort, OptInt, OptChoice, OptBool
from core.output_handler import print_success, print_status, print_error, print_info, print_warning

from smb.SMBConnection import SMBConnection
from smb.base import SharedDevice


@dataclass
class SMBAuth:
    username: str = ""
    password: str = ""
    domain: str = ""
    client_name: str = "kittysploit"   # nom local (n'importe)
    server_name: str = ""              # netbios name (optionnel, IP ok)


class SMBClient:
    """
    SMB client using pysmb (Windows-friendly).
    Supports:
      - connect()
      - list_shares()
      - list_path(share, path)
      - get_file(share, remote_path, local_path)
      - put_file(share, local_path, remote_path)
      - delete_file(share, remote_path)
      - create_directory(share, path)
      - delete_directory(share, path)
      - close()
    """

    def __init__(self, host: str, port: int = 445, auth: Optional[SMBAuth] = None, timeout: int = 10, use_ntlm_v2: bool = True, direct_tcp: bool = True):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.use_ntlm_v2 = use_ntlm_v2
        self.direct_tcp = direct_tcp

        self.auth = auth or SMBAuth()
        self.conn: Optional[SMBConnection] = None
        self.connected: bool = False

    def connect(self) -> bool:
        """
        Establish SMB connection (TCP 445 by default).
        """
        try:
            server_name = self.auth.server_name or self.host
            self.conn = SMBConnection(
                username=self.auth.username,
                password=self.auth.password,
                my_name=self.auth.client_name,
                remote_name=server_name,
                domain=self.auth.domain,
                use_ntlm_v2=self.use_ntlm_v2,
                is_direct_tcp=self.direct_tcp,
            )

            ok = self.conn.connect(self.host, self.port, timeout=self.timeout)
            self.connected = bool(ok)

            if self.connected:
                print_success(f"SMB connected to {self.host}:{self.port} as {self.auth.domain}\\{self.auth.username}")
            else:
                print_warning(f"SMB connection to {self.host}:{self.port} failed (no exception)")

            return self.connected

        except Exception as e:
            self.connected = False
            self.conn = None
            print_error(f"SMB connect failed -> {e}")
            return False

    def close(self):
        try:
            if self.conn:
                try:
                    self.conn.close()
                except Exception:
                    pass
            self.conn = None
            self.connected = False
            print_status("SMB connection closed")
        except Exception as e:
            print_warning(f"SMB close failed -> {e}")

    def _require(self):
        if not self.conn or not self.connected:
            raise RuntimeError("Not connected. Call connect() first.")

    # ---------- Shares / browsing ----------

    def list_shares(self) -> List[str]:
        """
        List available shares. Returns share names.
        """
        self._require()
        shares: List[str] = []
        try:
            share_objs: List[SharedDevice] = self.conn.listShares(timeout=self.timeout)
            for s in share_objs:
                # s.name includes trailing null sometimes in some environments; safe-strip
                name = (s.name or "").rstrip("\x00")
                if name:
                    shares.append(name)
            return shares
        except Exception as e:
            print_error(f"list_shares failed -> {e}")
            return shares

    def list_path(self, share: str, path: str = "\\") -> List[Dict[str, Any]]:
        """
        List directory entries in `share` at `path`.
        Returns list of dicts: name, is_dir, size, last_write
        """
        self._require()
        entries: List[Dict[str, Any]] = []
        try:
            files = self.conn.listPath(share, path, timeout=self.timeout)
            for f in files:
                # skip pseudo entries
                if f.filename in [".", ".."]:
                    continue
                entries.append({
                    "name": f.filename,
                    "is_dir": bool(f.isDirectory),
                    "size": int(getattr(f, "file_size", 0)),
                    "last_write": int(getattr(f, "last_write_time", 0)),
                })
            return entries
        except Exception as e:
            print_error(f"list_path failed for {share}:{path} -> {e}")
            return entries

    # ---------- File operations ----------

    def get_file(self, share: str, remote_path: str, local_path: str) -> bool:
        """
        Download a remote file to local path.
        """
        self._require()
        try:
            with open(local_path, "wb") as fp:
                self.conn.retrieveFile(share, remote_path, fp, timeout=self.timeout)
            print_success(f"Downloaded {share}:{remote_path} -> {local_path}")
            return True
        except Exception as e:
            print_error(f"get_file failed -> {e}")
            return False

    def put_file(self, share: str, local_path: str, remote_path: str) -> bool:
        """
        Upload a local file to remote path.
        """
        self._require()
        try:
            with open(local_path, "rb") as fp:
                self.conn.storeFile(share, remote_path, fp, timeout=self.timeout)
            print_success(f"Uploaded {local_path} -> {share}:{remote_path}")
            return True
        except Exception as e:
            print_error(f"put_file failed -> {e}")
            return False

    def delete_file(self, share: str, remote_path: str) -> bool:
        self._require()
        try:
            self.conn.deleteFiles(share, remote_path, timeout=self.timeout)
            print_success(f"Deleted file {share}:{remote_path}")
            return True
        except Exception as e:
            print_error(f"delete_file failed -> {e}")
            return False

    def create_directory(self, share: str, path: str) -> bool:
        self._require()
        try:
            self.conn.createDirectory(share, path, timeout=self.timeout)
            print_success(f"Created directory {share}:{path}")
            return True
        except Exception as e:
            print_error(f"create_directory failed -> {e}")
            return False

    def delete_directory(self, share: str, path: str) -> bool:
        self._require()
        try:
            self.conn.deleteDirectory(share, path, timeout=self.timeout)
            print_success(f"Deleted directory {share}:{path}")
            return True
        except Exception as e:
            print_error(f"delete_directory failed -> {e}")
            return False


class SMBModule(BaseModule):
    smb_host = OptString("", "Target IP or hostname", True)
    smb_port = OptPort(445, "Target SMB port (445 recommended)", True)

    smb_user = OptString("", "SMB username", True)
    smb_pass = OptString("", "SMB password", False)
    smb_domain = OptString("", "SMB domain (optional)", False)

    smb_client_name = OptString("kittysploit", "Local client name", False)
    smb_server_name = OptString("", "Server NetBIOS name (optional)", False)

    smb_timeout = OptInt(10, "SMB timeout (seconds)", True)
    smb_ntlmv2 = OptBool(True, "Use NTLMv2 (true/false)", False)

    def __init__(self, framework=None):
        super().__init__(framework)

    def open_smb(self) -> SMBClient:
        auth = SMBAuth(username=self.smb_user.value, password=self.smb_pass.value, domain=self.smb_domain.value, client_name=self.smb_client_name.value, server_name=self.smb_server_name.value or "")

        client = SMBClient(host=self.smb_host.value, port=self.smb_port.value, auth=auth, timeout=int(self.smb_timeout.value), use_ntlm_v2=self.smb_ntlmv2.value, direct_tcp=True)

        return client
