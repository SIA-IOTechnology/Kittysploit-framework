#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""SMB session helpers for post-exploitation modules."""

from typing import Any, Dict, Optional

from lib.protocols.smb.smb_client import SMBAuth, SMBClient


class SMBSessionMixin:
    """Retrieve SMBClient instances from an active session or direct module options."""

    def get_smb_connection(self) -> SMBClient:
        session = self._resolve_session()
        if session:
            client = self._client_from_session(session)
            if client and client.connected:
                return client
            client = self._reconnect_from_session(session)
            if client:
                return client

        host = self._opt_value("rhost") or self._opt_value("smb_host") or self._opt_value("target")
        if host:
            return self._direct_client(str(host))

        raise RuntimeError("No SMB session and no rhost/smb_host configured.")

    def get_smb_connection_info(self) -> Dict[str, Any]:
        session = self._resolve_session()
        if session and getattr(session, "data", None):
            data = session.data if isinstance(session.data, dict) else {}
            return {
                "host": data.get("host", ""),
                "port": data.get("port", 445),
                "username": data.get("username", ""),
                "domain": data.get("domain", ""),
                "password": data.get("password", ""),
                "shares": data.get("shares", []),
            }
        return {
            "host": self._opt_value("rhost") or self._opt_value("smb_host") or "",
            "port": int(self._opt_value("rport") or self._opt_value("smb_port") or 445),
            "username": self._opt_value("username") or self._opt_value("smb_user") or "",
            "domain": self._opt_value("domain") or self._opt_value("smb_domain") or "",
            "password": self._opt_value("password") or self._opt_value("smb_pass") or "",
            "shares": [],
        }

    def open_smb(self) -> SMBClient:
        return self.get_smb_connection()

    def _resolve_session(self):
        if hasattr(self, "session") and self.session:
            return self.session
        session_id = self._opt_value("session_id")
        if session_id and getattr(self, "framework", None):
            mgr = getattr(self.framework, "session_manager", None)
            if mgr:
                return mgr.get_session(str(session_id))
        return None

    def _client_from_session(self, session) -> Optional[SMBClient]:
        data = getattr(session, "data", None)
        if isinstance(data, dict):
            conn = data.get("connection")
            if isinstance(conn, SMBClient):
                return conn

        framework = getattr(self, "framework", None)
        if framework and isinstance(data, dict):
            listener_id = data.get("listener_id")
            session_id = getattr(session, "session_id", getattr(session, "id", None))
            if listener_id and session_id and hasattr(framework, "active_listeners"):
                listener = framework.active_listeners.get(listener_id)
                if listener and hasattr(listener, "_session_connections"):
                    conn = listener._session_connections.get(session_id)
                    if isinstance(conn, SMBClient):
                        return conn
        return None

    def _reconnect_from_session(self, session) -> Optional[SMBClient]:
        info = self.get_smb_connection_info()
        host = info.get("host")
        if not host:
            return None
        client = self._build_client(
            host=str(host),
            port=int(info.get("port") or 445),
            username=str(info.get("username") or ""),
            password=str(info.get("password") or ""),
            domain=str(info.get("domain") or ""),
        )
        if client.connect():
            return client
        return None

    def _direct_client(self, host: str) -> SMBClient:
        client = self._build_client(
            host=host,
            port=int(self._opt_value("rport") or self._opt_value("smb_port") or 445),
            username=str(self._opt_value("username") or self._opt_value("smb_user") or ""),
            password=str(self._opt_value("password") or self._opt_value("smb_pass") or ""),
            domain=str(self._opt_value("domain") or self._opt_value("smb_domain") or ""),
            client_name=str(self._opt_value("client_name") or self._opt_value("smb_client_name") or "kittysploit"),
            server_name=str(self._opt_value("server_name") or self._opt_value("smb_server_name") or host),
        )
        if not client.connect():
            raise RuntimeError(f"SMB connection failed for {host}")
        return client

    def _build_client(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        domain: str,
        client_name: str = "kittysploit",
        server_name: str = "",
    ) -> SMBClient:
        auth = SMBAuth(
            username=username,
            password=password,
            domain=domain,
            client_name=client_name,
            server_name=server_name or host,
        )
        timeout = int(self._opt_value("timeout") or self._opt_value("smb_timeout") or 10)
        use_ntlm_v2 = self._opt_value("use_ntlm_v2")
        if use_ntlm_v2 is None:
            use_ntlm_v2 = True
        return SMBClient(
            host=host,
            port=port,
            auth=auth,
            timeout=timeout,
            use_ntlm_v2=bool(use_ntlm_v2),
            direct_tcp=True,
        )

    def _opt_value(self, name: str):
        attr = getattr(self, name, None)
        if attr is None:
            return None
        return attr.value if hasattr(attr, "value") else attr
