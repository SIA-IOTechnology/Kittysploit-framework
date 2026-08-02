#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""RTSP session helpers — inherit ``RtspSessionMixin``."""

from __future__ import annotations

from typing import Any, Dict

from lib.protocols.ics.ics_session_mixin import IcsSessionMixin
from lib.protocols.rtsp.client import RTSP_PORT, RtspClient, parse_rtsp_url


class RtspSessionMixin(IcsSessionMixin):
    """Resolve ``RtspClient`` from session registry / listener / module options."""

    def _rtsp_opt(self, name: str, default=None):
        attr = getattr(self, name, default)
        if hasattr(attr, "value"):
            attr = attr.value
        return attr if attr is not None else default

    def get_rtsp_connection_info(self) -> Dict[str, Any]:
        session = self._resolve_session()
        if session:
            data = self._session_data(session)
            url = str(data.get("url") or data.get("rtsp_url") or "").strip()
            if url:
                parts = parse_rtsp_url(url)
                return {
                    "url": url,
                    "host": str(parts.get("host") or data.get("host") or ""),
                    "port": int(parts.get("port") or data.get("port") or RTSP_PORT),
                    "path": str(parts.get("path") or data.get("path") or "/"),
                    "username": str(
                        data.get("username") or parts.get("username") or self._rtsp_opt("username") or ""
                    ),
                    "password": str(
                        data.get("password") or parts.get("password") or self._rtsp_opt("password") or ""
                    ),
                    "use_tls": bool(data.get("use_tls") or data.get("ssl") or parts.get("scheme") == "rtsps"),
                    "timeout": float(data.get("timeout") or self._rtsp_opt("timeout") or 5),
                }
            return {
                "url": "",
                "host": str(data.get("host") or data.get("rhost") or "").strip(),
                "port": int(data.get("port") or data.get("rport") or RTSP_PORT),
                "path": str(data.get("path") or "/"),
                "username": str(data.get("username") or self._rtsp_opt("username") or ""),
                "password": str(data.get("password") or self._rtsp_opt("password") or ""),
                "use_tls": bool(data.get("use_tls") or data.get("ssl") or False),
                "timeout": float(data.get("timeout") or self._rtsp_opt("timeout") or 5),
            }

        url = str(self._rtsp_opt("url") or self._rtsp_opt("rtsp_url") or "").strip()
        if url:
            parts = parse_rtsp_url(url)
            return {
                "url": url,
                "host": str(parts.get("host") or ""),
                "port": int(parts.get("port") or RTSP_PORT),
                "path": str(parts.get("path") or "/"),
                "username": str(parts.get("username") or self._rtsp_opt("username") or ""),
                "password": str(parts.get("password") or self._rtsp_opt("password") or ""),
                "use_tls": str(parts.get("scheme") or "").lower() == "rtsps"
                or bool(self._rtsp_opt("ssl") or self._rtsp_opt("use_tls")),
                "timeout": float(self._rtsp_opt("timeout") or 5),
            }
        return {
            "url": "",
            "host": str(self._rtsp_opt("rhost") or self._rtsp_opt("target") or "").strip(),
            "port": int(self._rtsp_opt("rport") or self._rtsp_opt("port") or RTSP_PORT),
            "path": str(self._rtsp_opt("path") or "/"),
            "username": str(self._rtsp_opt("username") or ""),
            "password": str(self._rtsp_opt("password") or ""),
            "use_tls": bool(self._rtsp_opt("ssl") or self._rtsp_opt("use_tls") or False),
            "timeout": float(self._rtsp_opt("timeout") or 5),
        }

    def _make_rtsp_client(self, info: Dict[str, Any]) -> RtspClient:
        url = str(info.get("url") or "").strip()
        if url:
            return RtspClient(
                url=url,
                username=str(info.get("username") or ""),
                password=str(info.get("password") or ""),
                timeout=float(info.get("timeout") or 5),
                use_tls=bool(info.get("use_tls")),
            )
        return RtspClient(
            host=str(info.get("host") or ""),
            port=int(info.get("port") or RTSP_PORT),
            path=str(info.get("path") or "/"),
            username=str(info.get("username") or ""),
            password=str(info.get("password") or ""),
            timeout=float(info.get("timeout") or 5),
            use_tls=bool(info.get("use_tls")),
        )

    def get_rtsp_client(self, *, connect: bool = True) -> RtspClient:
        session = self._resolve_session()
        if session:
            session_id = self._session_id(session)
            registry_client = self._ics_registry().get(session_id)
            if isinstance(registry_client, RtspClient) and registry_client.connected:
                return registry_client
            listener_client = self._client_from_listener(session, RtspClient)
            if listener_client and listener_client.connected:
                return listener_client
            info = self.get_rtsp_connection_info()
            if info.get("host") or info.get("url"):
                client = self._make_rtsp_client(info)
                if connect and not client.connect():
                    raise RuntimeError(client.last_error or "RTSP connect failed")
                self._ics_registry()[session_id] = client
                return client

        info = self.get_rtsp_connection_info()
        if not info.get("host") and not info.get("url"):
            raise RuntimeError("RTSP session, url, or rhost is required")
        client = self._make_rtsp_client(info)
        if connect and not client.connect():
            raise RuntimeError(client.last_error or "RTSP connect failed")
        return client

    def open_rtsp(self, *, connect: bool = True) -> RtspClient:
        return self.get_rtsp_client(connect=connect)
