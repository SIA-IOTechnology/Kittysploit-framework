#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""UPnP session helpers — inherit ``UpnpSessionMixin``."""

from __future__ import annotations

from typing import Any, Dict

from lib.protocols.ics.ics_session_mixin import IcsSessionMixin
from lib.protocols.upnp.client import SSDP_PORT, UpnpClient


class UpnpSessionMixin(IcsSessionMixin):
    """Resolve ``UpnpClient`` from session registry / listener / module options."""

    def get_upnp_connection_info(self) -> Dict[str, Any]:
        session = self._resolve_session()
        if session:
            data = self._session_data(session)
            return {
                "host": str(data.get("host") or data.get("rhost") or "").strip(),
                "port": int(data.get("port") or data.get("rport") or SSDP_PORT),
                "location": str(data.get("location") or self._opt_value("location") or ""),
                "timeout": float(data.get("timeout") or self._opt_value("timeout") or 5),
            }
        host = self._opt_value("rhost") or self._opt_value("target")
        return {
            "host": str(host or "").strip(),
            "port": int(self._opt_value("rport") or self._opt_value("port") or SSDP_PORT),
            "location": str(self._opt_value("location") or ""),
            "timeout": float(self._opt_value("timeout") or 5),
        }

    def _make_upnp_client(self, info: Dict[str, Any]) -> UpnpClient:
        return UpnpClient(
            str(info.get("host") or "127.0.0.1"),
            int(info.get("port") or SSDP_PORT),
            float(info.get("timeout") or 5),
            location=str(info.get("location") or ""),
        )

    def get_upnp_client(self, *, connect: bool = True) -> UpnpClient:
        session = self._resolve_session()
        if session:
            session_id = self._session_id(session)
            registry_client = self._ics_registry().get(session_id)
            if isinstance(registry_client, UpnpClient) and registry_client.connected:
                return registry_client
            listener_client = self._client_from_listener(session, UpnpClient)
            if listener_client and listener_client.connected:
                return listener_client
            info = self.get_upnp_connection_info()
            client = self._make_upnp_client(info)
            if connect and not client.connect(location=str(info.get("location") or "")):
                raise RuntimeError(client.last_error or "UPnP connect failed")
            self._ics_registry()[session_id] = client
            return client

        info = self.get_upnp_connection_info()
        if not info.get("host") and not info.get("location"):
            raise RuntimeError("UPnP session, rhost, or location is required")
        client = self._make_upnp_client(info)
        if connect and not client.connect(location=str(info.get("location") or "")):
            raise RuntimeError(client.last_error or "UPnP connect failed")
        return client

    def open_upnp(self) -> UpnpClient:
        return self.get_upnp_client(connect=True)
