#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Matter session helpers — inherit ``MatterSessionMixin``."""

from __future__ import annotations

from typing import Any, Dict

from lib.protocols.ics.ics_session_mixin import IcsSessionMixin
from lib.protocols.matter.client import MATTER_UDP_PORT, MatterClient


class MatterSessionMixin(IcsSessionMixin):
    """Resolve ``MatterClient`` from session registry / listener / module options."""

    def get_matter_connection_info(self) -> Dict[str, Any]:
        session = self._resolve_session()
        if session:
            data = self._session_data(session)
            return {
                "host": str(data.get("host") or data.get("rhost") or "").strip(),
                "port": int(data.get("port") or data.get("rport") or MATTER_UDP_PORT),
                "timeout": float(data.get("timeout") or self._opt_value("timeout") or 3),
                "multicast": bool(
                    data.get("multicast")
                    if data.get("multicast") is not None
                    else self._opt_value("multicast")
                ),
            }
        host = self._opt_value("rhost") or self._opt_value("target") or self._opt_value("host")
        return {
            "host": str(host or "").strip(),
            "port": int(
                self._opt_value("rport")
                or self._opt_value("port")
                or MATTER_UDP_PORT
            ),
            "timeout": float(self._opt_value("timeout") or 3),
            "multicast": bool(self._opt_value("multicast")),
        }

    def _make_matter_client(self, info: Dict[str, Any]) -> MatterClient:
        return MatterClient(
            host=str(info.get("host") or ""),
            port=int(info.get("port") or MATTER_UDP_PORT),
            timeout=float(info.get("timeout") or 3),
            multicast=bool(info.get("multicast")),
        )

    def get_matter_client(self, *, connect: bool = True) -> MatterClient:
        session = self._resolve_session()
        if session:
            session_id = self._session_id(session)
            registry_client = self._ics_registry().get(session_id)
            if isinstance(registry_client, MatterClient) and (
                registry_client.connected or registry_client.devices
            ):
                return registry_client
            listener_client = self._client_from_listener(session, MatterClient)
            if listener_client and (listener_client.connected or listener_client.devices):
                return listener_client
            info = self.get_matter_connection_info()
            client = self._make_matter_client(info)
            if connect and not client.connect():
                # Still return client with empty inventory if multicast/host discovery soft-fails
                if not client.devices:
                    raise RuntimeError(client.last_error or "Matter discovery failed")
            self._ics_registry()[session_id] = client
            return client

        info = self.get_matter_connection_info()
        if not info.get("host") and not info.get("multicast"):
            raise RuntimeError("Matter session, rhost/target, or multicast=true required")
        client = self._make_matter_client(info)
        if connect and not client.connect():
            if not client.devices:
                raise RuntimeError(client.last_error or "Matter discovery failed")
        return client

    def open_matter(self, *, connect: bool = True) -> MatterClient:
        return self.get_matter_client(connect=connect)
