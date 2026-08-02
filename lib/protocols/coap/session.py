#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CoAP session helpers for post modules — inherit ``CoapSessionMixin``."""

from __future__ import annotations

from typing import Any, Dict

from lib.protocols.coap.client import COAP_PORT, COAPS_PORT, CoapClient
from lib.protocols.ics.ics_session_mixin import IcsSessionMixin


class CoapSessionMixin(IcsSessionMixin):
    """Resolve a live ``CoapClient`` from session registry / listener / rhost."""

    def get_coap_connection_info(self) -> Dict[str, Any]:
        session = self._resolve_session()
        dtls_opt = self._opt_value("dtls")
        if session:
            data = self._session_data(session)
            dtls = bool(data.get("dtls") if data.get("dtls") is not None else dtls_opt)
            default_port = COAPS_PORT if dtls else COAP_PORT
            return {
                "host": str(data.get("host") or ""),
                "port": int(data.get("port") or default_port),
                "timeout": float(data.get("timeout") or 5),
                "dtls": dtls,
            }
        host = self._opt_value("rhost") or self._opt_value("target")
        dtls = bool(dtls_opt)
        default_port = COAPS_PORT if dtls else COAP_PORT
        return {
            "host": str(host or "").strip(),
            "port": int(self._opt_value("rport") or self._opt_value("port") or default_port),
            "timeout": float(self._opt_value("timeout") or 5),
            "dtls": dtls,
        }

    def _make_coap_client(self, info: Dict[str, Any]) -> CoapClient:
        return CoapClient(
            str(info["host"]),
            int(info["port"]),
            float(info["timeout"]),
            dtls=bool(info.get("dtls")),
        )

    def get_coap_client(self) -> CoapClient:
        session = self._resolve_session()
        if session:
            session_id = self._session_id(session)
            registry_client = self._ics_registry().get(session_id)
            if isinstance(registry_client, CoapClient) and registry_client.connected:
                return registry_client
            listener_client = self._client_from_listener(session, CoapClient)
            if listener_client and listener_client.connected:
                return listener_client
            info = self.get_coap_connection_info()
            if info.get("host"):
                client = self._make_coap_client(info)
                if client.connect():
                    self._ics_registry()[session_id] = client
                    return client
                raise RuntimeError(client.last_error or "CoAP connect/probe failed")

        info = self.get_coap_connection_info()
        host = str(info.get("host") or "").strip()
        if not host:
            raise RuntimeError("CoAP session or rhost required")
        client = self._make_coap_client(info)
        if not client.connect():
            raise RuntimeError(client.last_error or "CoAP connect/probe failed")
        return client

    def open_coap(self) -> CoapClient:
        return self.get_coap_client()
