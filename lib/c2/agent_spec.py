#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unified agent configuration consumed by Python/Zig/PHP/covert builders."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from lib.c2.beacon_profile import BeaconProfile


def _opt_raw(module: Any, name: str, default: Any = None) -> Any:
    attr = getattr(module, name, default)
    if attr is None:
        return default
    if hasattr(attr, "value"):
        return getattr(attr, "value")
    return attr


@dataclass
class AgentSpec:
    """Shared implant configuration for all agent script builders."""

    host: str
    port: int
    client_id: str
    url_prefix: str = "/c2"
    use_ssl: bool = False
    private_key_pem: Optional[str] = None
    profile: Optional[BeaconProfile] = None
    chain_token: str = ""
    chain_listen_port: int = 0
    chain_listen_host: str = "0.0.0.0"
    task_mode: str = "typed"

    @classmethod
    def from_module(
        cls,
        module: Any,
        *,
        client_id: Optional[str] = None,
        private_key_pem: Optional[str] = None,
        task_mode: str = "typed",
    ) -> "AgentSpec":
        cid = str(client_id or _opt_raw(module, "client_id", "") or "").strip()
        if not cid:
            cid = "kitty1"
        profile = BeaconProfile.from_opts(module)
        return cls(
            host=str(_opt_raw(module, "lhost", "127.0.0.1") or "127.0.0.1"),
            port=int(_opt_raw(module, "lport", 8088) or 8088),
            client_id=cid,
            url_prefix=str(_opt_raw(module, "url_prefix", "/c2") or "/c2"),
            use_ssl=bool(_opt_raw(module, "use_ssl", False)),
            private_key_pem=private_key_pem,
            profile=profile,
            chain_token=str(_opt_raw(module, "chain_token", "") or "").strip(),
            chain_listen_port=int(_opt_raw(module, "chain_listen_port", 0) or 0),
            chain_listen_host=str(_opt_raw(module, "chain_listen_host", "0.0.0.0") or "0.0.0.0"),
            task_mode=task_mode,
        )
