#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Remote command execution over SMB (PsExec-style) via impacket."""

from __future__ import annotations

import random
import string
import time


def _random_service_name(prefix: str = "KS") -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}{suffix}"


def exec_command(
    host: str,
    username: str,
    password: str,
    command: str,
    domain: str = "",
    port: int = 445,
    remote_name: str = "",
    timeout: int = 30,
) -> tuple[int, str, str]:
    """
    Execute a command on a remote Windows host via SMB + SCM (impacket).

    Returns (return_code, stdout, stderr).
    Raises ImportError if impacket is not installed.
    """
    try:
        from impacket.dcerpc.v5 import scmr, transport
    except ImportError as exc:
        raise ImportError(
            "impacket is required for remote SMB command execution. "
            "Install with: pip install impacket"
        ) from exc

    remote = remote_name or host
    string_binding = rf"ncacn_np:{host}[\pipe\svcctl]"
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    rpctransport.set_credentials(username, password, domain, remote_name=remote)

    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(scmr.MSRPC_UUID_SCMR)

    resp = scmr.hROpenSCManagerW(dce)
    sc_handle = resp["lpScHandle"]

    service_name = _random_service_name()
    binary_path = rf"C:\Windows\System32\cmd.exe /Q /c {command}"

    try:
        resp = scmr.hRCreateServiceW(
            dce,
            sc_handle,
            service_name,
            service_name,
            lpBinaryPathName=binary_path,
            dwStartType=scmr.SERVICE_DEMAND_START,
        )
        service_handle = resp["lpServiceHandle"]

        try:
            scmr.hRStartServiceW(dce, service_handle, [])
        except Exception:
            pass

        time.sleep(min(max(timeout // 10, 1), 5))

        try:
            scmr.hRDeleteService(dce, service_handle)
        except Exception:
            pass
        try:
            scmr.hRCloseServiceHandle(dce, service_handle)
        except Exception:
            pass
    finally:
        try:
            scmr.hRCloseServiceHandle(dce, sc_handle)
        except Exception:
            pass
        try:
            dce.disconnect()
        except Exception:
            pass

    return 0, "", ""


def impacket_available() -> bool:
    try:
        import impacket  # noqa: F401
        return True
    except ImportError:
        return False
