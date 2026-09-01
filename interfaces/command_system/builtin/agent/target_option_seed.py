#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Seed scanner/exploit modules with the operator's HTTP target (host/port/ssl).

Http_client defaults are ``ssl=True`` and ``port=443``. Adaptive-loop and other
paths that load a module then call :class:`AgentModuleExecutionService` without
``_set_default_target_options`` would brute-force ``https://host:443`` even when
the operator typed ``http://127.0.0.1``.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional


def http_target_fields(target_info: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    info = dict(target_info or {})
    hostname = str(
        info.get("hostname") or info.get("host") or info.get("ip") or ""
    ).strip()
    scheme = str(info.get("scheme") or "http").strip().lower() or "http"
    port = info.get("port")
    if port in (None, ""):
        port = 443 if scheme == "https" else 80
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 443 if scheme == "https" else 80
    return {"hostname": hostname, "port": port, "scheme": scheme}


def apply_http_target_options(
    module_instance: Any,
    target_info: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Set target/rhost, port/rport, and ssl from parsed campaign target_info."""
    fields = http_target_fields(target_info)
    hostname = fields["hostname"]
    port = fields["port"]
    scheme = fields["scheme"]
    applied: Dict[str, Any] = {}
    if hostname:
        if hasattr(module_instance, "target"):
            _set_option(module_instance, "target", hostname)
            applied["target"] = hostname
        elif hasattr(module_instance, "rhost"):
            _set_option(module_instance, "rhost", hostname)
            applied["rhost"] = hostname
        elif hasattr(module_instance, "rhosts"):
            _set_option(module_instance, "rhosts", hostname)
            applied["rhosts"] = hostname
    if hasattr(module_instance, "port"):
        _set_option(module_instance, "port", port)
        applied["port"] = port
    elif hasattr(module_instance, "rport"):
        _set_option(module_instance, "rport", port)
        applied["rport"] = port
    if hasattr(module_instance, "ssl"):
        ssl_on = scheme == "https"
        _set_option(module_instance, "ssl", ssl_on)
        applied["ssl"] = ssl_on
    return applied


def apply_option_dict(module_instance: Any, options: Optional[Mapping[str, Any]]) -> None:
    if not isinstance(options, dict):
        return
    for key, value in options.items():
        if key in {"option_patch", "module_path"}:
            continue
        if not hasattr(module_instance, key):
            continue
        _set_option(module_instance, key, value)


def inferred_options_for_module(module_path: str, state: Any) -> Dict[str, Any]:
    """Login path / field overrides the linear plan path already applies."""
    path = str(module_path or "").strip()
    if not path:
        return {}
    from interfaces.command_system.builtin.agent.auth_operations import AuthContextOperations

    ops = AuthContextOperations(_normalize_relative_path)
    try:
        return dict(ops.build_inferred_option_overrides([{"path": path}], state).get(path) or {})
    except Exception:
        return {}


def apply_inferred_module_options(module_instance: Any, module_path: str, state: Any) -> Dict[str, Any]:
    inferred = inferred_options_for_module(module_path, state)
    apply_option_dict(module_instance, inferred)
    return inferred


def stamp_inferred_options_on_modules(modules: Any, state: Any) -> list:
    """Attach inferred option dicts onto module rows before scanner._execute_modules."""
    out = []
    for module in modules or []:
        if not isinstance(module, dict):
            out.append(module)
            continue
        row = dict(module)
        path = str(row.get("path") or "").strip()
        inferred = inferred_options_for_module(path, state)
        if inferred:
            opts = dict(row.get("options") or {})
            for key, value in inferred.items():
                opts.setdefault(key, value)
            row["options"] = opts
        out.append(row)
    return out


def _set_option(module_instance: Any, key: str, value: Any) -> None:
    try:
        if hasattr(module_instance, "set_option"):
            module_instance.set_option(key, value)
    except Exception:
        return


def _normalize_relative_path(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.startswith("/"):
        return raw.split("#", 1)[0][:256]
    return raw[:256]
