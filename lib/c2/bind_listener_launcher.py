#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Launch BIND listeners from auxiliary/post modules (one-shot connect + session)."""

from __future__ import annotations

from typing import Any, Dict, Optional


def _set_option(listener, name: str, value: Any) -> None:
    if value is None or value == "":
        return
    if not hasattr(listener, name):
        return
    opt = getattr(listener, name)
    if hasattr(opt, "__set__"):
        opt.__set__(listener, value)
    elif hasattr(opt, "value"):
        opt.value = value
    else:
        setattr(listener, name, value)


def launch_bind_listener(
    framework,
    listener_path: str,
    options: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """
    Load a BIND listener, apply options, connect once, register a session.

    Returns session_id on success, None otherwise.
    """
    if not framework or not hasattr(framework, "module_loader"):
        return None

    listener = framework.module_loader.load_module(listener_path, framework=framework)
    if not listener:
        return None

    opts = dict(options or {})
    # Common aliases
    if opts.get("rhost") and "host" not in opts:
        opts.setdefault("host", opts["rhost"])
    if opts.get("rport") and "port" not in opts:
        opts.setdefault("port", opts["rport"])

    for key, value in opts.items():
        _set_option(listener, key, value)

    try:
        result = listener.run()
    except Exception as exc:
        from core.output_handler import print_error

        print_error(f"BIND listener failed: {exc}")
        return None

    if not result or result is False:
        return None

    if isinstance(result, tuple) and len(result) >= 3:
        connection, target, port = result[0], result[1], result[2]
        extra = result[3] if len(result) > 3 and isinstance(result[3], dict) else {}
        if hasattr(listener, "_create_session_from_connection_data"):
            try:
                port_int = int(port)
            except (TypeError, ValueError):
                port_int = 0
            return listener._create_session_from_connection_data(
                connection, str(target), port_int, extra
            )

    from core.output_handler import print_warning

    print_warning("BIND listener returned an unsupported result format")
    return None
