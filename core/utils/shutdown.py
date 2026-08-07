#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Best-effort framework shutdown helpers."""

from __future__ import annotations

from typing import Any, Optional


def _safe_close(obj: Any, method: str = "close") -> None:
    if obj is None:
        return
    closer = getattr(obj, method, None)
    if not callable(closer):
        return
    try:
        closer()
    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception:
        pass


def shutdown_http_clients() -> None:
    """Close shared HTTP sessions before interpreter exit."""
    try:
        from lib.scanner import http_pool

        http_pool.force_close_active_session()
    except Exception:
        pass


def graceful_shutdown(framework: Optional[Any] = None) -> None:
    """Release runtime resources while the interpreter is still healthy."""
    if framework is not None:
        cleanup = getattr(framework, "cleanup", None)
        if callable(cleanup):
            try:
                cleanup()
            except Exception:
                pass

        proxy_manager = getattr(framework, "proxy_manager", None)
        if proxy_manager is not None:
            try:
                if getattr(proxy_manager, "is_running", False):
                    proxy_manager.stop()
            except Exception:
                pass

        graph_server = getattr(framework, "graph_explorer_server", None)
        if graph_server is not None:
            try:
                if getattr(graph_server, "is_running", lambda: False)():
                    graph_server.stop()
            except Exception:
                pass

        room_client = getattr(framework, "room_client", None)
        if room_client is not None:
            _safe_close(getattr(room_client, "session", None))

    shutdown_http_clients()
