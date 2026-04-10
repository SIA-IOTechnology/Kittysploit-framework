#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KittySploit MCP (Model Context Protocol) server.

Exposes structured tools so LLMs can drive the framework via explicit calls (list modules,
read options, run). Natural-language requests are interpreted by the model, which maps
them to tools and parameters.
"""

from __future__ import annotations

import base64
import functools
import json
import logging
import sys
import time
from typing import Any, Callable, Dict, List, Literal, Optional, TypeVar

from mcp.server.fastmcp import FastMCP

from interfaces.rpc_server import RpcServer

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def _stdio_safe(stdio_transport: bool) -> Callable[[F], F]:
    """
    MCP stdio: only JSON-RPC may use stdout. Redirect framework print() to stderr during tools.
    """

    def deco(fn: F) -> F:
        if not stdio_transport:
            return fn

        @functools.wraps(fn)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            old_out = sys.stdout
            sys.stdout = sys.stderr
            try:
                return fn(*args, **kwargs)
            finally:
                sys.stdout = old_out

        return wrapped  # type: ignore[return-value]

    return deco

MCP_INSTRUCTIONS = """\
KittySploit MCP — remote control for the penetration testing framework.

Rules:
- Use only against systems and networks you are explicitly authorized to test.
- Typical flow: search or list a module → read its options → set RHOST/target/port/etc. → run → poll logs with the returned client_id.
- The "discreet" operation profile adjusts common options (timeout, threads, verbose) when they exist on the module.
- The interpreter tool runs Python inside KittySploit's context — use with extreme care.
"""


def _safe_json(obj: Any) -> Any:
    """Best-effort JSON-serializable view for tool outputs."""
    try:
        json.dumps(obj, default=str)
        return obj
    except TypeError:
        return json.loads(json.dumps(obj, default=str))


def _decode_module_logs(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Add text_decoded alongside base64 text from RPC get_module_logs."""
    if not isinstance(raw, dict):
        return {"error": "invalid_logs_payload"}
    out = dict(raw)
    decoded_rows: List[Dict[str, Any]] = []
    for item in raw.get("outputs") or []:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        t = row.get("text")
        if isinstance(t, str) and t:
            try:
                row["text_decoded"] = base64.b64decode(t).decode("utf-8", errors="replace")
            except Exception:
                row["text_decoded"] = None
        decoded_rows.append(row)
    out["outputs"] = decoded_rows
    return out


def _merge_operation_profile(
    rpc: RpcServer,
    module_name: str,
    params: Optional[Dict[str, Any]],
    profile: Optional[str],
) -> Dict[str, Any]:
    """Merge optional operation profile into params using only options that exist on the module."""
    merged: Dict[str, Any] = dict(params or {})
    if not profile or profile.strip().lower() in ("", "normal", "default"):
        return merged

    module = rpc.framework.module_loader.load_module(module_name)
    if not module:
        return merged

    opts = getattr(module, "exploit_attributes", None) or {}
    if not isinstance(opts, dict):
        return merged

    keys_by_lower = {str(k).lower(): k for k in opts.keys()}

    def set_if(names: List[str], value: Any) -> None:
        for name in names:
            if name in opts:
                merged[name] = value
                return
            ln = name.lower()
            if ln in keys_by_lower:
                merged[keys_by_lower[ln]] = value
                return

    pl = profile.strip().lower()
    if pl == "discreet":
        set_if(["timeout", "TIMEOUT"], "30")
        set_if(["threads", "THREADS"], "1")
        set_if(["verbose", "VERBOSE"], "false")
    elif pl == "aggressive":
        set_if(["timeout", "TIMEOUT"], "5")
        set_if(["threads", "THREADS"], "16")
        set_if(["verbose", "VERBOSE"], "true")

    return merged


def create_mcp_server(
    rpc: RpcServer,
    host: str = "127.0.0.1",
    port: int = 8765,
    stdio_transport: bool = False,
) -> FastMCP:
    """
    Build a FastMCP server bound to an existing RpcServer instance (no need to start XML-RPC).
    """
    mcp = FastMCP(
        name="KittySploit",
        instructions=MCP_INSTRUCTIONS,
        host=host,
        port=port,
    )

    safe = _stdio_safe(stdio_transport)
    module_cache: Dict[str, Any] = {"expires_at": 0.0, "data": None}
    module_info_cache: Dict[str, Dict[str, Any]] = {}
    module_options_cache: Dict[str, Dict[str, Any]] = {}
    cache_ttl = 20.0

    def _invalidate_module_caches() -> None:
        module_cache["expires_at"] = 0.0
        module_cache["data"] = None
        module_info_cache.clear()
        module_options_cache.clear()

    def _get_modules_cached() -> Dict[str, Any]:
        now = time.monotonic()
        if module_cache["data"] is not None and now < float(module_cache["expires_at"]):
            cached = module_cache["data"]
            return cached if isinstance(cached, dict) else {}
        all_modules = rpc.get_modules()
        if not isinstance(all_modules, dict):
            return {}
        module_cache["data"] = all_modules
        module_cache["expires_at"] = now + cache_ttl
        return all_modules

    @mcp.tool()
    @safe
    def ks_health() -> Dict[str, Any]:
        """Framework status and capabilities (interpreter, runtime kernel)."""
        return _safe_json(rpc.health())

    @mcp.tool()
    @safe
    def ks_list_modules(query: Optional[str] = None, limit: int = 200) -> Dict[str, Any]:
        """
        List available modules with name and description.
        Optional `query` filters by substring (case-insensitive) on path, name, or description.
        """
        all_modules = _get_modules_cached()
        if not isinstance(all_modules, dict):
            return {"error": "get_modules_failed", "raw": str(all_modules)}

        q = (query or "").strip().lower()
        items: List[Dict[str, Any]] = []
        for path, meta in all_modules.items():
            if not isinstance(meta, dict):
                meta = {"name": path, "description": ""}
            name = str(meta.get("name", path))
            desc = str(meta.get("description", ""))
            if q:
                blob = f"{path} {name} {desc}".lower()
                if q not in blob:
                    continue
            items.append({"path": path, "name": name, "description": desc})
            if len(items) >= max(1, min(limit, 500)):
                break

        return {"count": len(items), "modules": items}

    @mcp.tool()
    @safe
    def ks_get_module_info(module_path: str) -> Dict[str, Any]:
        """Module metadata and options (path e.g. 'scanner/http/wordpress_detect')."""
        if module_path in module_info_cache:
            return _safe_json(module_info_cache[module_path])
        module = rpc.framework.module_loader.load_module(module_path)
        if not module:
            return {"error": "Module not found", "module_path": module_path}
        if hasattr(module, "get_info"):
            info = _safe_json(module.get_info())
            if isinstance(info, dict):
                module_info_cache[module_path] = info
            return info
        info = {
            "name": getattr(module, "name", module_path),
            "description": getattr(module, "description", ""),
            "options": getattr(module, "exploit_attributes", {}),
        }
        module_info_cache[module_path] = info
        return info

    @mcp.tool()
    @safe
    def ks_get_module_options(module_path: str) -> Dict[str, Any]:
        """Module option schema (names, defaults, required flags, descriptions)."""
        if module_path in module_options_cache:
            return _safe_json(module_options_cache[module_path])
        module = rpc.framework.module_loader.load_module(module_path)
        if not module:
            return {"error": "Module not found", "module_path": module_path}
        opts = getattr(module, "get_options", lambda: {})()
        data = _safe_json(
            {
                "name": getattr(module, "name", module_path),
                "module_path": module_path,
                "options": opts,
            }
        )
        if isinstance(data, dict):
            module_options_cache[module_path] = data
        return data

    @mcp.tool()
    @safe
    def ks_run_module(
        module_path: str,
        options: Optional[Dict[str, Any]] = None,
        use_runtime_kernel: bool = False,
        operation_profile: Optional[Literal["normal", "discreet", "aggressive"]] = None,
    ) -> Dict[str, Any]:
        """
        Run a module in the background. Returns a `client_id` for ks_get_module_logs.

        `options` are module option names (e.g. RHOST, target, port).
        `operation_profile`: discreet = slower / quieter where supported; aggressive = shorter
        timeouts / more parallelism where supported.
        """
        merged = _merge_operation_profile(rpc, module_path, options, operation_profile)
        result = rpc.run_module(module_path, merged, use_runtime_kernel=use_runtime_kernel)
        out = _safe_json(result)
        # Running modules can modify framework state/options; keep caches fresh.
        _invalidate_module_caches()
        if isinstance(out, dict) and operation_profile:
            out["resolved_options"] = merged
        return out if isinstance(out, dict) else {"result": out}

    @mcp.tool()
    @safe
    def ks_get_module_logs(client_id: str, decode_text: bool = True) -> Dict[str, Any]:
        """Fetch output from a run started with ks_run_module (stdout/stderr/errors)."""
        raw = rpc.get_module_logs(client_id)
        if decode_text:
            return _safe_json(_decode_module_logs(raw if isinstance(raw, dict) else {"outputs": []}))
        return _safe_json(raw)

    @mcp.tool()
    @safe
    def ks_execute_interpreter(code: str, session_id: str = "mcp") -> Dict[str, Any]:
        """
        Execute Python in the KittySploit interpreter (persistent state per session_id).
        Dangerous: can affect the framework and host depending on the code.
        """
        return _safe_json(rpc.execute_interpreter(code, session_id=session_id))

    @mcp.tool()
    @safe
    def ks_list_workspaces() -> Any:
        """List framework workspaces."""
        return _safe_json(rpc.list_workspaces())

    @mcp.tool()
    @safe
    def ks_switch_workspace(name: str) -> Any:
        """Switch the active workspace."""
        return _safe_json(rpc.switch_workspace(name))

    return mcp


def run_mcp_server(
    rpc: RpcServer,
    transport: Literal["stdio", "sse", "streamable-http"] = "stdio",
    host: str = "127.0.0.1",
    port: int = 8765,
) -> None:
    """Run blocking MCP transport (stdio by default for Cursor / Claude Desktop)."""
    app = create_mcp_server(
        rpc,
        host=host,
        port=port,
        stdio_transport=(transport == "stdio"),
    )
    logger.info("Starting KittySploit MCP transport=%s host=%s port=%s", transport, host, port)
    app.run(transport=transport)
