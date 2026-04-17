#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KittySploit MCP (Model Context Protocol) server.

Exposes structured tools so LLMs can drive the framework via explicit calls, native
framework commands, and a natural-language planning layer.
"""

from __future__ import annotations

import base64
import functools
import json
import logging
import sys
from typing import Any, Callable, Dict, List, Literal, Optional, TypeVar

from mcp.server.fastmcp import FastMCP

from interfaces.mcp_kittysploit_bridge import MCPCommandBridge, NaturalLanguagePlanner
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
- For free-form user requests, start with `ks_plan_natural_request` to extract intent,
  targets, module candidates, and native command/tool suggestions.
- Typical flow: search or plan → inspect a module → set RHOST/target/port/etc. → run →
  poll logs with the returned client_id.
- `ks_execute_command` can drive the framework through its native CLI commands when that
  is more natural than raw module RPC calls.
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
    command_bridge = MCPCommandBridge(rpc.framework)
    natural_bridge = NaturalLanguagePlanner(rpc.framework, command_bridge=command_bridge)
    module_info_cache: Dict[str, Dict[str, Any]] = {}
    module_options_cache: Dict[str, Dict[str, Any]] = {}

    def _invalidate_module_caches() -> None:
        natural_bridge.invalidate_caches()
        module_info_cache.clear()
        module_options_cache.clear()

    @mcp.tool()
    @safe
    def ks_health() -> Dict[str, Any]:
        """Framework status and capabilities (interpreter, runtime kernel)."""
        raw_health = rpc.health()
        health = dict(raw_health) if isinstance(raw_health, dict) else {"raw": raw_health}
        health["state"] = command_bridge.get_state()
        return _safe_json(health)

    @mcp.tool()
    @safe
    def ks_framework_state() -> Dict[str, Any]:
        """Current workspace, current module, and session counters."""
        return _safe_json(command_bridge.get_state())

    @mcp.tool()
    @safe
    def ks_ollama_status() -> Dict[str, Any]:
        """Show whether Ollama-assisted planning is enabled for kittymcp."""
        return _safe_json(natural_bridge.ollama_status())

    @mcp.tool()
    @safe
    def ks_list_modules(query: Optional[str] = None, limit: int = 200) -> Dict[str, Any]:
        """
        Ranked module search.

        When `query` is provided, this uses the natural-language planner to score modules from
        path/name/description/tags/type hints instead of a raw substring filter.
        """
        if query and query.strip():
            return _safe_json(
                natural_bridge.search_modules(
                    query,
                    max_candidates=max(1, min(limit, 500)),
                )
            )
        return _safe_json(
            natural_bridge.list_modules(limit=max(1, min(limit, 500)))
        )

    @mcp.tool()
    @safe
    def ks_get_module_info(module_path: str) -> Dict[str, Any]:
        """Rich module metadata with normalized options and inferred option hints."""
        if module_path in module_info_cache:
            return _safe_json(module_info_cache[module_path])
        info = natural_bridge.get_module_details(module_path)
        if isinstance(info, dict) and "error" not in info:
            module_info_cache[module_path] = info
        return _safe_json(info)

    @mcp.tool()
    @safe
    def ks_get_module_options(module_path: str) -> Dict[str, Any]:
        """Normalized module option schema with required/missing sets and semantic roles."""
        if module_path in module_options_cache:
            return _safe_json(module_options_cache[module_path])
        details = natural_bridge.get_module_details(module_path)
        if "error" in details:
            return _safe_json(details)
        data = {
            "module_path": details.get("module_path"),
            "name": details.get("name"),
            "type": details.get("type"),
            "options": details.get("options"),
            "required_options": details.get("required_options"),
            "missing_options": details.get("missing_options"),
            "option_hints": details.get("option_hints"),
        }
        if isinstance(data, dict):
            module_options_cache[module_path] = data
        return _safe_json(data)

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
    def ks_list_commands() -> Dict[str, Any]:
        """List native framework commands with usage, help text, and safety classification."""
        return _safe_json(command_bridge.list_commands())

    @mcp.tool()
    @safe
    def ks_get_command_help(command_name: str) -> Dict[str, Any]:
        """Detailed help for a native framework command."""
        return _safe_json(command_bridge.get_command_help(command_name))

    @mcp.tool()
    @safe
    def ks_execute_command(command_line: str, allow_dangerous: bool = False) -> Dict[str, Any]:
        """
        Execute a native KittySploit command line.

        Dangerous or interactive commands are blocked unless `allow_dangerous=true`, and some
        interactive commands stay blocked entirely from MCP.
        """
        result = command_bridge.execute_command(
            command_line,
            allow_dangerous=allow_dangerous,
        )
        if result.get("status") in ("ok", "failed"):
            _invalidate_module_caches()
        return _safe_json(result)

    @mcp.tool()
    @safe
    def ks_plan_natural_request(
        request: str,
        execute_safe_command: bool = False,
        max_candidates: int = 6,
        prefer_ollama: bool = True,
    ) -> Dict[str, Any]:
        """
        Parse a free-form user request into intent, target, ranked modules, native commands,
        and recommended MCP tool calls.
        """
        result = natural_bridge.plan_request(
            request,
            max_candidates=max_candidates,
            execute_safe_command=execute_safe_command,
            prefer_ollama=prefer_ollama,
        )
        if result.get("executed_command"):
            _invalidate_module_caches()
        return _safe_json(result)

    @mcp.tool()
    @safe
    def ks_execute_natural_request(
        request: str,
        allow_dangerous: bool = False,
        prefer_ollama: bool = True,
        dry_run: bool = False,
        max_candidates: int = 6,
    ) -> Dict[str, Any]:
        """
        Translate a natural-language request into KittySploit commands, then optionally
        execute the first recommended command.
        """
        result = natural_bridge.plan_request(
            request,
            max_candidates=max_candidates,
            execute_recommended=not dry_run,
            allow_dangerous=allow_dangerous,
            prefer_ollama=prefer_ollama,
        )
        if result.get("executed_command"):
            _invalidate_module_caches()
        return _safe_json(result)

    @mcp.tool()
    @safe
    def ks_list_workspaces() -> Any:
        """List framework workspaces and identify the current one."""
        return _safe_json(
            {
                "current": command_bridge.get_state().get("workspace"),
                "workspaces": rpc.list_workspaces(),
            }
        )

    @mcp.tool()
    @safe
    def ks_switch_workspace(name: str) -> Any:
        """Switch the active workspace."""
        result = rpc.switch_workspace(name)
        _invalidate_module_caches()
        return _safe_json(
            {
                "result": result,
                "current": command_bridge.get_state().get("workspace"),
            }
        )

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
