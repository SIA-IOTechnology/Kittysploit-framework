#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Manage the KittySploit MCP server from the interactive console."""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_error, print_info, print_success, print_warning


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


class McpCommand(BaseCommand):
    """Start / stop / inspect in-process MCP (SSE or streamable-http)."""

    @property
    def name(self) -> str:
        return "mcp"

    @property
    def aliases(self) -> List[str]:
        return ["kittymcp"]

    @property
    def description(self) -> str:
        return "Manage KittySploit MCP server (Cursor / IDE integration)"

    @property
    def usage(self) -> str:
        return (
            "mcp start|stop|status|cursor|help "
            "[--transport sse|streamable-http] [--host HOST] [--port PORT] "
            "[--role ROLE] [--dangerous-consent] [--ollama]"
        )

    @property
    def help_text(self) -> str:
        return """
Manage the Model Context Protocol (MCP) bridge from this KittySploit console.

In-console transports share the live Framework (sessions, modules, workspace).
stdio cannot run inside the interactive CLI — use Cursor's mcp.json (see mcp cursor).

Subcommands:
    start     Start MCP over sse or streamable-http (background thread)
    stop      Stop the in-console MCP server
    status    Show whether MCP is running and on which endpoint
    cursor    Print a Cursor ~/.cursor/mcp.json snippet for stdio
    help      Show this help

Start options:
    --transport sse|streamable-http   Default: streamable-http
    --host HOST                       Default: 127.0.0.1
    --port PORT                       Default: 8765
    --role ROLE                       Repeatable: viewer | operator | admin
                                      (or KITTYMCP_ROLES)
    --dangerous-consent               Allow risky tools (or KITTYMCP_DANGEROUS_CONSENT=1)
    --ollama                          Enable Ollama-assisted planning

Examples:
    mcp start
    mcp start --transport sse --port 8765 --role operator --dangerous-consent
    mcp status
    mcp stop
    mcp cursor
        """

    def get_subcommands(self) -> List[str]:
        return ["start", "stop", "status", "cursor", "help"]

    def execute(self, args: List[str], **kwargs) -> bool:
        if not args or args[0] in ("-h", "--help", "help"):
            self.show_help()
            return True

        sub = args[0].lower()
        rest = args[1:]
        if sub == "start":
            return self._start(rest)
        if sub == "stop":
            return self._stop()
        if sub == "status":
            return self._status()
        if sub == "cursor":
            return self._cursor()
        print_error(f"Unknown subcommand: {sub}")
        print_info("Use: mcp start|stop|status|cursor|help")
        return False

    def _state(self) -> Optional[Dict[str, Any]]:
        return getattr(self.framework, "_mcp_console", None)

    def _set_state(self, state: Optional[Dict[str, Any]]) -> None:
        self.framework._mcp_console = state

    def _start(self, args: List[str]) -> bool:
        existing = self._state()
        if existing and existing.get("running"):
            print_warning(
                f"MCP already running ({existing.get('transport')} "
                f"on {existing.get('host')}:{existing.get('port')})"
            )
            print_info("Use 'mcp stop' first, or 'mcp status'.")
            return True

        parser = argparse.ArgumentParser(prog="mcp start", add_help=True)
        parser.add_argument(
            "--transport",
            choices=("sse", "streamable-http"),
            default="streamable-http",
            help="HTTP MCP transport (stdio is for Cursor via mcp cursor / kittymcp_server.py)",
        )
        parser.add_argument("--host", default="127.0.0.1")
        parser.add_argument("--port", type=int, default=8765)
        parser.add_argument(
            "--role",
            action="append",
            choices=("viewer", "operator", "admin"),
            dest="roles",
            default=None,
            help="RBAC role (repeatable)",
        )
        parser.add_argument(
            "--dangerous-consent",
            action="store_true",
            help="Allow risky MCP tools",
        )
        parser.add_argument(
            "--ollama",
            action="store_true",
            help="Enable Ollama-assisted natural-language planning",
        )

        try:
            parsed = parser.parse_args(args)
        except SystemExit:
            return False

        roles = parsed.roles
        if not roles:
            env_roles = os.environ.get("KITTYMCP_ROLES", "").strip()
            if env_roles:
                roles = [r.strip() for r in env_roles.split(",") if r.strip()]

        dangerous = bool(parsed.dangerous_consent) or _env_truthy("KITTYMCP_DANGEROUS_CONSENT")
        if parsed.ollama:
            os.environ["KITTYMCP_OLLAMA_ENABLED"] = "1"

        try:
            from interfaces.mcp_kittysploit_server import create_mcp_server
            from interfaces.rpc_server import RpcServer
        except ImportError as exc:
            print_error(f"MCP dependencies unavailable: {exc}")
            print_info("Install the 'mcp' package in the KittySploit venv.")
            return False

        # In-process MCP bypasses XML-RPC auth; RBAC + dangerous consent still apply.
        rpc = RpcServer(self.framework, host="127.0.0.1", port=0, api_key=None)
        mcp_app = create_mcp_server(
            rpc,
            host=parsed.host,
            port=parsed.port,
            stdio_transport=False,
            roles=roles,
            dangerous_consent=dangerous,
        )

        state: Dict[str, Any] = {
            "running": False,
            "transport": parsed.transport,
            "host": parsed.host,
            "port": parsed.port,
            "roles": list(roles or []),
            "dangerous_consent": dangerous,
            "thread": None,
            "uvicorn_server": None,
            "rpc": rpc,
            "error": None,
            "started_at": time.time(),
        }
        self._set_state(state)

        def _thread_main() -> None:
            try:
                import anyio
                import uvicorn

                async def _serve() -> None:
                    if parsed.transport == "sse":
                        starlette_app = mcp_app.sse_app()
                    else:
                        starlette_app = mcp_app.streamable_http_app()
                    config = uvicorn.Config(
                        starlette_app,
                        host=parsed.host,
                        port=parsed.port,
                        log_level="warning",
                    )
                    server = uvicorn.Server(config)
                    state["uvicorn_server"] = server
                    state["running"] = True
                    await server.serve()
                anyio.run(_serve)
            except Exception as exc:
                state["error"] = str(exc)
            finally:
                state["running"] = False

        thread = threading.Thread(
            target=_thread_main,
            name="kittysploit-mcp",
            daemon=True,
        )
        state["thread"] = thread
        thread.start()

        # Wait briefly for bind / early failure
        for _ in range(20):
            time.sleep(0.1)
            if state.get("error"):
                print_error(f"MCP failed to start: {state['error']}")
                self._set_state(None)
                return False
            if state.get("running") and state.get("uvicorn_server"):
                break
        else:
            if state.get("error"):
                print_error(f"MCP failed to start: {state['error']}")
                self._set_state(None)
                return False
            if not state.get("running"):
                print_warning("MCP thread started but not yet marked running; check 'mcp status'.")

        url_host = "127.0.0.1" if parsed.host in ("0.0.0.0", "") else parsed.host
        print_success(
            f"MCP started ({parsed.transport}) on http://{url_host}:{parsed.port}"
        )
        if roles:
            print_info(f"Roles: {', '.join(roles)}")
        print_info(f"Dangerous consent: {'yes' if dangerous else 'no'}")
        print_info("This process shares the live console Framework (sessions, modules).")
        print_info("For Cursor stdio integration, run: mcp cursor")
        return True

    def _stop(self) -> bool:
        state = self._state()
        if not state or (not state.get("running") and not state.get("thread")):
            print_info("MCP is not running in this console.")
            return True

        server = state.get("uvicorn_server")
        if server is not None:
            server.should_exit = True
            print_info("Stopping MCP server...")
        else:
            print_warning("No uvicorn handle; waiting for thread exit.")

        thread = state.get("thread")
        if thread is not None and thread.is_alive():
            thread.join(timeout=5.0)
            if thread.is_alive():
                print_warning("MCP thread did not exit within 5s (daemon will die with process).")
                state["running"] = False
                return True

        self._set_state(None)
        print_success("MCP stopped.")
        return True

    def _status(self) -> bool:
        state = self._state()
        if not state:
            print_info("MCP: not running in this console.")
            print_info("Start with: mcp start")
            print_info("Cursor stdio: mcp cursor  (or kittymcp_server.py --transport stdio)")
            return True

        thread = state.get("thread")
        alive = bool(thread and thread.is_alive())
        running = bool(state.get("running")) and alive
        url_host = "127.0.0.1" if state.get("host") in ("0.0.0.0", "") else state.get("host")
        print_info(f"MCP running: {'yes' if running else 'no'}")
        print_info(f"  transport : {state.get('transport')}")
        print_info(f"  endpoint  : http://{url_host}:{state.get('port')}")
        print_info(f"  roles     : {', '.join(state.get('roles') or []) or '(default)'}")
        print_info(f"  dangerous : {'yes' if state.get('dangerous_consent') else 'no'}")
        if state.get("error"):
            print_warning(f"  last error: {state['error']}")
        if state.get("started_at"):
            age = int(time.time() - float(state["started_at"]))
            print_info(f"  uptime    : {age}s")
        return True

    def _cursor(self) -> bool:
        """Print a Cursor mcp.json snippet for the separate stdio process."""
        root = Path(__file__).resolve().parents[3]
        server_script = root / "kittymcp_server.py"
        python = sys.executable

        snippet = {
            "mcpServers": {
                "kittysploit": {
                    "command": str(python),
                    "args": [
                        str(server_script),
                        "--transport",
                        "stdio",
                        "--accept-charter",
                    ],
                    "env": {
                        "KITTYSPLOIT_MASTER_KEY": "your-master-password",
                        "KITTYSPLOIT_MCP_ACCEPT_CHARTER": "1",
                        "KITTYMCP_ROLES": "operator",
                        "KITTYMCP_DANGEROUS_CONSENT": "1",
                    },
                }
            }
        }

        print_info("Cursor uses a separate stdio process (not this console).")
        print_info("Add/merge into ~/.cursor/mcp.json (or project .cursor/mcp.json):")
        print()
        print(json.dumps(snippet, indent=2))
        print()
        print_info(
            "To expose THIS live console instead, run "
            "'mcp start --transport streamable-http' and point an HTTP MCP client at it."
        )
        return True
