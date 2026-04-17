#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KittySploit MCP (Model Context Protocol) server entrypoint.

Use stdio transport for local IDE integration (Cursor spawns this process and talks over
stdin/stdout). MCP requires JSON-RPC on stdout — interactive prompts and normal prints
must not use stdout during startup; this script redirects stdout to stderr until the MCP
layer starts.

Cursor example (`~/.cursor/mcp.json`). Prefer secrets in `env`, not in `args`:

    "kittysploit": {
      "command": "/path/to/Kittysploit-framework/venv/bin/python",
      "args": [
        "/path/to/Kittysploit-framework/kittymcp.py",
        "--transport", "stdio",
        "--accept-charter"
      ],
      "env": {
        "KITTYSPLOIT_MASTER_KEY": "your-master-password",
        "KITTYSPLOIT_MCP_ACCEPT_CHARTER": "1",
        "KITTYMCP_OLLAMA_ENABLED": "1",
        "KITTYMCP_OLLAMA_MODEL": "llama3.1:8b",
        "KITTYMCP_OLLAMA_ENDPOINT": "http://127.0.0.1:11434/api/chat"
      }
    }

If the charter is already accepted and encryption is unlocked the same way, you can omit
`--accept-charter` and `KITTYSPLOIT_MCP_ACCEPT_CHARTER`. First-time stdio setup needs a
master key (or run `kittysploit` CLI once to accept charter and initialize encryption).
"""

import argparse
import logging
import os
import signal
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.utils.venv_helper import ensure_venv

ensure_venv(__file__)

from core.framework.framework import Framework
from core.output_handler import print_error, print_info, print_success
from interfaces.mcp_kittysploit_server import run_mcp_server
from interfaces.rpc_server import RpcServer


def setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        stream=sys.stderr,
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="KittySploit MCP server")
    p.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default="stdio",
        help="MCP transport (stdio is recommended for Cursor / Claude Desktop)",
    )
    p.add_argument("--host", default="127.0.0.1", help="Bind host for sse / streamable-http")
    p.add_argument("--port", type=int, default=8765, help="Port for sse / streamable-http")
    p.add_argument(
        "-m",
        "--master-key",
        help="Master password for encryption (or set KITTYSPLOIT_MASTER_KEY). Required for stdio when encryption is enabled.",
    )
    p.add_argument(
        "--accept-charter",
        action="store_true",
        help="Non-interactive: record Terms of Use acceptance (stdio / automation). Or set KITTYSPLOIT_MCP_ACCEPT_CHARTER=1.",
    )
    p.add_argument(
        "--ollama",
        action="store_true",
        help="Enable Ollama-assisted natural-language planning (or set KITTYMCP_OLLAMA_ENABLED=1).",
    )
    p.add_argument(
        "--ollama-endpoint",
        help="Ollama-compatible chat endpoint (or set KITTYMCP_OLLAMA_ENDPOINT).",
    )
    p.add_argument(
        "--ollama-model",
        help="Ollama model name for natural-language planning (or set KITTYMCP_OLLAMA_MODEL).",
    )
    p.add_argument(
        "--ollama-timeout",
        type=int,
        help="Timeout in seconds for Ollama requests (or set KITTYMCP_OLLAMA_TIMEOUT).",
    )
    p.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    return p.parse_args()


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _resolve_master_key(args: argparse.Namespace) -> Optional[str]:
    if args.master_key:
        return args.master_key
    return os.environ.get("KITTYSPLOIT_MASTER_KEY") or None


def _configure_ollama_env(args: argparse.Namespace) -> None:
    if args.ollama:
        os.environ["KITTYMCP_OLLAMA_ENABLED"] = "1"
    if args.ollama_endpoint:
        os.environ["KITTYMCP_OLLAMA_ENDPOINT"] = args.ollama_endpoint
    if args.ollama_model:
        os.environ["KITTYMCP_OLLAMA_MODEL"] = args.ollama_model
    if args.ollama_timeout is not None:
        os.environ["KITTYMCP_OLLAMA_TIMEOUT"] = str(args.ollama_timeout)


def main() -> int:
    args = parse_args()
    setup_logging(args.debug)
    _configure_ollama_env(args)

    real_stdout = sys.stdout
    use_stdio_mcp = args.transport == "stdio"
    # Keep MCP JSON channel clean: all framework prints during init go to stderr.
    if use_stdio_mcp:
        sys.stdout = sys.stderr

    def handle_sig(_signum, _frame):
        try:
            print("Stopping MCP server...", file=sys.stderr, flush=True)
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sig)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_sig)

    try:
        framework = Framework()
        master_key = _resolve_master_key(args)

        if not framework.check_charter_acceptance():
            if use_stdio_mcp:
                accept = bool(args.accept_charter) or _env_truthy("KITTYSPLOIT_MCP_ACCEPT_CHARTER")
                if accept:
                    if not framework.charter_manager.accept_charter("mcp"):
                        print_error("Failed to record charter acceptance.")
                        return 1
                else:
                    print_error(
                        "Charter not accepted. For stdio MCP, run the CLI once to accept the "
                        "charter, or pass --accept-charter (or set KITTYSPLOIT_MCP_ACCEPT_CHARTER=1)."
                    )
                    return 1
            else:
                print_info("First startup of KittySploit")
                if not framework.prompt_charter_acceptance():
                    print_error("Charter not accepted. Exiting.")
                    return 1

        if not framework.is_encryption_initialized():
            if use_stdio_mcp and not master_key:
                print_error(
                    "Encryption not initialized. Set a master password: use -m / --master-key or "
                    "KITTYSPLOIT_MASTER_KEY, or run the CLI once to set up encryption interactively."
                )
                return 1
            print_info("Setting up encryption...")
            if not framework.initialize_encryption(master_key):
                print_error("Failed to initialize encryption.")
                return 1
        else:
            if use_stdio_mcp and not master_key:
                print_error(
                    "Encryption is configured. For stdio MCP, pass the master password via -m / "
                    "--master-key or KITTYSPLOIT_MASTER_KEY (interactive password prompts break MCP)."
                )
                return 1
            if not framework.load_encryption(master_key):
                print_error(
                    "Failed to load encryption. Provide the correct -m / KITTYSPLOIT_MASTER_KEY."
                )
                return 1

        rpc = RpcServer(framework, host="127.0.0.1", port=0, api_key=None)

        if use_stdio_mcp:
            print_success("KittySploit MCP (stdio) — JSON-RPC on stdout; logs on stderr.")
        else:
            print_success(f"KittySploit MCP ({args.transport}) on {args.host}:{args.port}")

        if use_stdio_mcp:
            sys.stdout = real_stdout

        run_mcp_server(
            rpc,
            transport=args.transport,
            host=args.host,
            port=args.port,
        )
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as e:
        print_error(f"Error: {e}")
        logging.exception("MCP server failed")
        return 1
    finally:
        if use_stdio_mcp:
            sys.stdout = real_stdout


if __name__ == "__main__":
    sys.exit(main())
