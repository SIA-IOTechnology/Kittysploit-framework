#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Native KittySploit natural-language client.

This client avoids external MCP tools by talking directly to the same natural-language
planner and command bridge used by kittymcp.
"""

import argparse
import itertools
import logging
import os
import sys
import time
from threading import Event, Thread
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.utils.venv_helper import ensure_venv

ensure_venv(__file__)

from core.framework.framework import Framework
from core.output_handler import print_error, print_info, print_success, print_warning
from interfaces.mcp_kittysploit_bridge import MCPCommandBridge, NaturalLanguagePlanner


def setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        stream=sys.stderr,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="KittySploit natural-language client")
    parser.add_argument(
        "request",
        nargs="*",
        help="Optional natural-language request. If omitted, start interactive mode.",
    )
    parser.add_argument(
        "-m",
        "--master-key",
        help="Master password for encryption (or set KITTYSPLOIT_MASTER_KEY).",
    )
    parser.add_argument(
        "--accept-charter",
        action="store_true",
        help="Non-interactive: record Terms of Use acceptance (or set KITTYSPLOIT_MCP_ACCEPT_CHARTER=1).",
    )
    parser.add_argument(
        "--ollama",
        action="store_true",
        help="Enable Ollama-assisted natural-language planning.",
    )
    parser.add_argument("--ollama-endpoint", help="Ollama-compatible chat endpoint.")
    parser.add_argument("--ollama-model", help="Ollama model name.")
    parser.add_argument("--ollama-timeout", type=int, help="Ollama request timeout in seconds.")
    parser.add_argument(
        "--no-ollama",
        action="store_true",
        help="Disable Ollama even if KITTYMCP_OLLAMA_ENABLED is set.",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="Execute the first recommended command for the request.",
    )
    parser.add_argument(
        "--allow-dangerous",
        action="store_true",
        help="Allow dangerous commands when using --run or /run.",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=6,
        help="Maximum module candidates kept in the plan.",
    )
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _resolve_master_key(args: argparse.Namespace) -> Optional[str]:
    if args.master_key:
        return args.master_key
    return os.environ.get("KITTYSPLOIT_MASTER_KEY") or None


def _configure_ollama_env(args: argparse.Namespace) -> bool:
    if args.no_ollama:
        os.environ["KITTYMCP_OLLAMA_ENABLED"] = "0"
        return False
    if args.ollama:
        os.environ["KITTYMCP_OLLAMA_ENABLED"] = "1"
    if args.ollama_endpoint:
        os.environ["KITTYMCP_OLLAMA_ENDPOINT"] = args.ollama_endpoint
    if args.ollama_model:
        os.environ["KITTYMCP_OLLAMA_MODEL"] = args.ollama_model
    if args.ollama_timeout is not None:
        os.environ["KITTYMCP_OLLAMA_TIMEOUT"] = str(args.ollama_timeout)
    return _env_truthy("KITTYMCP_OLLAMA_ENABLED")


def _bootstrap_framework(args: argparse.Namespace) -> Optional[Framework]:
    framework = Framework()
    master_key = _resolve_master_key(args)

    if not framework.check_charter_acceptance():
        accept = bool(args.accept_charter) or _env_truthy("KITTYSPLOIT_MCP_ACCEPT_CHARTER")
        if accept:
            if not framework.charter_manager.accept_charter("mcp-client"):
                print_error("Failed to record charter acceptance.")
                return None
        else:
            print_error(
                "Charter not accepted. Run the CLI once to accept it, or pass --accept-charter "
                "(or set KITTYSPLOIT_MCP_ACCEPT_CHARTER=1)."
            )
            return None

    if not framework.is_encryption_initialized():
        if not master_key:
            print_error(
                "Encryption not initialized. Use --master-key / KITTYSPLOIT_MASTER_KEY, "
                "or run kittysploit once to initialize it interactively."
            )
            return None
        print_info("Setting up encryption...")
        if not framework.initialize_encryption(master_key):
            print_error("Failed to initialize encryption.")
            return None
    else:
        if not master_key:
            print_error(
                "Encryption is configured. Pass --master-key or KITTYSPLOIT_MASTER_KEY."
            )
            return None
        if not framework.load_encryption(master_key):
            print_error("Failed to load encryption. Check the provided master key.")
            return None

    return framework


def _print_state(command_bridge: MCPCommandBridge) -> None:
    state = command_bridge.get_state()
    print_info("")
    print_info("State")
    print_info(f"Workspace: {state.get('workspace')}")
    current_module = state.get("current_module") or {}
    if current_module:
        print_info(f"Current module: {current_module.get('path') or current_module.get('name')}")
    else:
        print_info("Current module: none")
    sessions = state.get("sessions") or {}
    print_info(
        f"Sessions: standard={sessions.get('standard', 0)} browser={sessions.get('browser', 0)}"
    )


def _print_plan(plan: Dict[str, Any]) -> None:
    parsed = plan.get("parsed_request") or {}
    print_info("")
    print_info("Interpretation")
    print_info(f"Intent: {parsed.get('intent') or 'unknown'}")
    target = (parsed.get("target") or {}).get("normalized") or (parsed.get("target") or {}).get("raw")
    if target:
        print_info(f"Target: {target}")

    ollama = plan.get("ollama") or {}
    ollama_search_assist = plan.get("ollama_search_assist") or {}
    ollama_plan = plan.get("ollama_plan") or {}
    framework_overview = plan.get("framework_overview") or {}
    if ollama.get("enabled"):
        if ollama_plan:
            print_success(
                f"Ollama: active ({ollama.get('model')} @ {ollama.get('endpoint')})"
            )
            rationale = str(ollama_plan.get("rationale") or "").strip()
            if rationale:
                print_info(f"Rationale: {rationale}")
        else:
            print_warning(
                f"Ollama enabled but unavailable: {ollama.get('last_error') or 'no response'}"
            )

    if ollama_search_assist:
        rewritten = str(ollama_search_assist.get("rewritten_request") or "").strip()
        terms = ollama_search_assist.get("search_terms") or []
        boost_terms = ollama_search_assist.get("boost_terms") or []
        families = ollama_search_assist.get("module_types") or []
        rationale = str(ollama_search_assist.get("rationale") or "").strip()
        print_info("")
        print_info("Ollama search assist")
        if rewritten:
            print_info(f"Rewritten: {rewritten}")
        if terms:
            print_info(f"Search terms: {', '.join(terms)}")
        if boost_terms:
            print_info(f"Boost terms: {', '.join(boost_terms)}")
        if families:
            print_info(f"Module families: {', '.join(families)}")
        if rationale:
            print_info(f"Why: {rationale}")

    if parsed.get("intent") == "framework_info":
        answer = str(ollama_plan.get("answer") or "").strip()
        summary = str(framework_overview.get("summary") or "").strip()
        highlights = framework_overview.get("highlights") or []
        print_info("")
        print_info("Framework overview")
        if answer:
            print_info(answer)
        elif summary:
            print_info(summary)
        for item in highlights[:4]:
            print_info(f"- {item}")
        hints = framework_overview.get("documentation_hints") or []
        if hints:
            print_info("")
            print_info("Docs")
            for item in hints[:4]:
                print_info(f"- {item}")
        return

    modules = plan.get("recommended_modules") or []
    if modules:
        print_info("")
        print_info("Recommended modules")
        for idx, module in enumerate(modules[:5], start=1):
            line = f"{idx}. {module.get('path')} ({module.get('type')})"
            why = ", ".join(module.get("why") or [])
            print_info(line)
            if why:
                print_info(f"   {why}")

    commands = plan.get("recommended_commands") or []
    if commands:
        print_info("")
        print_info("Recommended commands")
        for idx, item in enumerate(commands[:8], start=1):
            print_info(f"{idx}. {item.get('command')}")
            reason = str(item.get("reason") or "").strip()
            if reason:
                print_info(f"   {reason}")

    executed = plan.get("executed_command")
    if executed:
        print_info("")
        print_info("Execution")
        print_info(f"Status: {executed.get('status')}")
        if executed.get("stdout"):
            print(executed["stdout"], end="" if executed["stdout"].endswith("\n") else "\n")
        if executed.get("stderr"):
            print(executed["stderr"], end="" if executed["stderr"].endswith("\n") else "\n", file=sys.stderr)


class _LoadingIndicator:
    def __init__(self, message: str) -> None:
        self.message = message
        self._stop_event = Event()
        self._thread: Optional[Thread] = None
        self._active = False

    def __enter__(self) -> "_LoadingIndicator":
        if not sys.stdout.isatty():
            return self
        self._active = True
        self._thread = Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if not self._active:
            return
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join()
        sys.stdout.write("\r" + (" " * (len(self.message) + 6)) + "\r")
        sys.stdout.flush()

    def _run(self) -> None:
        for char in itertools.cycle(["|", "/", "-", "\\"]):
            if self._stop_event.is_set():
                return
            sys.stdout.write(f"\r{self.message} {char}")
            sys.stdout.flush()
            time.sleep(0.1)


def _handle_request(
    planner: NaturalLanguagePlanner,
    command_bridge: MCPCommandBridge,
    request: str,
    execute: bool,
    allow_dangerous: bool,
    max_candidates: int,
) -> None:
    if not request.strip():
        return
    if request.strip() == "/state":
        _print_state(command_bridge)
        return
    if request.strip() == "/help":
        print_info("")
        print_info("Commands")
        print_info("/help               Show this help")
        print_info("/state              Show workspace/module/session state")
        print_info("/plan <request>     Plan only")
        print_info("/run <request>      Plan then execute the first recommended command")
        print_info("/exit               Quit")
        return
    if request.strip() in ("/exit", "/quit"):
        raise EOFError

    effective_execute = execute
    effective_request = request.strip()
    if effective_request.startswith("/plan "):
        effective_request = effective_request[6:].strip()
        effective_execute = False
    elif effective_request.startswith("/run "):
        effective_request = effective_request[5:].strip()
        effective_execute = True

    use_spinner = bool(getattr(planner, "ollama_enabled", False))
    if use_spinner:
        print_info("Consulting Ollama...")
    with _LoadingIndicator("Searching...") if use_spinner else _LoadingIndicator(""):
        plan = planner.plan_request(
            effective_request,
            max_candidates=max_candidates,
            execute_recommended=effective_execute,
            allow_dangerous=allow_dangerous,
            prefer_ollama=True,
        )
    _print_plan(plan)


def _interactive_loop(
    planner: NaturalLanguagePlanner,
    command_bridge: MCPCommandBridge,
    args: argparse.Namespace,
) -> int:
    print_success("KittyMCP client ready. Type natural requests directly.")
    print_info("Use /help for commands.")
    while True:
        try:
            request = input("kittymcp> ")
        except EOFError:
            print_info("")
            return 0
        except KeyboardInterrupt:
            print_info("")
            return 0

        try:
            _handle_request(
                planner,
                command_bridge,
                request,
                execute=args.run,
                allow_dangerous=args.allow_dangerous,
                max_candidates=args.max_candidates,
            )
        except EOFError:
            return 0
        except Exception as exc:
            print_error(f"Request failed: {exc}")


def main() -> int:
    args = parse_args()
    setup_logging(args.debug)
    ollama_enabled = _configure_ollama_env(args)

    framework = _bootstrap_framework(args)
    if framework is None:
        return 1

    command_bridge = MCPCommandBridge(framework)
    planner = NaturalLanguagePlanner(
        framework,
        command_bridge=command_bridge,
        ollama_enabled=ollama_enabled,
    )

    if ollama_enabled:
        print_success(
            f"Ollama planning enabled: {planner.ollama_model} @ {planner.ollama_endpoint}"
        )
    else:
        print_info("Ollama planning disabled. Using local heuristic planning.")

    request = " ".join(args.request).strip()
    if request:
        try:
            _handle_request(
                planner,
                command_bridge,
                request,
                execute=args.run,
                allow_dangerous=args.allow_dangerous,
                max_candidates=args.max_candidates,
            )
            return 0
        except Exception as exc:
            print_error(f"Request failed: {exc}")
            return 1

    return _interactive_loop(planner, command_bridge, args)


if __name__ == "__main__":
    sys.exit(main())
