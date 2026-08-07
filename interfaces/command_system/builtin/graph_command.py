#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Attack path graph explorer — interactive UI from workspace intelligence."""

from __future__ import annotations

import argparse
import json
import webbrowser

from core.graph.data_loader import load_explorer_graph
from core.graph.explorer_server import DEFAULT_GRAPH_EXPLORER_PORT, GraphExplorerServer
from core.output_handler import print_empty, print_error, print_info, print_success, print_table, print_warning
from interfaces.command_system.base_command import BaseCommand


class GraphCommand(BaseCommand):
    """Launch and export the interactive attack path explorer."""

    @property
    def name(self) -> str:
        return "graph"

    @property
    def description(self) -> str:
        return "Explore attack paths as an interactive graph (host → service → vuln → creds → session → pivot)"

    @property
    def usage(self) -> str:
        return "graph [explore|export|status] [options]"

    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

Subcommands:
    explore     Start the local web UI (default)
    export      Write unified graph JSON to disk
    status      Show whether the explorer server is running

Explore options:
    --host <addr>       Bind address (default: 127.0.0.1)
    --port <n>          Port (default: {DEFAULT_GRAPH_EXPLORER_PORT})
    --source <mode>     campaign | agent | both (default: both)
    --run-id <id>       Agent run checkpoint to use for agent graph
    --max-steps <n>     Campaign graph depth (default: 50)
    --no-browser        Do not open a browser tab automatically

The UI shows confidence, risk, validation modules, and ranked attack paths.
Credential pivot suggestions are displayed only for in-scope destinations.

Examples:
    graph explore
    graph explore --source campaign --port {DEFAULT_GRAPH_EXPLORER_PORT}
    graph explore --source agent --run-id agent_20260807T120000_ab12cd34ef
    graph export --output artifacts/graph/explorer.json
    graph status
        """

    def execute(self, args, **kwargs) -> bool:
        raw = list(args or [])
        if not raw or raw[0].lower() in {"help", "--help", "-h"}:
            print_info(self.help_text)
            return True

        sub = raw[0].lower()
        tail = raw[1:]

        if sub == "status":
            return self._status()
        if sub == "export":
            return self._export(tail)
        if sub in {"explore", "start", "serve"}:
            return self._explore(tail)
        if sub == "stop":
            return self._stop()
        return self._explore(raw)

    def _status(self) -> bool:
        server = getattr(self.framework, "graph_explorer_server", None)
        if server and server.is_running():
            print_success(f"Attack path explorer running at {server.url()}")
            print_info(f"Source: {getattr(server, 'source', 'both')} | max_steps={getattr(server, 'max_steps', 50)}")
            return True
        print_warning("Attack path explorer is not running")
        print_info("Start it with: graph explore")
        return True

    def _stop(self) -> bool:
        server = getattr(self.framework, "graph_explorer_server", None)
        if server and server.is_running():
            server.stop()
            self.framework.graph_explorer_server = None
            print_success("Attack path explorer stopped")
            return True
        print_warning("Attack path explorer is not running")
        return True

    def _export(self, args: list) -> bool:
        parser = argparse.ArgumentParser(prog="graph export", add_help=False)
        parser.add_argument("--output", "-o", default="artifacts/graph/explorer.json")
        parser.add_argument("--source", default="both", choices=["campaign", "agent", "both", "merged"])
        parser.add_argument("--run-id", default="")
        parser.add_argument("--max-steps", type=int, default=50)
        try:
            parsed = parser.parse_args(args)
        except SystemExit:
            return True

        try:
            graph = load_explorer_graph(
                self.framework,
                source=parsed.source,
                max_steps=max(1, parsed.max_steps),
                run_id=parsed.run_id or None,
            )
            output_path = self._resolve_output_path(parsed.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("w", encoding="utf-8") as handle:
                json.dump(graph.to_dict(), handle, indent=2, ensure_ascii=False, default=str)
        except Exception as exc:
            print_error(f"Graph export failed: {exc}")
            return False

        print_success(f"Explorer graph exported to {output_path}")
        self._print_summary(graph.to_dict())
        return True

    def _explore(self, args: list) -> bool:
        parser = argparse.ArgumentParser(prog="graph explore", add_help=False)
        parser.add_argument("--host", default="127.0.0.1")
        parser.add_argument("--port", type=int, default=DEFAULT_GRAPH_EXPLORER_PORT)
        parser.add_argument("--source", default="both", choices=["campaign", "agent", "both", "merged"])
        parser.add_argument("--run-id", default="")
        parser.add_argument("--max-steps", type=int, default=50)
        parser.add_argument("--no-browser", action="store_true")
        try:
            parsed = parser.parse_args(args)
        except SystemExit:
            return True

        existing = getattr(self.framework, "graph_explorer_server", None)
        if existing and existing.is_running():
            print_warning(f"Explorer already running at {existing.url()} — refreshing graph")
            existing.source = parsed.source
            existing.max_steps = max(1, parsed.max_steps)
            existing.run_id = parsed.run_id or None
            existing.refresh_payload()
            print_info(f"Open {existing.url()} in your browser")
            return True

        try:
            server = GraphExplorerServer(
                self.framework,
                host=parsed.host,
                port=parsed.port,
                source=parsed.source,
                max_steps=max(1, parsed.max_steps),
                run_id=parsed.run_id or None,
            )
            server.start()
            self.framework.graph_explorer_server = server
            payload = server.get_payload()
        except OSError as exc:
            print_error(f"Could not bind graph explorer on {parsed.host}:{parsed.port}: {exc}")
            if parsed.port == 8765:
                print_warning("Port 8765 is often used by KittySploit Academy — default explorer port is 9477")
            return False
        except Exception as exc:
            print_error(f"Graph explorer failed to start: {exc}")
            return False

        url = server.url()
        print_success(f"Attack path explorer started at {url}")
        self._print_summary(payload)
        if int(payload.get("summary", {}).get("nodes", len(payload.get("nodes") or [])) or 0) == 0:
            print_warning("Graph is empty — add hosts/vulns to the workspace or run an agent first")
            print_info("Try: host --add <ip>, scanner modules, or agent target.com")
        if not parsed.no_browser:
            try:
                webbrowser.open(url)
            except Exception:
                print_info(f"Open manually: {url}")
        else:
            print_info(f"Open manually: {url}")
        return True

    def _print_summary(self, payload: dict) -> None:
        nodes = payload.get("nodes") or []
        edges = payload.get("edges") or []
        paths = payload.get("paths") or []
        print_info(
            f"Workspace: {payload.get('workspace') or '—'} | "
            f"source={payload.get('source') or 'merged'} | "
            f"nodes={len(nodes)} edges={len(edges)} paths={len(paths)}"
        )
        next_action = payload.get("next_action") if isinstance(payload.get("next_action"), dict) else {}
        if next_action.get("action"):
            print_info(
                f"Next action: {next_action.get('action')} "
                f"(confidence={float(next_action.get('confidence', 0) or 0):.2f})"
            )
        if not paths:
            return
        rows = []
        for index, path in enumerate(paths, start=1):
            label = str(path.get("label") or "")
            confidence = float(path.get("confidence", 0) or 0)
            risk = str(path.get("risk") or "—")
            modules = ", ".join(str(item) for item in (path.get("modules") or []) if item) or "—"
            rows.append([
                str(index),
                label,
                f"{confidence:.0%}",
                risk,
                modules,
            ])
        print_empty()
        print_table(
            ["#", "Path", "Conf.", "Risk", "Modules"],
            rows,
            expand_to_terminal=True,
            # Modules absorbs leftover terminal width; Path stays compact for short labels.
            expand_headers=("Modules",),
            wrap_extra_headers=("Modules",),
            prefer_single_line=True,
            protect_full_width_headers=("Path",),
            column_max_widths={"#": 3, "Conf.": 5, "Risk": 8, "Path": 42},
            column_min_widths={"Modules": 48, "Path": 20},
        )

    @staticmethod
    def _resolve_output_path(raw: str):
        from pathlib import Path

        return Path(str(raw or "artifacts/graph/explorer.json")).expanduser()
