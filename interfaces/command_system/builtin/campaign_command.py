#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Campaign command — attack graph and authorized engagement planning."""

from __future__ import annotations

import argparse

from core.campaign import CampaignGraphBuilder
from core.output_handler import print_empty, print_error, print_info, print_success, print_table, print_warning
from interfaces.command_system.base_command import BaseCommand


class CampaignCommand(BaseCommand):
    """Build authorized attack graphs from the active workspace."""

    VALID_FORMATS = ("graph", "plan", "dry_run", "timeline", "report", "navigator", "all")

    @property
    def name(self) -> str:
        return "campaign"

    @property
    def description(self) -> str:
        return "Build authorized attack graphs and campaign plans from workspace data"

    @property
    def usage(self) -> str:
        return "campaign [--output <dir>] [--formats <list>] [--max-steps N] [--force] [--preview]"

    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

Reads the current workspace (hosts, services, vulnerabilities, sessions, browser
sessions from `browser_server`) and produces a structured attack plan — not an
auto-run. Use it to prepare and review an engagement before executing modules
manually or with your team.

Options:
    --output, -o <dir>      Base output directory (default: artifacts/campaigns)
    --formats <list>        Comma-separated: {", ".join(self.VALID_FORMATS)}
    --max-steps <n>         Maximum graph nodes (default: 50)
    --force                 Overwrite existing campaign directory
    --preview               Print graph summary without writing files

Outputs (under <output>/<workspace>/):
    graph.json                  Full attack graph
    plan_executable.json        Suggested use/set/run command sequence
    plan_dry_run.json           Same plan flagged for rehearsal
    timeline.json               Ordered schedule with evidence checkpoints
    report.md                   Human-readable engagement report
    attack_navigator_layer.json MITRE ATT&CK Navigator overlay

Examples:
    campaign
    campaign --preview
    campaign --formats plan,report,navigator --max-steps 25
    campaign build --force
        """

    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="campaign",
            description=self.description,
            add_help=True,
        )
        parser.add_argument("--output", "-o", default=str(CampaignGraphBuilder.DEFAULT_OUTPUT_DIR))
        parser.add_argument("--formats", default="all", help="Comma-separated output formats")
        parser.add_argument("--max-steps", type=int, default=50)
        parser.add_argument("--force", action="store_true")
        parser.add_argument("--preview", action="store_true")
        return parser

    def execute(self, args, **kwargs) -> bool:
        raw = list(args or [])
        if not raw or raw[0].lower() in ("help", "--help", "-h"):
            print_info(self.help_text)
            return True
        if raw[0].lower() == "build":
            raw = raw[1:]

        try:
            parsed = self.parser.parse_args(raw)
        except SystemExit:
            return True

        try:
            formats = self._parse_formats(parsed.formats)
        except ValueError as exc:
            print_error(str(exc))
            return False

        builder = CampaignGraphBuilder(self.framework)

        try:
            graph = builder.build(max_steps=max(1, parsed.max_steps))
        except Exception as exc:
            print_error(f"Campaign build failed: {exc}")
            return False

        if parsed.preview:
            self._print_preview(graph)
            return True

        try:
            root = builder.write_artifacts(
                graph,
                output_dir=parsed.output,
                formats=formats,
                force=parsed.force,
            )
        except FileExistsError as exc:
            print_error(str(exc))
            return False
        except Exception as exc:
            print_error(f"Could not write campaign artifacts: {exc}")
            return False

        print_success(f"Campaign graph written to {root}")
        self._print_preview(graph)
        return True

    def _parse_formats(self, raw: str):
        parts = [p.strip().lower() for p in (raw or "all").split(",") if p.strip()]
        if "all" in parts:
            return None
        invalid = [p for p in parts if p not in self.VALID_FORMATS]
        if invalid:
            raise ValueError(f"Unknown formats: {', '.join(invalid)}")
        return parts

    def _print_preview(self, graph) -> None:
        summary = graph.summary or {}
        print_info(f"Workspace: {graph.workspace} (id={graph.workspace_id})")
        print_info(
            f"Steps: {summary.get('total_steps', len(graph.nodes))} "
            f"(in-scope: {summary.get('in_scope_steps', 0)}, "
            f"high-risk: {summary.get('high_risk_steps', 0)})"
        )
        ws_hosts = summary.get("workspace_hosts", 0)
        ws_services = summary.get("workspace_services", 0)
        if ws_hosts or ws_services:
            print_info(f"Workspace intel: {ws_hosts} host(s), {ws_services} service(s) in database")
        browser_sessions = summary.get("browser_sessions", 0)
        if browser_sessions:
            running = "running" if summary.get("browser_server_running") else "stopped"
            print_info(f"Browser C2: {browser_sessions} session(s), browser_server {running}")
        if ws_services == 0 and graph.nodes:
            print_info(
                "Tip: portscan/scanner results are saved to the workspace — re-run campaign after scanning"
            )
        if summary.get("techniques"):
            print_info(f"ATT&CK techniques: {', '.join(summary['techniques'][:12])}")
        if not graph.nodes:
            print_warning("No campaign steps generated — add hosts or vulnerabilities to the workspace")
            print_info("Try: network_discover, host add, scanner modules, or import findings via vuln")
            return

        rows = []
        for node in graph.nodes[:20]:
            module_col = (node.selected_module or "(commands)")[:40]
            rows.append(
                [
                    node.phase,
                    node.host_address,
                    module_col,
                    node.risk_level,
                    "yes" if node.scope_allowed else "NO",
                ]
            )
        print_empty()
        print_table(["Phase", "Host", "Module", "Risk", "Scope"], rows)
        if len(graph.nodes) > 20:
            print_info(f"... and {len(graph.nodes) - 20} more steps")
