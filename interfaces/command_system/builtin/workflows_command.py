#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Workflow library command — list, show, and run declarative YAML/JSON workflows."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.output_handler import print_empty, print_error, print_info, print_success, print_table, print_warning
from core.workflows import (
    WorkflowEngine,
    list_workflow_ids,
    load_workflow_definition,
    load_workflow_file,
)
from core.workflows.cli_args import expand_workflow_variable_flags
from interfaces.command_system.base_command import BaseCommand


class WorkflowsCommand(BaseCommand):
    """Run KittySploit declarative workflow library (YAML/JSON on WorkflowStep)."""

    @property
    def name(self) -> str:
        return "workflows"

    @property
    def description(self) -> str:
        return (
            "List and run declarative workflow library (web-recon, service-discovery, devops-panels, …). "
            "Same workflows are also available via use workflow/<id>."
        )

    @property
    def usage(self) -> str:
        return (
            "workflows list | show <id> | run <id> [--target URL] [--VAR VALUE] "
            "[--set KEY=VAL] [--file path.yaml] [--dry-run] [--from-workspace]"
        )

    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

Subcommands:
    list                    List bundled workflow definitions
    show <id>               Show workflow steps and variables
    run <id>                Execute a library workflow
    run --file <path>       Execute a custom YAML/JSON workflow file

Options (run):
    --target, -t <url>      Primary target (hostname or URL)
    --<variable> <value>    Set any workflow variable (e.g. --persona_name "Jane Doe")
    --set, -s KEY=VAL       Override workflow variables (repeatable)
    --dry-run               Print execution plan without running modules
    --from-workspace        Use active workspace primary host when --target omitted
    --json                  Machine-readable output for list/show/run

Examples:
    workflows list
    workflows show web-recon
    use workflow/web-recon
    set target example.com
    run
    workflows run web-recon --target example.com --dry-run
    workflows run osint-deep-recon --target acme.com --persona_name "Jane Doe"
    workflows run osint-passive-recon -t acme.com --legal_basis "CASE-2026-001" --persona_name "Jane Doe"
    workflows run osint-deep-recon -t acme.com --run_login_bruteforce true
    workflows run client-retest --from-workspace
    workflows run owasp-quick -t https://lab.local --set port=8443 --set ssl=true
    workflows run network-services --target 10.0.0.5
    workflows run devops-panels --target app.example.com --port 443 --ssl true
    workflows run service-discovery --target 10.0.0.5 --http_port 8443 --ssl true
        """

    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog="workflows", add_help=True)
        sub = parser.add_subparsers(dest="command")

        sub.add_parser("list", help="List library workflows")

        show_p = sub.add_parser("show", help="Show workflow definition")
        show_p.add_argument("workflow_id")
        show_p.add_argument("--json", action="store_true")

        run_p = sub.add_parser("run", help="Run a workflow")
        run_p.add_argument("workflow_id", nargs="?", help="Library workflow id")
        run_p.add_argument("--file", "-f", help="Custom workflow YAML/JSON path")
        run_p.add_argument("--target", "-t", help="Target URL or hostname")
        run_p.add_argument("--set", "-s", action="append", default=[], metavar="KEY=VAL")
        run_p.add_argument("--dry-run", action="store_true")
        run_p.add_argument("--from-workspace", action="store_true")
        run_p.add_argument("--json", action="store_true")

        return parser

    def execute(self, args: List[str], **kwargs) -> bool:
        args = expand_workflow_variable_flags(args)
        try:
            parsed = self.parser.parse_args(args)
        except SystemExit:
            return True

        command = parsed.command
        if not command:
            if args and args[0] in list_workflow_ids():
                parsed = self.parser.parse_args(["run"] + args)
                command = "run"
            else:
                self.show_help()
                return True

        if command == "list":
            return self._cmd_list(getattr(parsed, "json", False))
        if command == "show":
            return self._cmd_show(parsed.workflow_id, parsed.json)
        if command == "run":
            return self._cmd_run(parsed)
        print_error(f"Unknown subcommand: {command}")
        return False

    def _cmd_list(self, as_json: bool) -> bool:
        rows = []
        for workflow_id in list_workflow_ids():
            try:
                definition = load_workflow_definition(workflow_id)
            except Exception as exc:
                print_warning(f"Could not load {workflow_id}: {exc}")
                continue
            rows.append(
                {
                    "id": definition.workflow_id,
                    "name": definition.name,
                    "tags": ", ".join(definition.tags),
                    "steps": len(definition.steps),
                    "quick_win": definition.quick_win,
                }
            )

        if as_json:
            print_info(json.dumps(rows, indent=2))
            return True

        if not rows:
            print_warning("No workflows found in library.")
            return True

        print_table(
            ["ID", "Name", "Tags", "Steps", "Quick win"],
            [[r["id"], r["name"], r["tags"], r["steps"], "yes" if r["quick_win"] else ""] for r in rows],
        )
        return True

    def _cmd_show(self, workflow_id: str, as_json: bool) -> bool:
        try:
            definition = load_workflow_definition(workflow_id)
        except FileNotFoundError:
            print_error(f"Workflow not found: {workflow_id}")
            return False

        if as_json:
            print_info(json.dumps(self._definition_to_dict(definition), indent=2))
            return True

        print_info(f"{definition.name} ({definition.workflow_id}) v{definition.version}")
        print_info(definition.description.strip())
        if definition.tags:
            print_info(f"Tags: {', '.join(definition.tags)}")
        print_empty()
        print_info("Variables:")
        for name, spec in definition.variables.items():
            req = "required" if spec.required else "optional"
            default = f", default={spec.default}" if spec.default else ""
            print_info(f"  {name} ({req}{default}) — {spec.description}")
        print_empty()
        print_info(f"Start: {definition.start_step}")
        for step_name, step in definition.steps.items():
            kind = step.step_type
            detail = step.module or step.builtin_action or ""
            print_info(f"  • {step_name} [{kind}] {detail}")
            if step.description:
                print_info(f"      {step.description}")
        return True

    def _cmd_run(self, parsed) -> bool:
        try:
            if parsed.file:
                definition = load_workflow_file(parsed.file)
            elif parsed.workflow_id:
                definition = load_workflow_definition(parsed.workflow_id)
            else:
                print_error("Provide a workflow id or --file")
                return False
        except (FileNotFoundError, ValueError, ImportError) as exc:
            print_error(str(exc))
            return False

        variables = self._parse_set_args(parsed.set)
        if parsed.target:
            variables["target"] = parsed.target
        if parsed.from_workspace and "target" not in variables:
            variables.setdefault("from_workspace", "true")
        variables["workflow_id"] = definition.workflow_id

        engine = WorkflowEngine(self.framework)
        try:
            engine.resolve_variables(definition, variables)
        except ValueError as exc:
            if not parsed.target and not parsed.from_workspace:
                print_error(f"{exc} — use --target or --from-workspace")
            else:
                print_error(str(exc))
            return False

        if parsed.dry_run:
            print_info(f"Dry-run plan for {definition.workflow_id}")

        try:
            result = engine.run(definition, variables, dry_run=parsed.dry_run)
        except Exception as exc:
            print_error(f"Workflow run failed: {exc}")
            return False

        if parsed.json:
            payload = {
                "workflow_id": result.workflow_id,
                "success": result.success,
                "dry_run": result.dry_run,
                "duration_seconds": round(result.duration_seconds, 2),
                "steps_executed": result.steps_executed,
                "step_results": result.step_results,
                "errors": result.errors,
                "plan": result.plan,
            }
            print_info(json.dumps(payload, indent=2))
            return result.success

        if parsed.dry_run:
            for entry in result.plan:
                label = entry.get("module") or entry.get("action") or entry.get("type")
                print_info(f"  → {entry['name']}: {label}")
            print_success(f"Plan ready ({len(result.plan)} steps)")
            return True

        if result.success:
            total = len(result.step_results or {})
            matches = result.matches
            if matches:
                print_success(
                    f"Workflow {result.workflow_id} finished in {result.duration_seconds:.1f}s "
                    f"— {matches}/{total} step(s) matched"
                )
            elif total:
                print_success(
                    f"Workflow {result.workflow_id} finished in {result.duration_seconds:.1f}s "
                    f"— {total} step(s) probed, no matches"
                )
            else:
                print_success(
                    f"Workflow {result.workflow_id} finished in {result.duration_seconds:.1f}s"
                )
        else:
            print_warning(
                f"Workflow {result.workflow_id} stopped with "
                f"{len(result.errors)} error(s)"
            )
        return result.success

    def _parse_set_args(self, set_args: List[str]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for item in set_args or []:
            if "=" not in item:
                print_warning(f"Ignoring invalid --set value: {item}")
                continue
            key, value = item.split("=", 1)
            out[key.strip()] = value.strip()
        return out

    def _definition_to_dict(self, definition) -> Dict[str, Any]:
        return {
            "id": definition.workflow_id,
            "name": definition.name,
            "description": definition.description,
            "version": definition.version,
            "tags": definition.tags,
            "policy": definition.policy,
            "start_step": definition.start_step,
            "continue_on_failure": definition.continue_on_failure,
            "variables": {
                name: {
                    "description": spec.description,
                    "default": spec.default,
                    "required": spec.required,
                }
                for name, spec in definition.variables.items()
            },
            "steps": {
                name: {
                    "type": step.step_type,
                    "module": step.module,
                    "action": step.builtin_action,
                    "description": step.description,
                    "options": step.options,
                    "on_success": step.on_success,
                    "on_failure": step.on_failure,
                }
                for name, step in definition.steps.items()
            },
        }
