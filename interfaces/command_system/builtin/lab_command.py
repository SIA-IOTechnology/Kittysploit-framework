#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Lab orchestrator command — scenarios, scoring, walkthrough, stop, reset."""

from __future__ import annotations

import argparse
import json
from typing import Optional

from core.lab_orchestrator import LabOrchestrator, discover_lab_scenarios
from core.output_handler import print_empty, print_error, print_info, print_success, print_table, print_warning
from interfaces.command_system.base_command import BaseCommand


class LabCommand(BaseCommand):
    """Orchestrate docker_environments labs for training, demos, and regression tests."""

    @property
    def name(self) -> str:
        return "lab"

    @property
    def description(self) -> str:
        return "Run training labs based on docker_environments (start, stop, score, reset, walkthrough)"

    @property
    def usage(self) -> str:
        return "lab [list|show|start|stop|run|score|reset|walkthrough|state|verify-agent|attest|pin-digest] [lab_id] [options]"

    def get_subcommands(self):
        return [
            "list",
            "show",
            "start",
            "stop",
            "run",
            "score",
            "reset",
            "walkthrough",
            "state",
            "verify-agent",
            "attest",
            "pin-digest",
        ]

    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

Lab scenarios live in the repository ``labs/`` directory as JSON files.
Each scenario references a ``docker_environments/*`` module, defines objectives
with automatic checks, scoring, walkthrough steps, and reset behavior.

Subcommands:
    list                         List available lab scenarios
    show <lab_id>                Show scenario details
    walkthrough <lab_id>         Print guided steps
    start <lab_id>               Start the Docker environment only
    stop <lab_id>                Stop (and remove) the lab environment
    score <lab_id> [--run-id RUN_ID]     Evaluate objectives (and agent checks if run id set)
    verify-agent <lab_id> <run_id>       Verify agent run against lab manifest
    run <lab_id>                 Start environment and score objectives
    reset <lab_id>               Stop container and start a clean environment
    state <lab_id>               Show persisted lab run state
    attest <lab_id>              Show or verify reset attestation for benchmarks
    pin-digest <lab_id>          Resolve and pin immutable image digest in manifest

Options (run):
    --skip-start                 Score objectives without starting Docker

Examples:
    lab list
    lab show dvwa-basics
    lab walkthrough webgoat-intro
    lab start metasploitable-recon
    lab stop dvwa-basics
    lab run dvwa-basics
    lab score dvwa-basics
    lab reset dvwa-basics
        """

    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="lab",
            description="Lab orchestrator for docker_environments",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        subparsers = parser.add_subparsers(dest="action")

        subparsers.add_parser("list", help="List lab scenarios")

        show = subparsers.add_parser("show", help="Show lab scenario")
        show.add_argument("lab_id")

        walkthrough = subparsers.add_parser("walkthrough", help="Show walkthrough")
        walkthrough.add_argument("lab_id")

        start = subparsers.add_parser("start", help="Start lab environment")
        start.add_argument("lab_id")

        stop = subparsers.add_parser("stop", help="Stop lab environment")
        stop.add_argument("lab_id")

        score = subparsers.add_parser("score", help="Score lab objectives")
        score.add_argument("lab_id")
        score.add_argument("--run-id", dest="run_id", default=None, help="Agent run id for agent_objectives")

        verify_agent = subparsers.add_parser("verify-agent", help="Verify agent run against lab manifest")
        verify_agent.add_argument("lab_id")
        verify_agent.add_argument("run_id")

        reset = subparsers.add_parser("reset", help="Reset lab environment")
        reset.add_argument("lab_id")

        state = subparsers.add_parser("state", help="Show persisted lab state")
        state.add_argument("lab_id")

        attest = subparsers.add_parser("attest", help="Show or verify reset attestation")
        attest.add_argument("lab_id")
        attest.add_argument("--json", action="store_true", help="Print attestation JSON")

        pin_digest = subparsers.add_parser("pin-digest", help="Pin immutable image digest in manifest")
        pin_digest.add_argument("lab_id")
        pin_digest.add_argument("--digest", default=None, help="Explicit sha256 digest to pin")

        run = subparsers.add_parser("run", help="Start and score lab")
        run.add_argument("lab_id")
        run.add_argument("--skip-start", action="store_true", help="Only score objectives")
        return parser

    def execute(self, args, **kwargs) -> bool:
        try:
            parsed = self.parser.parse_args(args)
        except SystemExit:
            return True

        orchestrator = LabOrchestrator(self.framework)

        if not parsed.action:
            print_info(self.help_text)
            return True

        if parsed.action == "list":
            return self._handle_list(orchestrator)

        if parsed.action == "verify-agent":
            lab_id = getattr(parsed, "lab_id", None)
            run_id = getattr(parsed, "run_id", None)
            if not lab_id or not run_id:
                print_error("Usage: lab verify-agent <lab_id> <run_id>")
                return False
            try:
                scenario = orchestrator.get_scenario(lab_id)
            except FileNotFoundError:
                print_error(f"Unknown lab scenario: {lab_id}")
                return False
            return self._handle_verify_agent(orchestrator, scenario, run_id)

        lab_id = getattr(parsed, "lab_id", None)
        if not lab_id:
            print_error("Lab id is required")
            return False

        try:
            scenario = orchestrator.get_scenario(lab_id)
        except FileNotFoundError:
            print_error(f"Unknown lab scenario: {lab_id}")
            return False

        handlers = {
            "show": lambda: self._handle_show(scenario),
            "walkthrough": lambda: self._handle_walkthrough(scenario),
            "start": lambda: self._handle_start(orchestrator, scenario),
            "stop": lambda: self._handle_stop(orchestrator, scenario),
            "score": lambda: self._handle_score(orchestrator, scenario, getattr(parsed, "run_id", None)),
            "reset": lambda: self._handle_reset(orchestrator, scenario),
            "state": lambda: self._handle_state(orchestrator, scenario),
            "attest": lambda: self._handle_attest(orchestrator, scenario, getattr(parsed, "json", False)),
            "pin-digest": lambda: self._handle_pin_digest(orchestrator, scenario, getattr(parsed, "digest", None)),
            "run": lambda: self._handle_run(orchestrator, scenario, parsed.skip_start, getattr(parsed, "run_id", None)),
            "verify-agent": lambda: self._handle_verify_agent(orchestrator, scenario, parsed.run_id),
        }
        return handlers[parsed.action]()

    def _handle_list(self, orchestrator: LabOrchestrator) -> bool:
        scenarios = discover_lab_scenarios(orchestrator.labs_dir)
        if not scenarios:
            print_warning("No lab scenarios found in labs/")
            return True

        rows = []
        for scenario in scenarios:
            rows.append(
                [
                    scenario.id,
                    scenario.name,
                    scenario.environment,
                    scenario.difficulty,
                    str(scenario.max_score),
                    ", ".join(scenario.tags[:3]),
                ]
            )
        print_table(
            ["ID", "Name", "Environment", "Difficulty", "Score", "Tags"],
            rows,
        )
        return True

    def _handle_show(self, scenario) -> bool:
        print_info(f"Lab: {scenario.name} ({scenario.id})")
        print_info(f"Environment: {scenario.environment}")
        print_info(f"Difficulty: {scenario.difficulty}")
        print_info(f"Max score: {scenario.max_score}")
        print_info(scenario.description)
        print_empty()
        print_info("Objectives:")
        for objective in scenario.objectives:
            print_info(f"  - [{objective.points} pts] {objective.title} ({objective.id})")
        if scenario.agent_objectives:
            print_empty()
            print_info("Agent objectives (require verify-agent or --run-id):")
            for objective in scenario.agent_objectives:
                print_info(f"  - [{objective.points} pts] {objective.title} ({objective.id})")
        return True

    def _handle_walkthrough(self, scenario) -> bool:
        print_info(f"Walkthrough: {scenario.name}")
        print_info("=" * 50)
        for step in scenario.walkthrough:
            print_success(f"Step {step.step}: {step.title}")
            print_info(step.body)
            print_empty()
        return True

    def _handle_start(self, orchestrator: LabOrchestrator, scenario) -> bool:
        try:
            if orchestrator.start_lab(scenario):
                print_success(f"Lab '{scenario.id}' environment started")
                return True
            print_error(f"Failed to start lab '{scenario.id}'")
            return False
        except Exception as exc:
            print_error(f"Lab start failed: {exc}")
            return False

    def _handle_stop(self, orchestrator: LabOrchestrator, scenario) -> bool:
        try:
            if orchestrator.stop_lab(scenario):
                print_success(f"Lab '{scenario.id}' stopped")
                return True
            print_error(f"Failed to stop lab '{scenario.id}'")
            return False
        except Exception as exc:
            print_error(f"Lab stop failed: {exc}")
            return False

    def _handle_reset(self, orchestrator: LabOrchestrator, scenario) -> bool:
        try:
            if orchestrator.reset_lab(scenario):
                print_success(f"Lab '{scenario.id}' reset and restarted")
                return True
            print_error(f"Failed to reset lab '{scenario.id}'")
            return False
        except Exception as exc:
            print_error(f"Lab reset failed: {exc}")
            return False

    def _handle_score(self, orchestrator: LabOrchestrator, scenario, run_id: Optional[str] = None) -> bool:
        result = orchestrator.score_lab(scenario, agent_run_id=run_id)
        self._print_score(result)
        return not result.error

    def _handle_run(
        self,
        orchestrator: LabOrchestrator,
        scenario,
        skip_start: bool,
        run_id: Optional[str] = None,
    ) -> bool:
        try:
            result = orchestrator.run_lab(scenario, skip_start=skip_start, agent_run_id=run_id)
        except Exception as exc:
            print_error(f"Lab run failed: {exc}")
            return False
        self._print_score(result)
        return not result.error

    def _handle_verify_agent(self, orchestrator: LabOrchestrator, scenario, run_id: str) -> bool:
        try:
            result = orchestrator.verify_agent_run(scenario, run_id)
        except Exception as exc:
            print_error(f"Agent verification failed: {exc}")
            return False
        self._print_agent_score(result)
        return result.agent_passed

    def _handle_state(self, orchestrator: LabOrchestrator, scenario) -> bool:
        state = orchestrator.load_state(scenario.id)
        if not state:
            print_info(f"No persisted state for lab '{scenario.id}'")
            return True
        print_info(json.dumps(state, indent=2, sort_keys=True))
        return True

    def _handle_attest(self, orchestrator: LabOrchestrator, scenario, as_json: bool) -> bool:
        attestation = orchestrator.get_reset_attestation(scenario.id)
        ok, detail = orchestrator.verify_reset_attestation(scenario)
        if as_json:
            print_info(json.dumps({"valid": ok, "detail": detail, "attestation": attestation}, indent=2))
            return ok
        if not attestation:
            print_warning("No reset attestation recorded — run `lab start` or `lab reset` first")
            return False
        print_info(f"Attestation: {attestation.get('id')} ({attestation.get('event')})")
        print_info(f"Manifest fingerprint: {attestation.get('manifest_fingerprint', '')[:32]}...")
        print_info(f"Image digest: {attestation.get('image_digest') or 'unpinned'}")
        if ok:
            print_success(detail)
        else:
            print_warning(detail)
        return ok

    def _handle_pin_digest(self, orchestrator: LabOrchestrator, scenario, digest: Optional[str]) -> bool:
        from core.lab_orchestrator.attestation import update_manifest_digest
        from core.lab_orchestrator.manifest import find_ground_truth_manifest

        manifest = orchestrator.get_manifest(scenario)
        if manifest is None:
            print_error(f"No manifest configured for lab {scenario.id}")
            return False

        resolved = str(digest or "").strip()
        if not resolved:
            module = self.framework.module_loader.load_module(
                scenario.environment,
                framework=self.framework,
            )
            if module is None:
                print_error(f"Could not load environment module: {scenario.environment}")
                return False
            pull_fn = getattr(module, "pull_image", None)
            if callable(pull_fn):
                pull_fn()
            digest_fn = getattr(module, "get_image_digest", None)
            if callable(digest_fn):
                resolved = str(digest_fn() or "").strip()
        if not resolved:
            print_error(
                "Could not resolve image digest. Pass --digest sha256:... "
                "or ensure Docker has pulled the lab image."
            )
            return False

        manifest_path = find_ground_truth_manifest(scenario.manifest or scenario.id).source_path
        update_manifest_digest(manifest_path, resolved)
        print_success(f"Pinned digest in {manifest_path}: {resolved[:32]}...")
        print_info("Re-run `lab reset` to record a fresh reset attestation.")
        return True

    def _print_score(self, result) -> None:
        print_info(f"Lab score: {result.score}/{result.max_score}")
        for objective in result.objectives:
            if objective.passed:
                print_success(f"[+{objective.earned}] {objective.title}: {objective.detail}")
            else:
                print_warning(f"[ 0] {objective.title}: {objective.detail}")
        if result.error:
            print_error(result.error)
        elif result.score >= result.max_score:
            print_success("All objectives completed")
        else:
            print_info("Lab incomplete — review walkthrough with `lab walkthrough <id>`")
        if result.agent_objectives:
            print_empty()
            self._print_agent_score(result)

    def _print_agent_score(self, result) -> None:
        print_info(f"Agent verification: {result.agent_score}/{result.max_agent_score} (run={result.agent_run_id})")
        for objective in result.agent_objectives:
            if objective.passed:
                print_success(f"[+{objective.earned}] {objective.title}: {objective.detail}")
            else:
                print_warning(f"[ 0] {objective.title}: {objective.detail}")
        if result.agent_passed:
            print_success("All agent objectives verified")
        elif result.agent_objectives:
            print_info("Agent verification incomplete")
