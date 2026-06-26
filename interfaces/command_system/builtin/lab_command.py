#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Lab orchestrator command — scenarios, scoring, walkthrough, reset."""

from __future__ import annotations

import argparse
import json

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
        return "Run training labs based on docker_environments (start, score, reset, walkthrough)"

    @property
    def usage(self) -> str:
        return "lab [list|show|start|run|score|reset|walkthrough|state] [lab_id] [options]"

    def get_subcommands(self):
        return ["list", "show", "start", "run", "score", "reset", "walkthrough", "state"]

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
    score <lab_id>               Evaluate objectives against the running lab
    run <lab_id>                 Start environment and score objectives
    reset <lab_id>               Stop container and start a clean environment
    state <lab_id>               Show persisted lab run state

Options (run):
    --skip-start                 Score objectives without starting Docker

Examples:
    lab list
    lab show dvwa-basics
    lab walkthrough webgoat-intro
    lab start metasploitable-recon
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

        score = subparsers.add_parser("score", help="Score lab objectives")
        score.add_argument("lab_id")

        reset = subparsers.add_parser("reset", help="Reset lab environment")
        reset.add_argument("lab_id")

        state = subparsers.add_parser("state", help="Show persisted lab state")
        state.add_argument("lab_id")

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
            "score": lambda: self._handle_score(orchestrator, scenario),
            "reset": lambda: self._handle_reset(orchestrator, scenario),
            "state": lambda: self._handle_state(orchestrator, scenario),
            "run": lambda: self._handle_run(orchestrator, scenario, parsed.skip_start),
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

    def _handle_score(self, orchestrator: LabOrchestrator, scenario) -> bool:
        result = orchestrator.score_lab(scenario)
        self._print_score(result)
        return not result.error

    def _handle_run(self, orchestrator: LabOrchestrator, scenario, skip_start: bool) -> bool:
        try:
            result = orchestrator.run_lab(scenario, skip_start=skip_start)
        except Exception as exc:
            print_error(f"Lab run failed: {exc}")
            return False
        self._print_score(result)
        return not result.error

    def _handle_state(self, orchestrator: LabOrchestrator, scenario) -> bool:
        state = orchestrator.load_state(scenario.id)
        if not state:
            print_info(f"No persisted state for lab '{scenario.id}'")
            return True
        print_info(json.dumps(state, indent=2, sort_keys=True))
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
