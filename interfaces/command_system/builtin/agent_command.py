#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Autonomous agent command implementation.

Workflow logic lives in :mod:`interfaces.command_system.builtin.agent` (services + core).
"""

import argparse

from interfaces.command_system.base_command import BaseCommand
from interfaces.command_system.builtin.agent import AgentServices
from interfaces.command_system.builtin.agent.state import AgentMetrics, AgentState
from interfaces.command_system.builtin.scanner_command import ScannerCommand
from core.output_handler import (
    print_error,
    print_info,
    print_success,
)


class AgentCommand(BaseCommand):
    """Autonomous command to scan, exploit and report."""

    @property
    def name(self) -> str:
        return "agent"

    @property
    def description(self) -> str:
        return "Autonomous scan/exploit/report workflow"

    @property
    def usage(self) -> str:
        return (
            "agent <target> [--threads N] [--protocol PROTO] [--no-exploit] "
            "[--llm-local] [--max-modules N] [--recon-modules N]"
        )

    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

Examples:
    agent target.com
    agent https://target.com --threads 10
    agent target.com --protocol http
    agent target.com --no-exploit
    agent target.com --llm-local --llm-model llama3.1:8b
    agent target.com --llm-local
    agent target.com --max-modules 40 --recon-modules 12
        """

    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()
        self._agent = AgentServices(framework)

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("target", nargs="?")
        parser.add_argument("--threads", type=int, default=5)
        parser.add_argument("--protocol", type=str, default=None)
        parser.add_argument("--no-exploit", action="store_true")
        parser.add_argument("--verbose", "-v", action="store_true")
        parser.add_argument("--llm-local", action="store_true")
        parser.add_argument("--llm-model", type=str, default="llama3.1:8b")
        parser.add_argument("--llm-endpoint", type=str, default="http://127.0.0.1:11434/api/chat")
        parser.add_argument("--max-modules", type=int, default=40)
        parser.add_argument("--recon-modules", type=int, default=12)
        parser.add_argument("--help", "-h", action="store_true")
        return parser

    def execute(self, args, **kwargs) -> bool:
        try:
            parsed = self.parser.parse_args(args)
        except SystemExit:
            return False

        if parsed.help or not parsed.target:
            print_info(self.help_text)
            return bool(parsed.help)

        scanner = ScannerCommand(self.framework, self.session, self.output_handler)
        target_value = self._agent.target_resolver.normalize_target_input(parsed.target)
        target_info = scanner._parse_target(target_value)
        if not target_info:
            print_error(f"Invalid target: {parsed.target}")
            return False
        module_capability_catalog = self._agent.module_catalog.build_module_capability_catalog()

        state = AgentState(
            raw_target=parsed.target,
            target_info=target_info,
            scanner=scanner,
            protocol=parsed.protocol,
            threads=parsed.threads,
            verbose=parsed.verbose,
            no_exploit=parsed.no_exploit,
            llm_local=parsed.llm_local,
            llm_model=parsed.llm_model,
            llm_endpoint=parsed.llm_endpoint,
            max_modules=max(5, int(parsed.max_modules)),
            recon_modules=max(3, int(parsed.recon_modules)),
            execution_plan={
                "next_actions": [],
                "max_requests_next_phase": 0,
                "stop_conditions": [],
                "reasoning_confidence": 0.0,
                "skip_exploitation": False,
            },
            llm_plan={"selected_paths": [], "rationale": "No LLM plan generated."},
            knowledge_base={
                "tech_hints": [],
                "tech_confidence": {},
                "specializations": [],
                "observed_modules": [],
                "discovered_endpoints": [],
                "discovered_params": [],
                "login_paths": [],
                "risk_signals": [],
                "authenticated_page_excerpt": "",
                "post_auth_catalog_paths": [],
                "post_auth_exploit_paths": [],
                "auth_milestone": {},
                "credential_store": [],
                "active_auth_context": {},
                "module_capability_catalog": module_capability_catalog,
            },
            sessions_before={
                "standard": set(self.framework.session_manager.sessions.keys()),
                "browser": set(self.framework.session_manager.browser_sessions.keys()),
            },
            metrics=AgentMetrics(),
            history_scores=self._agent.report.load_history_scores(),
        )
        self._agent.knowledge.bootstrap_knowledge_from_host_profile(state)

        final_state = self._agent.run_agent_flow(state)
        if final_state.error:
            print_error(final_state.error)
            return False

        report_path = final_state.report_path

        if report_path:
            print_success(f"Report generated: {report_path}")
            return True
        return False
