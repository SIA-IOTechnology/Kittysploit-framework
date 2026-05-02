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
from interfaces.command_system.builtin.sessions_command import SessionsCommand
from core.output_handler import (
    print_error,
    print_info,
    print_success,
    print_warning,
)
from interfaces.command_system.builtin.agent.agent_constants import (
    DEFAULT_AGENT_USER_AGENT,
    SAFETY_PROFILE_NAMES,
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
            "[--llm-local] [--max-modules N] [--recon-modules N] "
            "[--safety-profile safe|normal|aggressive] [--request-delay-min S] "
            "[--request-delay-max S] [--async-probes] [--all]"
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
    agent target.com --safety-profile safe --request-delay-min 0.5 --request-delay-max 2
    agent target.com --async-probes
    agent target.com --all
        """

    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()
        self._agent = AgentServices(framework)

    def _pick_auto_session(self, session_ids):
        candidates = []
        session_manager = getattr(self.framework, "session_manager", None)
        if not session_manager:
            return None

        metadata = getattr(session_manager, "_session_metadata", {}) or {}
        for session_id in session_ids or []:
            session = session_manager.get_session(str(session_id))
            if not session:
                continue
            created_at = 0.0
            if isinstance(metadata.get(session.id), dict):
                try:
                    created_at = float(metadata[session.id].get("created_at") or 0.0)
                except Exception:
                    created_at = 0.0
            candidates.append((created_at, session.id))

        if not candidates:
            return None
        candidates.sort(key=lambda row: (row[0], row[1]))
        return candidates[-1][1]

    def _open_interactive_session(self, final_state: AgentState) -> bool:
        session_id = self._pick_auto_session(final_state.new_sessions)
        if not session_id:
            return True

        if len(final_state.new_sessions) > 1:
            print_info(
                f"Multiple new sessions detected; opening the most recent standard session: {session_id}"
            )
        else:
            print_info(f"Opening interactive session: {session_id}")

        sessions_command = SessionsCommand(self.framework, self.session, self.output_handler)
        if sessions_command._interact_session(session_id):
            return True

        print_warning(
            f"Interactive shell could not be opened automatically. Fallback: sessions interact {session_id}"
        )
        return False

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
        parser.add_argument(
            "--safety-profile",
            choices=SAFETY_PROFILE_NAMES,
            default="normal",
            help="Execution guardrails: safe blocks noisy modules, normal preserves defaults, aggressive removes guardrails.",
        )
        parser.add_argument(
            "--user-agent",
            default=DEFAULT_AGENT_USER_AGENT,
            help="Explicit User-Agent for agent-owned HTTP probes.",
        )
        parser.add_argument(
            "--request-delay-min",
            type=float,
            default=0.0,
            help="Minimum delay in seconds before agent-controlled HTTP/module batches.",
        )
        parser.add_argument(
            "--request-delay-max",
            type=float,
            default=0.0,
            help="Maximum delay in seconds before agent-controlled HTTP/module batches.",
        )
        parser.add_argument(
            "--async-probes",
            action="store_true",
            help="Use async HTTP for agent-owned probes when aiohttp is available.",
        )
        parser.add_argument(
            "--all",
            dest="expanded_surface",
            action="store_true",
            help=(
                "Expanded surface: include OSINT / cloud / passive aux modules alongside web scanners; "
                "after the main pass, run a bounded HTTP scan on same-organization hostnames "
                "harvested from results (e.g. subdomains)."
            ),
        )
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
        delay_min = max(0.0, float(parsed.request_delay_min))
        delay_max = max(0.0, float(parsed.request_delay_max))
        if delay_max < delay_min:
            delay_max = delay_min
        threads = max(1, int(parsed.threads))
        if parsed.safety_profile == "safe":
            threads = 1

        state = AgentState(
            raw_target=parsed.target,
            target_info=target_info,
            scanner=scanner,
            protocol=parsed.protocol,
            expanded_surface=bool(getattr(parsed, "expanded_surface", False)),
            threads=threads,
            verbose=parsed.verbose,
            no_exploit=parsed.no_exploit,
            safety_profile=parsed.safety_profile,
            user_agent=str(parsed.user_agent or DEFAULT_AGENT_USER_AGENT),
            request_delay_min=delay_min,
            request_delay_max=delay_max,
            async_probes=bool(parsed.async_probes),
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
            if final_state.new_sessions:
                self._open_interactive_session(final_state)
            return True
        return False
