#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Autonomous agent command implementation.

Workflow logic lives in :mod:`interfaces.command_system.builtin.agent` (services + core).
"""

import argparse
import json
import random

from interfaces.command_system.base_command import BaseCommand
from interfaces.command_system.builtin.agent import AgentServices
from interfaces.command_system.builtin.agent.state import AgentMetrics, AgentState
from interfaces.command_system.builtin.agent.state import agent_state_from_dict
from interfaces.command_system.builtin.agent.doctor import AgentDoctor
from interfaces.command_system.builtin.agent.network_budget import NetworkBudget
from interfaces.command_system.builtin.agent.run_store import (
    AgentPathService,
    AgentRunStore,
    new_run_id,
)
from interfaces.command_system.builtin.agent.runtime_policy import (
    AgentRuntimePolicy,
    AgentScopeGuard,
    CancellationToken,
)
from interfaces.command_system.builtin.agent.goal_planner import (
    build_goal_plan,
    is_shell_operator_goal,
    normalize_goal,
)
from interfaces.command_system.builtin.agent.explain_service import AgentExplainService
from interfaces.command_system.builtin.agent.replay_service import AgentReplayService
from interfaces.command_system.builtin.agent.retest_service import AgentRetestService
from interfaces.command_system.builtin.agent.mission_profiles import apply_mission_profile, list_mission_profiles
from interfaces.command_system.builtin.scanner_command import ScannerCommand
from interfaces.command_system.builtin.sessions_command import SessionsCommand
from core.output_handler import (
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)
from interfaces.command_system.builtin.agent.agent_constants import (
    DEFAULT_AGENT_USER_AGENT,
    DISCREET_PROFILE_DEFAULT_DELAY_MAX,
    DISCREET_PROFILE_DEFAULT_DELAY_MIN,
    DISCREET_PROFILE_DEFAULT_MAX_MODULES,
    DISCREET_PROFILE_DEFAULT_RECON_MODULES,
    DISCREET_PROFILE_DEFAULT_REQUEST_BUDGET,
    DISCREET_PROFILE_MAX_LLM_CALLS,
    SAFETY_PROFILE_NAMES,
)
from core.framework.module_context import capture_module_context, restore_module_context


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
        return "agent <target> [options] | agent <doctor|explain|replay|retest|profiles|metadata|benchmark> ..."

    def get_subcommands(self):
        return ["doctor", "explain", "replay", "retest", "profiles", "metadata", "benchmark"]

    @property
    def help_text(self) -> str:
        profile_lines = "\n".join(
            f"    {name:<22} {desc}"
            for name, desc in list_mission_profiles().items()
        )
        return f"""
{self.description}

Usage:
    agent <target> [options]              Run scan → analyze → reason → exploit → report
    agent doctor [--json]                 Check agent prerequisites
    agent explain <run_id>                Explain a completed run
    agent replay <run_id> [options]        Replay decisions, shadow, specialists, or execution offline
    agent retest <finding_id|run_id>      Retest a finding or run
    agent profiles                        List mission profile presets
    agent metadata [--json]               Audit module agent metadata coverage
    agent metadata families [--suite ID]  Audit benchmark/lab module families (declared vs chain)
    agent metadata annotate [--apply]     Inject inferred agent blocks (dry-run by default)
    agent metadata upgrade [--apply]      Enrich existing agent blocks with chain metadata
    agent metadata contract [--strict]    Run static contract tests (priority families or suite)
    agent benchmark list                  List benchmark suites
    agent benchmark phase3-validate       Validate Phase 3 MCR exit criterion
    agent benchmark phase4-validate       Validate Phase 4 campaign MCR exit criterion
    agent benchmark phase5-validate       Validate Phase 5 learning memory exit criterion
    agent benchmark phase6-validate       Validate Phase 6 generalization exit criterion
    agent benchmark team008-validate      Validate TEAM-008 mono vs multi-agent A/B
    agent benchmark multiagent-ab         Alias for team008-validate
    agent benchmark release-gate          Block release on MCR/safety regressions
    agent benchmark dashboard             Write regression dashboard JSON
    agent benchmark [run] <suite> [options]  Run or score a benchmark suite

Benchmark options:
    --runs N                              Number of live runs (default: 1)
    --seed S                              Deterministic seed base
    --model M                             LLM model slug (heuristic if omitted)
    --offline                             Score existing run artifacts only
    --run-id RUN_ID                       Repeatable offline run id filter
    --output PATH                         Write comparable JSON to PATH
    --micro-seeds N                       Phase3/4/5/6 micro scenarios (default: 32)
    --skip-integration                    Phase3/4/TEAM-008: micro benchmark only
    --baseline PATH                       Release-gate baseline JSON (default: fixtures)

Target & workflow:
    <target>                              Hostname, IP, or URL
    --protocol PROTO                      Force http, https, tcp, ...
    --no-exploit                          Recon and analysis only
    --goal GOAL                           recon, validate, obtain-auth, obtain-shell,
                                          post-auth, evidence-only, detection-validation, retest
    --profile PROFILE                     Mission preset (see Mission profiles)
    --persona "Jane Doe"                     Persona for OSINT identity/password linking
    --all                                 Subdomains, identity OSINT, persona passwords → bruteforce
    --shell-hunter                        Pursue interactive shells (needs --approve-risk intrusive)
    --dry-run                             Plan without network traffic or module execution
    --plan-only                           Recon + planning, no exploitation
    --checkpoint                          Save checkpoint after each phase
    --resume RUN_ID                       Resume a checkpoint
    --restart-phase PHASE                 scan, analyze, reason, exploit, report

Safety & approvals:
    --safety-profile PROFILE              safe | discreet | normal | aggressive (default: normal)
    --approve-risk LEVEL                  Approve read, active, intrusive, or destructive (repeatable)
                                          intrusive also continues through CDN/WAF heuristics (throttled)
    --approve-active-replay               Allow mutating HTTP replay (--http-replay active)
    --approve-post-exploit                Allow read-only post-exploitation collection
    --policy FILE                         JSON/TOML mission policy file

    Risk levels (low → high): read → active → intrusive → destructive
    Approving a higher level includes lower levels. Some flags require explicit approval:
      --shell-hunter                      requires --approve-risk intrusive
      --http-replay active                requires --approve-active-replay

Limits & timing:
    --threads N                           Parallel module threads (default: 5)
    --max-modules N                       Cap modules per phase (default: 40)
    --recon-modules N                     Cap recon modules (default: 12)
    --request-budget N                    Max network units (0 = profile default / unbounded)
    --llm-budget N                        Max local LLM calls (0 = default / unbounded)
    --request-delay-min S                 Min delay between batches
    --request-delay-max S                 Max delay between batches
    --deadline SECONDS                    Hard campaign deadline
    --phase-timeout SECONDS               Per-phase timeout
    --seed N                              Deterministic planning seed

HTTP & proxy:
    --http-replay off|safe|active         Replay captured requests (default: safe)
    --http-replay-max N                   Max replay candidates (default: 3)
    --reuse-proxy-auth                    Seed cookies from KittyProxy flows
    --no-proxy-flows                      Skip KittyProxy flow import
    --proxy-flow-limit N                  Max flows to analyze (default: 40)
    --user-agent STRING                   User-Agent for agent HTTP probes
    --async-probes                        Use aiohttp when available

TLS:
    --tls-no-verify                       Disable TLS certificate verification
    --tls-ca PATH                         Custom CA bundle

LLM:
    --llm-local                           Use local LLM (Ollama)
    --refute-panel                        Run skeptic refutation panel on findings (analyze phase)
    --llm-model MODEL                     Model name (default: llama3.1:8b)
    --llm-endpoint URL                    Chat API endpoint

Sessions:
    --session-policy POLICY               report-only | open-latest | ask | never
    --no-interact                         Alias for --session-policy never

Mission profiles (agent profiles):
{profile_lines}

Examples:
    agent target.com
    agent https://target.com --threads 10 --safety-profile discreet
    agent target.com --no-exploit --goal recon
    agent target.com --profile safe-web --dry-run
    agent target.com --profile internal-lab --approve-risk intrusive --goal obtain-shell
    agent target.com --all --shell-hunter --approve-risk intrusive
    agent https://target.com --reuse-proxy-auth --http-replay active --approve-active-replay
    agent target.com --plan-only --checkpoint
    agent --resume agent_20260618T120000_ab12cd34ef
    agent doctor
    agent doctor --json
    agent explain agent_20260618T120000_ab12cd34ef
    agent replay agent_20260618T120000_ab12cd34ef
    agent replay agent_20260618T120000_ab12cd34ef --mode shadow
    agent replay agent_20260618T120000_ab12cd34ef --mode specialists
    agent replay agent_20260618T120000_ab12cd34ef --mode execution --lab metasploitable3-linux
    agent retest finding-xss-1
    agent metadata
    agent metadata --json
    agent metadata annotate
    agent metadata annotate --apply --family scanner,exploits
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
            try:
                transport_state = str((getattr(session, "data", {}) or {}).get("transport_state") or "").lower()
            except Exception:
                transport_state = ""
            if transport_state == "disconnected":
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
        parser.add_argument(
            "--refute-panel",
            action="store_true",
            help="Run multi-refuter skeptic panel during analysis to block overclaimed findings.",
        )
        parser.add_argument("--llm-model", type=str, default="llama3.1:8b")
        parser.add_argument("--llm-endpoint", type=str, default="http://127.0.0.1:11434/api/chat")
        parser.add_argument("--max-modules", type=int, default=40)
        parser.add_argument("--recon-modules", type=int, default=12)
        parser.add_argument(
            "--safety-profile",
            choices=SAFETY_PROFILE_NAMES,
            default="normal",
            help=(
                "Execution guardrails: safe blocks noisy modules, discreet keeps a small request budget, "
                "normal preserves defaults, aggressive removes guardrails."
            ),
        )
        parser.add_argument("--shell-hunter", action="store_true", help="Aggressively pursue interactive shells")
        parser.add_argument("--dry-run", action="store_true", help="Build a bounded plan without network traffic or module execution.")
        parser.add_argument("--plan-only", action="store_true", help="Run reconnaissance and planning, but never execute exploitation.")
        parser.add_argument("--checkpoint", action="store_true", help="Persist a redacted checkpoint after every completed phase.")
        parser.add_argument("--resume", metavar="RUN_ID", help="Resume a workspace agent checkpoint.")
        parser.add_argument(
            "--restart-phase",
            choices=("scan", "analyze", "reason", "exploit", "report"),
            help="When resuming, restart from this phase.",
        )
        parser.add_argument("--deadline", type=float, default=0.0, help="Hard campaign deadline in seconds.")
        parser.add_argument("--phase-timeout", type=float, default=0.0, help="Maximum seconds per workflow phase.")
        parser.add_argument("--seed", type=int, default=None, help="Deterministic random seed for planning and delays.")
        parser.add_argument(
            "--session-policy",
            choices=("report-only", "open-latest", "ask", "never"),
            default="ask",
            help="What to do when the agent creates sessions.",
        )
        parser.add_argument("--no-interact", action="store_true", help="Alias for --session-policy never.")
        parser.add_argument(
            "--approve-risk",
            action="append",
            default=[],
            metavar="LEVEL",
            help="Explicitly approve read, active, intrusive, or destructive actions.",
        )
        parser.add_argument("--approve-active-replay", action="store_true")
        parser.add_argument("--approve-post-exploit", action="store_true")
        parser.add_argument("--tls-no-verify", action="store_true", help="Disable TLS verification and record it in the report.")
        parser.add_argument("--tls-ca", help="CA bundle used for agent-owned HTTPS requests.")
        parser.add_argument("--policy", help="JSON/TOML agent mission policy.")
        parser.add_argument(
            "--goal",
            help="Campaign goal: recon, validate, obtain-auth, obtain-shell, post-auth, evidence-only, detection-validation, retest.",
        )
        parser.add_argument(
            "--profile",
            help="Mission profile preset. Use `agent profiles` to list available policies.",
        )
        parser.add_argument(
            "--request-budget",
            type=int,
            default=0,
            help=(
                "Approximate maximum agent-owned network units. A probe or module launch costs one unit. "
                "0 means profile default / unbounded."
            ),
        )
        parser.add_argument(
            "--llm-budget",
            type=int,
            default=0,
            help="Maximum local LLM calls for this agent run. 0 means profile default / unbounded.",
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
            "--no-proxy-flows",
            action="store_true",
            help="Do not import matching KittyProxy CLI flows into the agent knowledge base.",
        )
        parser.add_argument(
            "--proxy-flow-limit",
            type=int,
            default=40,
            help="Maximum recent KittyProxy flows to analyze for this target (default: 40).",
        )
        parser.add_argument(
            "--http-replay",
            choices=("off", "safe", "active"),
            default="safe",
            help=(
                "Replay captured request candidates when useful: off disables it, safe only re-sends "
                "idempotent GET/HEAD/OPTIONS requests, active may replay original non-idempotent methods."
            ),
        )
        parser.add_argument(
            "--http-replay-max",
            type=int,
            default=3,
            help="Maximum captured request candidates to replay during request intelligence (default: 3).",
        )
        parser.add_argument(
            "--reuse-proxy-auth",
            action="store_true",
            help="Seed agent modules with Cookie context observed in matching KittyProxy flows.",
        )
        parser.add_argument(
            "--persona",
            dest="persona_name",
            default="",
            help="Person full name for OSINT persona profiling (links identity → passwords).",
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
        if not args:
            print_info(self.help_text)
            return True
        sub = str(args[0]).lower()
        if sub == "doctor":
            return self._run_doctor(args[1:])
        if sub == "explain" and len(args) >= 2:
            return self._run_explain(args[1])
        if sub == "replay" and len(args) >= 2:
            return self._run_replay(args[1:])
        if sub == "retest" and len(args) >= 2:
            return self._run_retest(args[1])
        if sub == "profiles":
            for name, description in list_mission_profiles().items():
                print_info(f"{name}: {description}")
            return True
        if sub == "metadata":
            if len(args) >= 2 and str(args[1]).lower() == "annotate":
                return self._run_metadata_annotate(args[2:])
            if len(args) >= 2 and str(args[1]).lower() == "upgrade":
                return self._run_metadata_upgrade(args[2:])
            if len(args) >= 2 and str(args[1]).lower() == "families":
                return self._run_metadata_families(args[2:])
            if len(args) >= 2 and str(args[1]).lower() == "contract":
                return self._run_metadata_contract(args[2:])
            return self._run_metadata(args[1:])
        if sub == "benchmark":
            return self._run_benchmark(args[1:])
        try:
            parsed = self.parser.parse_args(args)
        except SystemExit:
            return False

        if parsed.help or (not parsed.target and not parsed.resume):
            print_info(self.help_text)
            return bool(parsed.help)

        profile_overrides = {}
        if getattr(parsed, "profile", None):
            try:
                profile_overrides = apply_mission_profile(parsed.profile)
            except ValueError as exc:
                print_error(str(exc))
                return False
            if not parsed.safety_profile or parsed.safety_profile == "normal":
                parsed.safety_profile = profile_overrides.get("safety_profile", parsed.safety_profile)
            if not parsed.request_budget:
                parsed.request_budget = int(profile_overrides.get("request_budget", 0) or 0)
            if parsed.http_replay == "safe" and profile_overrides.get("http_replay"):
                parsed.http_replay = profile_overrides.get("http_replay", parsed.http_replay)
            if profile_overrides.get("plan_only"):
                parsed.plan_only = True
            if profile_overrides.get("reuse_proxy_auth"):
                parsed.reuse_proxy_auth = True
            for risk in profile_overrides.get("approved_risks") or []:
                token = str(risk).strip().lower()
                if token and token not in {str(v).strip().lower() for v in (parsed.approve_risk or [])}:
                    parsed.approve_risk.append(token)

        scanner = ScannerCommand(self.framework, self.session, self.output_handler)
        workspace = (
            self.framework.get_current_workspace_name()
            if hasattr(self.framework, "get_current_workspace_name")
            else "default"
        )
        paths = AgentPathService(self.framework)
        run_id = str(parsed.resume or new_run_id())
        run_store = AgentRunStore(paths, run_id)
        self._agent.report.set_paths(paths)
        self._agent.core._module_perf.set_paths(paths)
        self._agent.core._module_ctx.set_paths(paths)
        self._agent.core._module_health.set_paths(paths)

        approved_risks = []
        for value in parsed.approve_risk or []:
            approved_risks.extend(part.strip() for part in str(value).split(",") if part.strip())
        try:
            runtime_policy = AgentRuntimePolicy.from_options(
                safety_profile=parsed.safety_profile,
                approved_risks=approved_risks,
                approve_active_replay=parsed.approve_active_replay,
                approve_post_exploit=parsed.approve_post_exploit,
                tls_verify=not parsed.tls_no_verify,
                tls_ca_bundle=parsed.tls_ca,
                dry_run=parsed.dry_run,
                plan_only=parsed.plan_only,
                session_policy="never" if parsed.no_interact else parsed.session_policy,
                mission_profile=profile_overrides.get("catalog_policy") or parsed.profile or "",
                deadline_seconds=parsed.deadline,
                policy_file=parsed.policy,
            )
        except (OSError, ValueError) as exc:
            print_error(f"Invalid agent policy: {exc}")
            return False

        if parsed.http_replay == "active" and not runtime_policy.approve_active_replay:
            print_error("--http-replay active requires --approve-active-replay or policy approval")
            return False
        if parsed.shell_hunter:
            from interfaces.command_system.builtin.agent.runtime_policy import shell_hunter_policy_decision

            block = shell_hunter_policy_decision(runtime_policy, phase="exploit")
            if block is not None:
                print_error(
                    f"--shell-hunter blocked: {block.reason} "
                    f"(phase={block.phase}, risk={block.risk}, approval_needed={block.approval_needed})"
                )
                return False
        if parsed.seed is not None:
            random.seed(parsed.seed)

        resumed_payload = {}
        if parsed.resume:
            try:
                resumed_payload = run_store.load_checkpoint()
            except (OSError, ValueError) as exc:
                print_error(f"Could not resume agent run {run_id}: {exc}")
                return False
            checkpoint_state = resumed_payload.get("state") or {}
            if not parsed.target:
                parsed.target = checkpoint_state.get("raw_target")
            if parsed.restart_phase:
                checkpoint_state["current_phase"] = parsed.restart_phase

        lab_hint_kb = {}
        # Bare `agent 127.0.0.1`: probe loopback ports and seed them into KB.
        # Only rewrite when :80/:443 is closed (remapped lab) or operator asked
        # for shell/SSH — never prefer :8080 over an open :80.
        try:
            from interfaces.command_system.builtin.agent.lab_target_hint import (
                detect_loopback_lab_hint,
            )

            lab_hint = detect_loopback_lab_hint(
                str(parsed.target or ""),
                protocol=parsed.protocol,
                goal=getattr(parsed, "goal", None),
                resolver=self._agent.target_resolver,
            )
        except Exception:
            lab_hint = None
        if lab_hint is not None:
            if lab_hint.message:
                print_status(lab_hint.message)
            if lab_hint.rewritten:
                parsed.target = lab_hint.target
                if not parsed.protocol and lab_hint.protocol:
                    parsed.protocol = lab_hint.protocol
                if not getattr(parsed, "goal", None) and lab_hint.goal:
                    parsed.goal = lab_hint.goal
                # Only arm shell-hunter when we actually rewrote to SSH.
                if lab_hint.protocol == "ssh" and not parsed.shell_hunter:
                    parsed.shell_hunter = True
                # Approve credential spray for SSH obtain-shell without switching to
                # an ``internal-lab`` profile (that would look like lab cheating).
                if lab_hint.protocol == "ssh":
                    for risk in ("intrusive", "active", "read"):
                        if risk not in {
                            str(v).strip().lower() for v in (parsed.approve_risk or [])
                        }:
                            parsed.approve_risk.append(risk)
                    approved_risks = []
                    for value in parsed.approve_risk or []:
                        approved_risks.extend(
                            part.strip() for part in str(value).split(",") if part.strip()
                        )
                    runtime_policy = AgentRuntimePolicy.from_options(
                        safety_profile=parsed.safety_profile,
                        approved_risks=approved_risks,
                        approve_active_replay=parsed.approve_active_replay,
                        approve_post_exploit=bool(parsed.approve_post_exploit),
                        tls_verify=not parsed.tls_no_verify,
                        tls_ca_bundle=parsed.tls_ca,
                        dry_run=parsed.dry_run,
                        plan_only=parsed.plan_only,
                        session_policy="never" if parsed.no_interact else parsed.session_policy,
                        mission_profile=str(parsed.profile or ""),
                        deadline_seconds=parsed.deadline,
                        policy_file=parsed.policy,
                    )
            # Port discovery only — never seed lab_manifest / ground-truth creds.
            lab_hint_kb = dict(lab_hint.knowledge_base or {})
            lab_hint_kb.pop("lab_manifest", None)
            lab_hint_kb.pop("credentials", None)

        target_value = self._agent.target_resolver.normalize_target_input(
            parsed.target,
            parsed.protocol or ("http" if runtime_policy.dry_run else None),
        )
        target_info = scanner._parse_target(target_value)
        if not target_info:
            print_error(f"Invalid target: {parsed.target}")
            return False

        # Fail closed on public targets: internal-lab must never widen approvals there.
        # Loopback without attestation is warned (oracle still fails-closed in helper).
        mission = str(
            profile_overrides.get("catalog_policy") or parsed.profile or ""
        ).strip().lower()
        if mission == "internal-lab":
            from interfaces.command_system.builtin.agent.benchmark.internal_lab_gate import (
                is_loopback_target,
                is_synthetic_lab_target,
                require_internal_lab_attestation,
            )

            prior_kb = {}
            if isinstance(resumed_payload.get("state"), dict):
                prior_kb = resumed_payload["state"].get("knowledge_base") or {}
            target_token = str(parsed.target or target_value)
            lab_allowed, lab_reason = require_internal_lab_attestation(
                profile="internal-lab",
                target=target_token,
                knowledge_base=prior_kb if isinstance(prior_kb, dict) else {},
                allow_synthetic_lab=True,
            )
            if not lab_allowed:
                if is_synthetic_lab_target(target_token):
                    pass
                elif is_loopback_target(target_token):
                    print_warning(
                        f"internal-lab without attestation on loopback: {lab_reason}. "
                        "Prefer `lab reset <id>` before benchmark/live runs."
                    )
                else:
                    print_error(
                        f"internal-lab profile blocked: {lab_reason}. "
                        "Use a lab target with attestation (`lab reset <id>`) "
                        "or a non-lab mission profile."
                    )
                    return False

        module_capability_catalog = self._agent.module_catalog.build_module_capability_catalog()
        delay_min = max(0.0, float(parsed.request_delay_min))
        delay_max = max(0.0, float(parsed.request_delay_max))
        if delay_max < delay_min:
            delay_max = delay_min
        threads = max(1, int(parsed.threads))
        max_modules = max(5, int(parsed.max_modules))
        recon_modules = max(3, int(parsed.recon_modules))
        request_budget = max(0, int(parsed.request_budget or 0))
        llm_budget = max(0, int(parsed.llm_budget or 0))

        if runtime_policy.safety_profile == "discreet":
            threads = 1
            max_modules = min(max_modules, DISCREET_PROFILE_DEFAULT_MAX_MODULES)
            recon_modules = min(recon_modules, DISCREET_PROFILE_DEFAULT_RECON_MODULES)
            request_budget = request_budget or DISCREET_PROFILE_DEFAULT_REQUEST_BUDGET
            llm_budget = llm_budget or DISCREET_PROFILE_MAX_LLM_CALLS
            if delay_max <= 0:
                delay_min = DISCREET_PROFILE_DEFAULT_DELAY_MIN
                delay_max = DISCREET_PROFILE_DEFAULT_DELAY_MAX
            parsed.async_probes = False
        elif runtime_policy.safety_profile == "safe":
            threads = 1

        scope_guard = AgentScopeGuard(
            getattr(self.framework, "scope_manager", None),
            runtime_policy,
        )
        target_url = str(target_info.get("url") or target_value)
        if runtime_policy.dry_run:
            manager = getattr(self.framework, "scope_manager", None)
            if manager is not None and getattr(manager, "enabled", False):
                decision = manager.is_target_allowed(str(target_info.get("hostname") or ""))
                allowed, reason = decision.allowed, decision.reason
            else:
                allowed, reason = True, "dry-run scope preview; DNS resolution skipped"
        elif "://" in target_url:
            allowed, reason = scope_guard.validate_url(target_url)
        else:
            allowed, reason = scope_guard.validate_destination(
                target_info.get("hostname", ""),
                int(target_info.get("port") or 0),
                str(parsed.protocol or target_info.get("scheme") or "tcp"),
            )
        if not allowed:
            print_error(f"Agent scope blocked target: {reason}")
            return False

        raw_operator_goal = (
            getattr(parsed, "goal", None) or profile_overrides.get("campaign_goal") or ""
        )
        normalized_operator_goal = (
            normalize_goal(raw_operator_goal) if str(raw_operator_goal).strip() else None
        )
        shell_goal = is_shell_operator_goal(normalized_operator_goal)
        if shell_goal:
            from interfaces.command_system.builtin.agent.runtime_policy import ModuleRisk

            intrusive = ModuleRisk(
                "intrusive",
                ("active_exploitation",),
                1,
                False,
                True,
                True,
            )
            if not runtime_policy.risk_approved(intrusive):
                print_warning(
                    "Goal obtain-shell: intrusive exploits are blocked without "
                    "--approve-risk intrusive (or --profile internal-lab). "
                    "Without that flag the agent can recon/plan but will skip RCE/shell modules."
                )
        replay_max = max(0, int(parsed.http_replay_max))
        if shell_goal and replay_max <= 3:
            replay_max = 8

        state = AgentState(
            raw_target=parsed.target,
            target_info=target_info,
            scanner=scanner,
            protocol=parsed.protocol,
            expanded_surface=bool(getattr(parsed, "expanded_surface", False)),
            threads=threads,
            verbose=parsed.verbose,
            no_exploit=parsed.no_exploit,
            safety_profile=runtime_policy.safety_profile,
            user_agent=str(parsed.user_agent or DEFAULT_AGENT_USER_AGENT),
            request_delay_min=delay_min,
            request_delay_max=delay_max,
            request_budget=request_budget,
            llm_budget=llm_budget,
            async_probes=bool(parsed.async_probes),
            proxy_flows=not bool(parsed.no_proxy_flows),
            proxy_flow_limit=max(0, int(parsed.proxy_flow_limit)),
            http_replay=str(parsed.http_replay or "safe"),
            http_replay_max=replay_max,
            reuse_proxy_auth=bool(parsed.reuse_proxy_auth),
            shell_hunter=bool(parsed.shell_hunter),
            llm_local=parsed.llm_local,
            refute_panel=bool(getattr(parsed, "refute_panel", False)),
            llm_model=parsed.llm_model,
            llm_endpoint=parsed.llm_endpoint,
            max_modules=max_modules,
            recon_modules=recon_modules,
            execution_plan=build_goal_plan(
                getattr(parsed, "goal", None) or profile_overrides.get("campaign_goal"),
                request_budget=request_budget or 0,
            ) if getattr(parsed, "goal", None) or profile_overrides.get("campaign_goal") else {
                "next_actions": [],
                "max_requests_next_phase": 0,
                "stop_conditions": [],
                "reasoning_confidence": 0.0,
                "skip_exploitation": False,
            },
            campaign_goal=normalized_operator_goal,
            operator_goal=normalized_operator_goal,
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
                "mission_profile": str(parsed.profile or ""),
                "catalog_policy": getattr(runtime_policy, "mission_profile", ""),
                "operator_campaign_goal": normalized_operator_goal or "",
                "shell_hunter_mode": bool(parsed.shell_hunter or shell_goal),
                "persona_name": str(getattr(parsed, "persona_name", "") or "").strip(),
                "authenticated_page_excerpt": "",
                "post_auth_catalog_paths": [],
                "post_auth_exploit_paths": [],
                "auth_milestone": {},
                "credential_store": [],
                "active_auth_context": {},
                "request_intel": {},
                "module_capability_catalog": module_capability_catalog,
                **(lab_hint_kb if isinstance(lab_hint_kb, dict) else {}),
            },
            sessions_before={
                "standard": set(self.framework.session_manager.sessions.keys()),
                "browser": set(self.framework.session_manager.browser_sessions.keys()),
            },
            metrics=AgentMetrics(),
            history_scores=self._agent.report.load_history_scores(),
            state_version=1,
            run_id=run_id,
            workspace=workspace,
            current_phase=str((resumed_payload.get("phase") if resumed_payload else "scan") or "scan"),
            dry_run=bool(runtime_policy.dry_run),
            plan_only=bool(runtime_policy.plan_only),
            checkpoint_enabled=bool(parsed.checkpoint or parsed.resume),
            session_policy=runtime_policy.session_policy,
            random_seed=parsed.seed,
            phase_timeout=max(0.0, float(parsed.phase_timeout or 0.0)),
            runtime_policy=runtime_policy,
            scope_guard=scope_guard,
            cancellation_token=CancellationToken(),
            run_store=run_store,
        )
        # Operator --protocol always wins over any lab-hint KB seed.
        if parsed.protocol:
            state.knowledge_base["protocol"] = str(parsed.protocol).strip().lower()
        elif not state.knowledge_base.get("protocol") and state.protocol:
            state.knowledge_base["protocol"] = str(state.protocol).strip().lower()
        state.network_budget = NetworkBudget(
            limit=request_budget,
            on_change=lambda used, skipped: (
                setattr(state.metrics, "network_units_used", used),
                setattr(state.metrics, "network_units_skipped", skipped),
            ),
        )
        try:
            from core.observability import set_run_id, set_workspace

            set_run_id(run_id)
            set_workspace(workspace)
        except ImportError:
            pass
        if resumed_payload:
            restored = agent_state_from_dict(resumed_payload.get("state") or {})
            for key, value in restored.__dict__.items():
                if key not in {
                    "scanner",
                    "runtime_policy",
                    "scope_guard",
                    "network_budget",
                    "cancellation_token",
                    "run_store",
                }:
                    setattr(state, key, value)
            state.scanner = scanner
            state.runtime_policy = runtime_policy
            state.scope_guard = scope_guard
            state.network_budget = NetworkBudget(
                limit=request_budget or int(restored.request_budget or 0),
                used=int(restored.metrics.network_units_used or 0),
                skipped=int(restored.metrics.network_units_skipped or 0),
                on_change=lambda used, skipped: (
                    setattr(state.metrics, "network_units_used", used),
                    setattr(state.metrics, "network_units_skipped", skipped),
                ),
            )
            state.cancellation_token = CancellationToken()
            state.run_store = run_store
            state.run_id = run_id
            state.workspace = workspace
            if isinstance(state.knowledge_base, dict):
                state.knowledge_base["_vault_run_id"] = run_id
            state.checkpoint_enabled = True
        self._agent.knowledge.bootstrap_knowledge_from_host_profile(state)

        previous_module = capture_module_context(self.framework)
        try:
            try:
                final_state = self._agent.run_agent_flow(state)
            except KeyboardInterrupt:
                state.cancellation_token.cancel("operator_cancelled")
                state.campaign_stop_reason = "operator_cancelled"
                print_warning("Agent cancelled; generating a partial report.")
                final_state = self._agent.core._node_report(state)
            if final_state.error:
                print_error(final_state.error)
                return False

            report_path = final_state.report_path

            if report_path:
                print_success(f"Report generated: {report_path}")
                if final_state.new_sessions and final_state.session_policy == "open-latest":
                    self._open_interactive_session(final_state)
                elif final_state.new_sessions and final_state.session_policy == "ask":
                    try:
                        answer = input("Open the newest agent session? [y/N] ").strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        answer = ""
                    if answer in {"y", "yes"}:
                        self._open_interactive_session(final_state)
                return True
            return False
        finally:
            restore_module_context(self.framework, previous_module, announce=False)

    def _run_doctor(self, args) -> bool:
        as_json = "--json" in [str(value) for value in args]
        doctor = AgentDoctor(self.framework)
        if as_json:
            payload = doctor.run_json()
            print_info(json.dumps(payload, indent=2))
            return bool(payload.get("ok"))
        checks = doctor.run()
        ok = True
        for name, row in checks.items():
            status = bool(row.get("ok"))
            optional = bool(row.get("optional"))
            ok = ok and (status or optional)
            printer = print_success if status else (print_warning if optional else print_error)
            printer(f"agent doctor {name}: {'ok' if status else 'failed'} {row}")
        return ok

    def _run_explain(self, run_id: str) -> bool:
        service = AgentExplainService(self.framework)
        if not service.find_run(run_id):
            print_error(f"No agent run artifacts found for {run_id}")
            return False
        payload = service.explain(run_id)
        print_info(json.dumps(payload, indent=2, default=str))
        return True

    def _run_replay(self, args) -> bool:
        tokens = [str(item) for item in (args or []) if str(item).strip()]
        if not tokens:
            print_error("Usage: agent replay <run_id> [--mode decision|shadow|specialists|chaos|adversarial|execution] [--lab LAB_ID]")
            return False

        run_id = tokens[0]
        mode = "decision"
        lab_id = None
        allow_network = False
        index = 1
        while index < len(tokens):
            token = tokens[index]
            if token == "--mode" and index + 1 < len(tokens):
                mode = str(tokens[index + 1]).strip().lower()
                index += 2
                continue
            if token == "--lab" and index + 1 < len(tokens):
                lab_id = str(tokens[index + 1]).strip()
                index += 2
                continue
            if token == "--allow-network":
                allow_network = True
                index += 1
                continue
            index += 1

        service = AgentReplayService(self.framework)
        if mode == "execution":
            payload = service.replay_execution(run_id, lab_id=lab_id, allow_network=allow_network)
        elif mode == "shadow":
            payload = service.replay_shadow(run_id, allow_network=allow_network)
        elif mode == "specialists":
            payload = service.replay_specialists(run_id, allow_network=allow_network)
        elif mode == "chaos":
            payload = service.replay_chaos(run_id, allow_network=allow_network)
        elif mode == "adversarial":
            payload = service.replay_adversarial(run_id, allow_network=allow_network)
        else:
            payload = service.replay_decision(run_id, allow_network=allow_network)
        if payload.get("error"):
            print_error(str(payload["error"]))
            return False
        print_info(json.dumps(payload, indent=2, default=str))
        return True

    def _run_retest(self, finding_id: str) -> bool:
        service = AgentRetestService(self.framework)
        payload = service.build_retest_plan(finding_id)
        if payload.get("error"):
            print_warning(str(payload["error"]))
        print_info(json.dumps(payload, indent=2, default=str))
        return "execution_plan" in payload

    def _run_benchmark(self, args) -> bool:
        from interfaces.command_system.builtin.agent.benchmark.service import AgentBenchmarkService
        from interfaces.command_system.builtin.agent.benchmark.suites import list_benchmark_suites

        tokens = [str(arg) for arg in (args or [])]
        if tokens and tokens[0].lower() == "phase3-validate":
            return self._run_phase3_validation(tokens[1:])
        if tokens and tokens[0].lower() == "phase4-validate":
            return self._run_phase4_validation(tokens[1:])
        if tokens and tokens[0].lower() == "phase5-validate":
            return self._run_phase5_validation(tokens[1:])
        if tokens and tokens[0].lower() == "phase6-validate":
            return self._run_phase6_validation(tokens[1:])
        if tokens and tokens[0].lower() in {"team008-validate", "multiagent-ab"}:
            return self._run_team008_validation(tokens[1:])
        if tokens and tokens[0].lower() == "release-gate":
            return self._run_release_gate(tokens[1:])
        if tokens and tokens[0].lower() == "dashboard":
            return self._run_benchmark_dashboard(tokens[1:])

        if not tokens or tokens[0].lower() == "list":
            for row in list_benchmark_suites():
                status = f" [{row.status}]" if row.status != "active" else ""
                print_info(f"{row.id}{status}: {row.description}")
            return True

        if tokens and tokens[0].lower() == "run":
            tokens = tokens[1:]
            if not tokens:
                print_error("Usage: agent benchmark run <suite> [--runs N] [--seed S] [--model M]")
                return False

        suite_id = tokens[0]
        runs = 1
        seed = None
        model = None
        offline = "--offline" in tokens
        reset_between_runs = None
        if "--reset-between-runs" in tokens:
            reset_between_runs = True
        if "--no-reset-between-runs" in tokens:
            reset_between_runs = False
        output_path = None
        run_ids: list[str] = []
        if "--runs" in tokens:
            idx = tokens.index("--runs")
            if idx + 1 < len(tokens):
                try:
                    runs = max(1, int(tokens[idx + 1]))
                except ValueError:
                    runs = 1
        if "--seed" in tokens:
            idx = tokens.index("--seed")
            if idx + 1 < len(tokens):
                try:
                    seed = int(tokens[idx + 1])
                except ValueError:
                    seed = None
        if "--model" in tokens:
            idx = tokens.index("--model")
            if idx + 1 < len(tokens):
                model = tokens[idx + 1]
        if "--output" in tokens:
            idx = tokens.index("--output")
            if idx + 1 < len(tokens):
                output_path = tokens[idx + 1]
        for index, token in enumerate(tokens):
            if token == "--run-id" and index + 1 < len(tokens):
                run_ids.append(tokens[index + 1])

        service = AgentBenchmarkService(self.framework)
        try:
            result = service.run_suite(
                suite_id,
                runs=runs,
                seed=seed,
                model=model,
                offline=offline,
                run_ids=run_ids or None,
                output_path=output_path,
                reset_between_runs=reset_between_runs,
            )
        except (KeyError, RuntimeError, ValueError) as exc:
            print_error(str(exc))
            return False

        payload = result.to_dict()
        print_info(json.dumps(payload, indent=2, default=str))
        mcr = float(payload.get("north_star", {}).get("mission_completion_rate", 0.0) or 0.0)
        mcr_meta = (payload.get("metadata") or {}).get("mcr") or {}
        ci = mcr_meta.get("wilson_ci95") or []
        ci_txt = f" IC95=[{ci[0]:.1%}, {ci[1]:.1%}]" if len(ci) == 2 else ""
        print_success(
            f"Benchmark {result.id}: mission completion rate={mcr:.0%} "
            f"({sum(1 for row in result.runs if row.mission_completed)}/{len(result.runs)} runs)"
            f"{ci_txt}"
        )
        if result.metadata.get("latest_path"):
            print_info(f"Latest report: {result.metadata['latest_path']}")
        return mcr >= 1.0 or (offline and bool(result.runs))

    def _run_phase3_validation(self, args) -> bool:
        from interfaces.command_system.builtin.agent.benchmark.phase3_validation import Phase3ValidationService

        tokens = [str(arg) for arg in (args or [])]
        micro_seeds = 32
        integration_runs = 10
        skip_integration = "--skip-integration" in tokens
        output_path = None
        if "--micro-seeds" in tokens:
            idx = tokens.index("--micro-seeds")
            if idx + 1 < len(tokens):
                try:
                    micro_seeds = max(4, int(tokens[idx + 1]))
                except ValueError:
                    micro_seeds = 32
        if "--runs" in tokens:
            idx = tokens.index("--runs")
            if idx + 1 < len(tokens):
                try:
                    integration_runs = max(1, int(tokens[idx + 1]))
                except ValueError:
                    integration_runs = 10
        if "--output" in tokens:
            idx = tokens.index("--output")
            if idx + 1 < len(tokens):
                output_path = tokens[idx + 1]

        service = Phase3ValidationService(self.framework)
        report = service.validate(
            integration_runs=integration_runs,
            micro_seeds=micro_seeds,
            skip_integration=skip_integration,
            output_path=output_path,
        )
        payload = report.to_dict()
        print_info(json.dumps(payload, indent=2, default=str))
        if report.passed:
            print_success(
                f"Phase 3 validated: hierarchical MCR {report.hierarchical_mcr:.0%} "
                f"vs heuristic {report.heuristic_mcr:.0%} "
                f"(delta +{report.mcr_delta:.0%}, threshold +{report.mcr_delta_threshold:.0%})"
            )
        else:
            print_warning(
                f"Phase 3 not validated: delta {report.mcr_delta:.0%} "
                f"(need +{report.mcr_delta_threshold:.0%})"
            )
        return report.passed

    def _run_phase4_validation(self, args) -> bool:
        from interfaces.command_system.builtin.agent.benchmark.phase4_validation import Phase4ValidationService

        tokens = [str(arg) for arg in (args or [])]
        micro_seeds = 32
        integration_runs = 30
        skip_integration = "--skip-integration" in tokens
        output_path = None
        if "--micro-seeds" in tokens:
            idx = tokens.index("--micro-seeds")
            if idx + 1 < len(tokens):
                try:
                    micro_seeds = max(4, int(tokens[idx + 1]))
                except ValueError:
                    micro_seeds = 32
        if "--runs" in tokens:
            idx = tokens.index("--runs")
            if idx + 1 < len(tokens):
                try:
                    integration_runs = max(1, int(tokens[idx + 1]))
                except ValueError:
                    integration_runs = 30
        if "--output" in tokens:
            idx = tokens.index("--output")
            if idx + 1 < len(tokens):
                output_path = tokens[idx + 1]

        service = Phase4ValidationService(self.framework)
        report = service.validate(
            integration_runs=integration_runs,
            micro_seeds=micro_seeds,
            skip_integration=skip_integration,
            output_path=output_path,
        )
        payload = report.to_dict()
        print_info(json.dumps(payload, indent=2, default=str))
        if report.passed:
            print_success(
                f"Phase 4 validated: MCR {report.mcr:.0%} "
                f"(threshold {report.mcr_threshold:.0%}, "
                f"CI [{report.mcr_ci[0]:.0%}, {report.mcr_ci[1]:.0%}])"
            )
        else:
            print_warning(
                f"Phase 4 not validated: MCR {report.mcr:.0%} "
                f"(need {report.mcr_threshold:.0%})"
            )
        return report.passed

    def _run_phase5_validation(self, args) -> bool:
        from interfaces.command_system.builtin.agent.benchmark.phase5_validation import Phase5ValidationService

        tokens = [str(arg) for arg in (args or [])]
        micro_seeds = 24
        output_path = None
        if "--micro-seeds" in tokens:
            idx = tokens.index("--micro-seeds")
            if idx + 1 < len(tokens):
                try:
                    micro_seeds = max(4, int(tokens[idx + 1]))
                except ValueError:
                    micro_seeds = 24
        if "--output" in tokens:
            idx = tokens.index("--output")
            if idx + 1 < len(tokens):
                output_path = tokens[idx + 1]

        service = Phase5ValidationService(self.framework)
        report = service.validate(micro_seeds=micro_seeds, output_path=output_path)
        payload = report.to_dict()
        print_info(json.dumps(payload, indent=2, default=str))
        if report.passed:
            print_success(
                f"Phase 5 validated: MCR {report.mcr:.0%} "
                f"(threshold {report.mcr_threshold:.0%}, "
                f"CI [{report.mcr_ci[0]:.0%}, {report.mcr_ci[1]:.0%}])"
            )
        else:
            print_warning(
                f"Phase 5 not validated: MCR {report.mcr:.0%} "
                f"(need {report.mcr_threshold:.0%})"
            )
        return report.passed

    def _run_phase6_validation(self, args) -> bool:
        from interfaces.command_system.builtin.agent.benchmark.phase6_validation import Phase6ValidationService

        tokens = [str(arg) for arg in (args or [])]
        micro_seeds = 24
        output_path = None
        if "--micro-seeds" in tokens:
            idx = tokens.index("--micro-seeds")
            if idx + 1 < len(tokens):
                try:
                    micro_seeds = max(4, int(tokens[idx + 1]))
                except ValueError:
                    micro_seeds = 24
        if "--output" in tokens:
            idx = tokens.index("--output")
            if idx + 1 < len(tokens):
                output_path = tokens[idx + 1]

        service = Phase6ValidationService(self.framework)
        report = service.validate(micro_seeds=micro_seeds, output_path=output_path)
        payload = report.to_dict()
        print_info(json.dumps(payload, indent=2, default=str))
        if report.passed:
            print_success(
                f"Phase 6 validated: MCR {report.mcr:.0%} "
                f"(threshold {report.mcr_threshold:.0%}, "
                f"CI [{report.mcr_ci[0]:.0%}, {report.mcr_ci[1]:.0%}])"
            )
        else:
            print_warning(
                f"Phase 6 not validated: MCR {report.mcr:.0%} "
                f"(need {report.mcr_threshold:.0%})"
            )
        return report.passed

    def _run_team008_validation(self, args) -> bool:
        from interfaces.command_system.builtin.agent.benchmark.team008_validation import (
            Team008ValidationService,
        )

        tokens = [str(arg) for arg in (args or [])]
        runs = 32
        seed = 42
        # Micro oracles are authoritative; live integration A/B is not wired yet.
        skip_integration = True
        output_path = None
        if "--runs" in tokens:
            idx = tokens.index("--runs")
            if idx + 1 < len(tokens):
                try:
                    runs = max(4, int(tokens[idx + 1]))
                except ValueError:
                    runs = 32
        if "--micro-seeds" in tokens:
            idx = tokens.index("--micro-seeds")
            if idx + 1 < len(tokens):
                try:
                    runs = max(4, int(tokens[idx + 1]))
                except ValueError:
                    runs = 32
        if "--seed" in tokens:
            idx = tokens.index("--seed")
            if idx + 1 < len(tokens):
                try:
                    seed = int(tokens[idx + 1])
                except ValueError:
                    seed = 42
        if "--output" in tokens:
            idx = tokens.index("--output")
            if idx + 1 < len(tokens):
                output_path = tokens[idx + 1]

        service = Team008ValidationService(self.framework)
        report = service.validate(
            runs=runs,
            seed=seed,
            skip_integration=skip_integration,
            output_path=output_path,
        )
        payload = report.to_dict()
        print_info(json.dumps(payload, indent=2, default=str))
        if report.passed:
            print_success(
                f"TEAM-008 validated: multi MCR {report.multi_mcr:.0%} "
                f"vs mono {report.mono_mcr:.0%} "
                f"(delta +{report.mcr_delta:.0%}, useless reduction {report.useless_reduction:.0%})"
            )
        else:
            print_warning(
                f"TEAM-008 not validated: MCR delta {report.mcr_delta:.0%} "
                f"(need +{report.mcr_delta_threshold:.0%} or "
                f"{report.useless_reduction_threshold:.0%} fewer useless actions)"
            )
        return report.passed

    def _run_release_gate(self, args) -> bool:
        from pathlib import Path

        from interfaces.command_system.builtin.agent.benchmark.release_gate import (
            evaluate_release_gate,
            write_release_gate_report,
        )

        tokens = [str(arg) for arg in (args or [])]
        baseline_path = None
        output_path = None
        if "--baseline" in tokens:
            idx = tokens.index("--baseline")
            if idx + 1 < len(tokens):
                baseline_path = Path(tokens[idx + 1])
        if "--output" in tokens:
            idx = tokens.index("--output")
            if idx + 1 < len(tokens):
                output_path = Path(tokens[idx + 1])

        report = evaluate_release_gate(baseline_path=baseline_path)
        write_release_gate_report(report, output_path=output_path)
        print_info(json.dumps(report.to_dict(), indent=2, default=str))
        if report.passed:
            print_success("Release gate passed: no MCR/safety regressions.")
        else:
            print_warning(
                f"Release gate blocked: {len(report.regressions)} regression(s)."
            )
        return report.passed

    def _run_benchmark_dashboard(self, args) -> bool:
        from pathlib import Path

        from interfaces.command_system.builtin.agent.benchmark.release_gate import (
            build_regression_dashboard,
        )

        tokens = [str(arg) for arg in (args or [])]
        output_path = None
        if "--output" in tokens:
            idx = tokens.index("--output")
            if idx + 1 < len(tokens):
                output_path = Path(tokens[idx + 1])
        dashboard = build_regression_dashboard(output_path=output_path)
        print_info(json.dumps(dashboard, indent=2, default=str))
        print_success("Benchmark dashboard written.")
        return True

    def _run_metadata(self, args) -> bool:
        from interfaces.command_system.builtin.agent.metadata_linter import format_audit_table

        as_json = "--json" in [str(arg).lower() for arg in (args or [])]
        audit = self._agent.module_catalog.audit_agent_metadata(limit_sample=20)
        if as_json:
            print_info(json.dumps(audit, indent=2))
            return True
        print_info(format_audit_table(audit))
        chain_ratio = float(audit.get("chain_coverage_ratio", 0) or 0)
        print_info(
            f"Effective chain coverage: {audit.get('chain_ready', 0)}/"
            f"{audit.get('total_modules', 0)} ({chain_ratio * 100:.1f}%)"
        )
        if int(audit.get("compliant", 0) or 0) == 0:
            print_warning(
                "No module exposes compliant agent metadata yet. "
                "Use `agent metadata --json` for the full audit sample."
            )
        return True

    @staticmethod
    def _metadata_suite_id(tokens: list[str], default: str = "metasploitable3-linux") -> str:
        if "--suite" in tokens:
            idx = tokens.index("--suite")
            if idx + 1 < len(tokens):
                return str(tokens[idx + 1]).strip().lower() or default
        return default

    def _run_metadata_families(self, args) -> bool:
        from interfaces.command_system.builtin.agent.benchmark.module_families import (
            audit_family_compliance,
            families_for_suite,
            format_family_audit_report,
        )

        tokens = [str(arg) for arg in (args or [])]
        as_json = "--json" in [token.lower() for token in tokens]
        suite_id = self._metadata_suite_id(tokens)
        discovered = self._agent.module_catalog._get_module_catalog()
        audit = audit_family_compliance(
            discovered,
            extract_metadata=self._agent.module_catalog.extract_static_module_metadata,
            families=families_for_suite(suite_id),
        )
        audit["suite_id"] = suite_id
        if as_json:
            print_info(json.dumps(audit, indent=2))
        else:
            print_info(f"Benchmark family audit for suite `{suite_id}`:")
            print_info(format_family_audit_report(audit))
        return bool(audit.get("overall_ok"))

    def _run_metadata_contract(self, args) -> bool:
        from interfaces.command_system.builtin.agent.golden_path_validation import validate_golden_path_catalog
        from interfaces.command_system.builtin.agent.module_contract_tests import (
            run_priority_contract_tests,
            run_suite_contract_tests,
        )

        tokens = [str(arg) for arg in (args or [])]
        as_json = "--json" in [token.lower() for token in tokens]
        strict = "--strict" in [token.lower() for token in tokens]
        discovered = self._agent.module_catalog._get_module_catalog()
        extract = self._agent.module_catalog.extract_static_module_metadata
        if "--golden-paths" in tokens:
            payload = validate_golden_path_catalog(
                discovered,
                extract_metadata=extract,
                os_name="linux",
                strict=strict,
            )
        elif "--suite" in tokens:
            payload = run_suite_contract_tests(
                discovered,
                self._metadata_suite_id(tokens),
                extract_metadata=extract,
                strict=strict,
            )
        else:
            payload = run_priority_contract_tests(
                discovered,
                extract_metadata=extract,
                strict=strict,
            )
        if as_json:
            print_info(json.dumps(payload, indent=2))
        else:
            print_info(json.dumps(payload, indent=2))
        return bool(payload.get("ok"))

    def _run_metadata_annotate(self, args) -> bool:
        from interfaces.command_system.builtin.agent.metadata_annotator import (
            DEFAULT_FAMILIES,
            annotate_benchmark_suite,
            annotate_catalog,
        )

        tokens = [str(arg) for arg in (args or [])]
        dry_run = "--apply" not in tokens
        families = DEFAULT_FAMILIES
        if "--family" in tokens:
            idx = tokens.index("--family")
            if idx + 1 < len(tokens):
                families = tuple(part.strip() for part in tokens[idx + 1].split(",") if part.strip())
        limit = 0
        if "--limit" in tokens:
            idx = tokens.index("--limit")
            if idx + 1 < len(tokens):
                try:
                    limit = max(0, int(tokens[idx + 1]))
                except ValueError:
                    limit = 0
        discovered = self._agent.module_catalog._get_module_catalog()
        if "--suite" in tokens:
            payload = annotate_benchmark_suite(
                discovered,
                self._agent.module_catalog.extract_static_module_metadata,
                self._metadata_suite_id(tokens),
                dry_run=dry_run,
                limit=limit,
            )
        else:
            payload = annotate_catalog(
                discovered,
                self._agent.module_catalog.extract_static_module_metadata,
                families=families,
                dry_run=dry_run,
                limit=limit,
            )
        print_info(json.dumps(payload, indent=2))
        if dry_run:
            print_warning("Dry-run only. Re-run with --apply to write agent metadata blocks.")
        else:
            self._agent.module_catalog.invalidate_module_catalog_cache()
            print_success(f"Annotated {payload.get('updated', 0)} module file(s).")
        return True

    def _run_metadata_upgrade(self, args) -> bool:
        from interfaces.command_system.builtin.agent.metadata_annotator import (
            DEFAULT_FAMILIES,
            upgrade_benchmark_suite,
            upgrade_catalog,
        )

        tokens = [str(arg) for arg in (args or [])]
        dry_run = "--apply" not in tokens
        families = DEFAULT_FAMILIES
        if "--family" in tokens:
            idx = tokens.index("--family")
            if idx + 1 < len(tokens):
                families = tuple(part.strip() for part in tokens[idx + 1].split(",") if part.strip())
        limit = 0
        if "--limit" in tokens:
            idx = tokens.index("--limit")
            if idx + 1 < len(tokens):
                try:
                    limit = max(0, int(tokens[idx + 1]))
                except ValueError:
                    limit = 0
        discovered = self._agent.module_catalog._get_module_catalog()
        if "--suite" in tokens:
            payload = upgrade_benchmark_suite(
                discovered,
                self._agent.module_catalog.extract_static_module_metadata,
                self._metadata_suite_id(tokens),
                dry_run=dry_run,
                limit=limit,
            )
        else:
            payload = upgrade_catalog(
                discovered,
                self._agent.module_catalog.extract_static_module_metadata,
                families=families,
                dry_run=dry_run,
                limit=limit,
            )
        print_info(json.dumps(payload, indent=2))
        if dry_run:
            print_warning("Dry-run only. Re-run with --apply to write chain metadata blocks.")
        else:
            self._agent.module_catalog.invalidate_module_catalog_cache()
            print_success(f"Upgraded {payload.get('updated', 0)} module file(s).")
        return True
