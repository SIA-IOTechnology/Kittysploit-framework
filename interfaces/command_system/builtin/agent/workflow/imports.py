#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared imports for agent workflow mixins."""

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
from typing import Any, Dict, List, Optional, Sequence, Tuple

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
    ADMIN_LOGIN_BRUTEFORCE_MODULE,
    is_auth_operator_goal,
    is_exploit_operator_goal,
    is_shell_operator_goal,
    kb_api_surface_ready,
    kb_client_js_surface_ready,
    kb_ssh_surface_ready,
    kb_subdomain_surface_expandable,
    operator_goal_from_mapping,
    path_matches_forced_protocol,
    prioritize_subdomain_hosts,
    product_auth_shell_followups,
    suggest_shell_plan_followups,
    filter_paths_for_product_focus,
    product_focus_skip_reason,
    product_chain_still_pending,
    product_shell_chain_paths,
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
from interfaces.command_system.builtin.agent.exploit_queue import (
    gate_queue_for_exploit,
    load_exploit_queue,
    queue_to_execution_actions,
    sync_exploit_queue_from_findings,
)
from interfaces.command_system.builtin.agent.owasp_mission import (
    filter_queue_by_mission_classes,
    is_owasp_web_parallel_mission,
)
from interfaces.command_system.builtin.agent.module_context_memory import (
    ModuleContextMemory,
    classify_operational_context,
)
from interfaces.command_system.builtin.agent.module_performance_memory import (
    ModulePerformanceMemory,
    classify_target_profile,
    cms_lock_targets,
    dominant_product_stack,
    kb_light_copy,
    should_suppress_cms_lock,
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
