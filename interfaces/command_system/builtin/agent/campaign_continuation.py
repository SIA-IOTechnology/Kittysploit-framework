#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect remaining shell-campaign pivots before allowing low-novelty stop."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.goal_planner import (
    SHELL_API_MODULE_LADDER,
    _module_observed_in_kb,
    is_shell_operator_goal,
    kb_api_surface_ready,
    kb_client_js_surface_ready,
    kb_subdomain_surface_expandable,
    suggest_shell_plan_followups,
)

_JS_HINTS = frozenset({"nextjs", "nodejs", "react", "javascript", "angular", "vue"})
_AUTH_NEEDLES = ("login_page", "admin_login", "bruteforce", "login_form")
_CMS_PROBE_PATHS: Sequence[tuple[str, str]] = (
    ("auxiliary/scanner/http/drupal_scanner", "drupal"),
    ("auxiliary/scanner/http/wordpress_scanner", "wordpress"),
    ("auxiliary/scanner/http/joomla_scanner", "joomla"),
)


def kb_has_unscanned_subdomains(kb: Mapping[str, Any]) -> bool:
    return kb_subdomain_surface_expandable(kb if isinstance(kb, dict) else {})


def kb_has_untested_js_endpoints(kb: Mapping[str, Any]) -> bool:
    if not isinstance(kb, dict):
        return False
    if not kb_client_js_surface_ready(kb):
        return False
    return (
        not _module_observed_in_kb(kb, "js_endpoint")
        or not _module_observed_in_kb(kb, "js_sourcemap")
    )


def kb_has_untested_api(kb: Mapping[str, Any]) -> bool:
    if not isinstance(kb, dict) or not kb_api_surface_ready(kb):
        return False
    for _path, needle in SHELL_API_MODULE_LADDER:
        if not _module_observed_in_kb(kb, needle):
            return True
    return False


def kb_has_unevaluated_auth(kb: Mapping[str, Any]) -> bool:
    if not isinstance(kb, dict):
        return False
    signals = {str(s).lower() for s in kb.get("risk_signals", []) or []}
    if signals.intersection({"authenticated_session", "credentials_obtained"}):
        return False
    login_paths = [str(p) for p in kb.get("login_paths", []) or [] if str(p).startswith("/")]
    auth_signal = bool(
        login_paths
        or signals.intersection({"login_surface_detected", "login_form_detected", "login_redirect_detected"})
    )
    if not auth_signal:
        return False
    return not _module_observed_in_kb(kb, *_AUTH_NEEDLES)


def kb_has_compatible_exploit_candidates(
    kb: Mapping[str, Any],
    *,
    stack_mismatch_fn: Optional[Callable[[str, Dict[str, Any]], str]] = None,
    exploit_paths: Optional[Sequence[str]] = None,
) -> bool:
    if not isinstance(kb, dict):
        return False
    observed = {str(p).lower() for p in kb.get("observed_modules", []) or [] if p}
    candidates = list(exploit_paths or [])
    graph = kb.get("attack_graph", {}) or {}
    if isinstance(graph, dict):
        for row in graph.get("exploit_paths", []) or []:
            if isinstance(row, dict):
                path = str(row.get("module_path", "") or row.get("path", "") or "").strip()
                if path:
                    candidates.append(path)
    for row in kb.get("contextual_findings", []) or []:
        if not isinstance(row, dict):
            continue
        exp = str(row.get("exploit_module", "") or "").strip()
        if exp:
            candidates.append(exp)

    kb_dict = dict(kb)
    mismatch = stack_mismatch_fn or (lambda _p, _k: "")
    for raw in candidates:
        path = str(raw or "").strip()
        if not path or path.lower() in observed:
            continue
        if not path.startswith(("exploit/", "exploits/")):
            continue
        if mismatch(path, kb_dict):
            continue
        return True
    return False


def list_shell_continuation_pivots(
    kb: Mapping[str, Any],
    *,
    stack_mismatch_fn: Optional[Callable[[str, Dict[str, Any]], str]] = None,
    exploit_paths: Optional[Sequence[str]] = None,
) -> List[str]:
    """Human-readable tokens describing unfinished shell-oriented work."""
    pivots: List[str] = []
    if kb_has_unscanned_subdomains(kb):
        pivots.append("unscanned_subdomains")
    if kb_has_untested_js_endpoints(kb):
        pivots.append("js_endpoints_pending")
    if kb_has_untested_api(kb):
        pivots.append("api_surface_untested")
    if kb_has_unevaluated_auth(kb):
        pivots.append("auth_unevaluated")
    if kb_has_compatible_exploit_candidates(
        kb,
        stack_mismatch_fn=stack_mismatch_fn,
        exploit_paths=exploit_paths,
    ):
        pivots.append("compatible_exploit_candidate")

    for path in suggest_shell_plan_followups(kb if isinstance(kb, dict) else {})[:4]:
        token = f"followup:{path.split('/')[-1]}"
        if token not in pivots:
            pivots.append(token)
    return pivots


def should_defer_shell_low_novelty_stop(
    kb: Mapping[str, Any],
    *,
    campaign_goal: str = "",
    stack_mismatch_fn: Optional[Callable[[str, Dict[str, Any]], str]] = None,
    exploit_paths: Optional[Sequence[str]] = None,
) -> Tuple[bool, List[str]]:
    """
    Return ``(defer_stop, pivot_tokens)`` for obtain-shell campaigns.

    Defer low-novelty termination while concrete pivots remain.
    """
    if not is_shell_operator_goal(campaign_goal):
        return False, []
    pivots = list_shell_continuation_pivots(
        kb,
        stack_mismatch_fn=stack_mismatch_fn,
        exploit_paths=exploit_paths,
    )
    return bool(pivots), pivots
