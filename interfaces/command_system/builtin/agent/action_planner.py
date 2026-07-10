#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Goal-aligned action scoring for opportunistic module ranking.

Maps campaign state + module metadata to an :class:`ActionProfile`, then scores it
with :class:`ActionScorer` (expected progress vs cost/noise/redundancy).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set

from interfaces.command_system.builtin.agent.agent_constants import (
    CAMPAIGN_GOAL_EXPLOIT,
    CAMPAIGN_GOAL_OBTAIN_AUTH,
    CAMPAIGN_GOAL_OBTAIN_SHELL,
    CAMPAIGN_GOAL_POST_AUTH,
    CAMPAIGN_GOAL_RECON,
    CAMPAIGN_GOAL_SHELL_STOP,
)
from interfaces.command_system.builtin.agent.module_scoring import (
    estimate_network_cost,
    module_blob_lower,
    module_path_lower,
)


def _normalize_action_tokens(values: Any) -> Set[str]:
    tokens: Set[str] = set()
    raw_items = values if isinstance(values, (list, tuple, set)) else [values]
    for item in raw_items:
        text = str(item or "").strip().lower()
        if not text:
            continue
        tokens.add(text)
        if "/" in text:
            tokens.add(text.rstrip("/").split("/")[-1])
    return tokens


@dataclass
class PlannerState:
    goal: str = "obtain_session"

    has_credentials: bool = False
    has_authenticated_session: bool = False
    has_db_access: bool = False
    has_session_cookie: bool = False
    has_auth_bypass: bool = False
    has_rce: bool = False
    has_shell: bool = False
    has_root: bool = False

    login_detected: bool = False
    login_path_known: bool = False

    executed_actions: Set[str] = field(default_factory=set)
    failed_actions: Set[str] = field(default_factory=set)
    unlocked_capabilities: Set[str] = field(default_factory=set)
    rce_potential: bool = False
    shell_hunter_mode: bool = False


@dataclass
class ActionProfile:
    name: str
    cost: float = 10.0
    noise: float = 5.0
    produces: Dict[str, float] = field(default_factory=dict)
    consumes: Set[str] = field(default_factory=set)


OUTPUT_VALUE: Dict[str, float] = {
    "credentials": 35.0,
    "db_access": 25.0,
    "session_cookie": 50.0,
    "authenticated_session": 60.0,
    "auth_bypass": 70.0,
    "rce": 120.0,
    "shell": 200.0,
    "root": 250.0,
    "csrf_token": 15.0,
    "file_read": 20.0,
    "admin_access": 80.0,
}


class ActionScorer:
    def __init__(self) -> None:
        self.goal_output_weights = {
            "obtain_session": {
                "credentials": 1.0,
                "db_access": 0.9,
                "session_cookie": 1.1,
                "authenticated_session": 1.3,
                "auth_bypass": 1.3,
                "rce": 1.4,
                "shell": 1.6,
                "root": 1.8,
            },
            "obtain_shell": {
                "credentials": 0.7,
                "db_access": 0.7,
                "session_cookie": 0.8,
                "authenticated_session": 1.0,
                "auth_bypass": 1.1,
                "rce": 1.5,
                "shell": 1.8,
                "root": 2.0,
            },
            "privilege_escalation": {
                "credentials": 0.2,
                "db_access": 0.2,
                "session_cookie": 0.3,
                "authenticated_session": 0.4,
                "auth_bypass": 0.4,
                "rce": 0.8,
                "shell": 1.2,
                "root": 2.5,
            },
        }
        self.capability_bonus = 45.0

    def score(self, action: ActionProfile, state: PlannerState) -> float:
        progress = self._expected_progress(action, state)
        multiplier = self._context_multiplier(action, state)
        
        if state.shell_hunter_mode:
            is_high_value = any(token in action.name.lower() for token in ("rce", "shell", "exploit", "upload", "command"))
            if is_high_value or action.produces.get("shell", 0) > 0 or action.produces.get("rce", 0) > 0:
                multiplier *= 2.5

        progress *= multiplier

        redundancy = self._redundancy_penalty(action, state)
        terminal_bonus = self._terminal_bonus(action, state)
        chain_bonus = self._chaining_bonus(action, state)

        return round(progress + terminal_bonus + chain_bonus - action.cost - action.noise - redundancy, 3)

    def _chaining_bonus(self, action: ActionProfile, state: PlannerState) -> float:
        bonus = 0.0
        for cap in action.consumes:
            if cap in state.unlocked_capabilities:
                bonus += self.capability_bonus
        return bonus

    def _expected_progress(self, action: ActionProfile, state: PlannerState) -> float:
        weights = self.goal_output_weights.get(state.goal, self.goal_output_weights["obtain_session"])
        score = 0.0

        for output, probability in action.produces.items():
            base_value = OUTPUT_VALUE.get(output, 0.0)
            goal_weight = weights.get(output, 1.0)
            score += float(probability) * base_value * goal_weight

        return score

    def _context_multiplier(self, action: ActionProfile, state: PlannerState) -> float:
        name = action.name.lower()
        mult = 1.0

        is_bruteforce = "bruteforce" in name
        is_login_action = any(token in name for token in ("login", "auth", "signin"))
        is_sqli = any(token in name for token in ("sql", "sqli", "sql_injection"))
        is_post_auth = "post_auth" in name or "authenticated" in name
        is_rce_action = "rce" in name or "command" in name or "shell" in name

        if state.login_detected and state.login_path_known and not state.has_authenticated_session:
            if is_bruteforce or is_login_action:
                mult *= 1.35

        if state.has_credentials:
            if is_bruteforce:
                mult *= 0.2
            if is_login_action:
                mult *= 1.25

        if state.has_authenticated_session:
            if is_login_action or is_bruteforce:
                mult *= 0.1
            if is_post_auth or is_rce_action:
                mult *= 1.35

        if state.has_db_access and is_sqli:
            mult *= 0.4

        if state.has_rce and not state.has_shell:
            if is_rce_action:
                mult *= 1.3

        if state.has_shell and not state.has_root:
            if "priv" in name or "sudo" in name or "escalat" in name or "root" in name:
                mult *= 1.5

        if state.has_root:
            mult *= 0.05

        return mult

    def _redundancy_penalty(self, action: ActionProfile, state: PlannerState) -> float:
        penalty = 0.0
        if action.name in state.executed_actions:
            penalty += 15.0
        if action.name in state.failed_actions:
            penalty += 25.0
        return penalty

    def _terminal_bonus(self, action: ActionProfile, state: PlannerState) -> float:
        bonus = 0.0
        if not state.has_shell:
            bonus += 20.0 * action.produces.get("shell", 0.0)
            bonus += 12.0 * action.produces.get("rce", 0.0)
            bonus += 10.0 * action.produces.get("authenticated_session", 0.0)
        if state.has_shell and not state.has_root:
            bonus += 30.0 * action.produces.get("root", 0.0)
        return bonus


def _map_campaign_goal_to_planner(raw: Optional[str]) -> str:
    if not raw:
        return "obtain_session"
    normalized = str(raw).strip().lower().replace("_", "-")
    if normalized in ("obtain-shell", "exploit") or raw in (CAMPAIGN_GOAL_EXPLOIT, CAMPAIGN_GOAL_OBTAIN_SHELL):
        return "obtain_shell"
    if raw in (CAMPAIGN_GOAL_POST_AUTH, CAMPAIGN_GOAL_SHELL_STOP) or normalized == "post-auth":
        return "privilege_escalation"
    if raw in (CAMPAIGN_GOAL_OBTAIN_AUTH, CAMPAIGN_GOAL_RECON) or normalized in ("obtain-auth", "recon"):
        return "obtain_session"
    return "obtain_session"


def planner_state_from_kb(kb: Dict[str, Any]) -> PlannerState:
    """Build :class:`PlannerState` from agent knowledge base + optional ``planner_campaign_goal``."""
    kb = kb if isinstance(kb, dict) else {}
    signals = {str(s).lower() for s in kb.get("risk_signals", []) or []}
    hints = [str(h).lower() for h in kb.get("tech_hints", []) or []]
    hint_blob = " ".join(hints)
    observed = [str(p).lower() for p in kb.get("observed_modules", []) or []]
    obs_blob = " ".join(observed)

    login_paths = kb.get("login_paths", []) or []
    has_login_paths = bool([p for p in login_paths if isinstance(p, str) and p.startswith("/")])

    executed: Set[str] = set()
    for p in observed:
        parts = p.rstrip("/").split("/")
        if parts:
            executed.add(parts[-1])
    executed |= _normalize_action_tokens(kb.get("planner_executed_actions", []))
    failed = _normalize_action_tokens(kb.get("planner_failed_actions", []))

    goal = _map_campaign_goal_to_planner(
        str(kb.get("planner_campaign_goal") or kb.get("operator_campaign_goal") or "").strip() or None
    )

    return PlannerState(
        goal=goal,
        has_credentials="credentials_obtained" in signals,
        has_authenticated_session="authenticated_session" in signals,
        has_db_access=(
            "sql_injection" in obs_blob
            or "sqli" in hint_blob
            or "sql_injection" in hint_blob
            or any("sql" in h and "injection" in h for h in hints)
        ),
        has_session_cookie="session_cookie_obtained" in signals,
        has_auth_bypass=any(
            x in signals for x in ("auth_bypass", "bypass_detected")
        )
        or "bypass" in obs_blob,
        has_rce=("rce" in hint_blob or "rce" in obs_blob or any("rce" in o for o in observed)),
        has_shell=bool(
            signals.intersection({"interactive_shell", "shell_obtained"})
        ),
        has_root=("root_access" in signals or "privilege_escalation" in signals),
        login_detected=bool(
            signals.intersection(
                {
                    "login_surface_detected",
                    "login_form_detected",
                    "login_redirect_detected",
                }
            )
        )
        or has_login_paths,
        login_path_known=has_login_paths,
        executed_actions=executed,
        failed_actions=failed,
        unlocked_capabilities={str(c).lower() for c in kb.get("unlocked_capabilities", []) or []},
        rce_potential="rce" in hint_blob or "lfi_detected" in signals or "file_read_success" in signals,
        shell_hunter_mode=bool(kb.get("shell_hunter_mode", False)),
    )


def _infer_produces(path_lower: str, blob: str) -> Dict[str, float]:
    """Heuristic ``produces`` map from module path + metadata blob."""
    if "bruteforce" in path_lower or "admin_login" in path_lower:
        return {"authenticated_session": 0.55, "credentials": 0.35, "session_cookie": 0.4}
    if "sql_injection" in path_lower or "sqli_engine" in path_lower or path_lower.endswith("/sqli") or "django_sqli" in path_lower:
        return {"db_access": 0.75, "credentials": 0.25, "rce": 0.12, "auth_bypass": 0.15}
    if "sqli_shell" in path_lower:
        return {"db_access": 0.85, "credentials": 0.45, "shell": 0.08}
    if "xss" in path_lower or "cors" in path_lower:
        return {"auth_bypass": 0.2, "credentials": 0.08}
    if "lfi" in path_lower or "rfi" in path_lower or "path_traversal" in path_lower:
        return {"rce": 0.35, "auth_bypass": 0.15, "shell": 0.2}
    if "ssrf" in path_lower:
        return {"rce": 0.25, "auth_bypass": 0.1}
    if "crawler" in path_lower or "spa_scanner" in path_lower:
        return {"credentials": 0.05, "session_cookie": 0.08, "rce": 0.04, "shell": 0.03}
    if "api_fuzzer" in path_lower or "graphql_detect" in path_lower or "swagger_detect" in path_lower:
        return {"auth_bypass": 0.18, "rce": 0.22, "shell": 0.08}
    if "domain_surface" in path_lower or "domain_crtsh" in path_lower:
        return {"credentials": 0.06, "rce": 0.05}
    if any(
        x in path_lower
        for x in (
            "login_page",
            "simple_login",
            "admin_panel_detect",
        )
    ):
        return {"credentials": 0.06, "authenticated_session": 0.1, "session_cookie": 0.06}
    if any(x in path_lower for x in ("rce", "cve_", "exploit", "command_inj", "code_injection")):
        return {"rce": 0.85, "shell": 0.45, "authenticated_session": 0.1}
    if "shell" in path_lower and "reverse" in path_lower:
        return {"shell": 0.9}
    if "_detect" in path_lower or "banner" in path_lower or "fingerprint" in path_lower:
        return {"credentials": 0.02}
    if "bypass" in path_lower or "smuggling" in path_lower:
        return {"auth_bypass": 0.4, "rce": 0.15}
    if "login" in path_lower or "auth" in blob:
        return {"authenticated_session": 0.12, "credentials": 0.08, "csrf_token": 0.2}
    return {}


def _infer_consumes(path_lower: str, blob: str) -> Set[str]:
    """Heuristic ``consumes`` set from module path + metadata blob."""
    consumes = set()
    if any(x in path_lower for x in ("post_auth", "authenticated", "admin_panel")):
        consumes.add("session_cookie")
    if "admin" in path_lower and any(x in path_lower for x in ("exploit", "rce", "upload")):
        consumes.add("admin_access")
    if "csrf" in path_lower and "exploit" in path_lower:
        consumes.add("csrf_token")
    return consumes


def action_profile_from_module(module: Dict[str, Any]) -> ActionProfile:
    """Build :class:`ActionProfile` from catalog module dict (path, name, tags, description)."""
    path_lower = module_path_lower(module)
    blob = module_blob_lower(module)
    parts = path_lower.rstrip("/").split("/")
    name = parts[-1] if parts else path_lower or "unknown"

    cost = float(estimate_network_cost(path_lower)) * 4.2 + 5.0
    noise = float(estimate_network_cost(path_lower)) * 2.6 + 3.5
    if "fuzzer" in path_lower or "fuzz" in path_lower:
        noise += 6.0
    if "smuggling" in path_lower:
        noise += 4.0

    produces = _infer_produces(path_lower, blob)
    # strip keys not in OUTPUT_VALUE (keeps scorer consistent)
    produces = {k: v for k, v in produces.items() if k in OUTPUT_VALUE}
    
    consumes = _infer_consumes(path_lower, blob)

    return ActionProfile(
        name=name, 
        cost=min(55.0, cost), 
        noise=min(40.0, noise), 
        produces=produces,
        consumes=consumes
    )


_SCORER = ActionScorer()


def planner_alignment_bonus(module: Dict[str, Any], kb: Dict[str, Any]) -> float:
    """
    Small additive bonus for :func:`campaign_utility.module_utility`.

    Typical range about ``-0.15 .. +1.8`` so legacy utility remains dominant.
    """
    try:
        state = planner_state_from_kb(kb if isinstance(kb, dict) else {})
        profile = action_profile_from_module(module if isinstance(module, dict) else {})
        raw = _SCORER.score(profile, state)
        # Compress to a gentle additive term
        b = raw / 72.0
        if b > 1.85:
            b = 1.85
        if b < -0.25:
            b = -0.25
        return b
    except Exception:
        return 0.0
