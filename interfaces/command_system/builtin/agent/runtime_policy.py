#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Risk, scope, TLS, approvals, cancellation, and stop conditions for agent runs."""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit


RISK_ORDER = {"read": 0, "active": 1, "intrusive": 2, "destructive": 3}
VALID_RISKS = frozenset(RISK_ORDER)
MUTATING_HTTP_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
NON_IDEMPOTENT_EFFECTS = frozenset({
    "active_exploitation",
    "target_modification",
    "write_access",
    "persistence",
    "destructive",
})

MISSION_PROFILE_ALIASES = {
    "ot-safe": "ot-safe",
    "ot-safe-assessment": "ot-safe",
    "bug-bounty-safe": "bug-bounty-safe",
    "internal-lab": "internal-lab",
    "europol-passive": "europol-passive",
    "europol_passive": "europol-passive",
    "infra-discovery": "infra-discovery",
    "infra_discovery": "infra-discovery",
}

BUG_BOUNTY_BLOCK_PREFIXES = (
    "backdoors/",
    "payloads/",
    "listeners/",
    "post/",
    "auxiliary/dos/",
    "dos/",
)

BUG_BOUNTY_BLOCK_TOKENS = (
    "bruteforce",
    "credential_stuffing",
    "password_spray",
    "hashdump",
    "dump_lsass",
    "keylogger",
    "persistence",
    "backdoor",
    "delete_file",
    "flush_",
    "write_coil",
    "write_register",
    "set_iam_policy",
    "create_service_account_key",
)

OT_SAFE_BLOCK_PREFIXES = (
    "backdoors/",
    "payloads/",
    "listeners/",
    "auxiliary/dos/",
    "dos/",
    "exploits/",
    "exploit/",
)

EUROPOL_PASSIVE_ALLOW_PREFIXES = (
    "auxiliary/osint/",
    "analysis/reporting/",
)

EUROPOL_PASSIVE_BLOCK_TOKENS = (
    "bruteforce",
    "persona_password",
    "admin_login",
    "credential_stuffing",
    "password_spray",
    "exploit",
    "payload",
    "listener",
    "backdoor",
    "persistence",
    "hashdump",
    "write_coil",
    "write_register",
    "dos/",
    "scanner/",
    "auxiliary/scanner/",
)

INFRA_DISCOVERY_ALLOW_PREFIXES = (
    "scanner/",
    "auxiliary/scanner/",
)

INFRA_DISCOVERY_BLOCK_PREFIXES = (
    "exploit/",
    "exploits/",
    "post/",
    "payloads/",
    "listeners/",
    "backdoors/",
    "auxiliary/osint/",
)

INFRA_DISCOVERY_BLOCK_TOKENS = (
    "bruteforce",
    "password_spray",
    "credential_stuffing",
    "dos",
    "wipe",
    "persistence",
    "hop_proxy",
)


@dataclass(frozen=True)
class PolicyBlock:
    """Structured refusal for policy, scope, or approval violations."""

    phase: str
    module: str
    risk: str
    reason: str
    approval_needed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase,
            "module": self.module,
            "risk": self.risk,
            "reason": self.reason,
            "approval_needed": self.approval_needed,
        }


class ScopeViolationError(PermissionError):
    """Raised before a network request leaves agent scope."""

    def __init__(self, reason: str, *, url: str = "", phase: str = "") -> None:
        self.reason = reason
        self.url = url
        self.phase = phase
        block = PolicyBlock(
            phase=phase or "network",
            module="",
            risk="scope",
            reason=reason,
            approval_needed=False,
        )
        self.block = block
        super().__init__(reason)


@dataclass(frozen=True)
class ModuleRisk:
    level: str
    effects: Tuple[str, ...] = ()
    expected_requests: int = 1
    reversible: bool = True
    approval_required: bool = False
    declared: bool = False
    reason: str = ""


@dataclass
class AgentRuntimePolicy:
    """Immutable-enough run policy derived from CLI and optional policy file."""

    safety_profile: str = "normal"
    approved_risks: Set[str] = field(default_factory=set)
    approve_active_replay: bool = False
    approve_post_exploit: bool = False
    tls_verify: bool = True
    tls_ca_bundle: Optional[str] = None
    dry_run: bool = False
    plan_only: bool = False
    session_policy: str = "ask"
    mission_profile: str = ""
    deadline_at: Optional[float] = None
    allowed_ports: Set[int] = field(default_factory=set)
    allowed_protocols: Set[str] = field(default_factory=set)
    denied_targets: Set[str] = field(default_factory=set)

    @classmethod
    def from_options(
        cls,
        *,
        safety_profile: str,
        approved_risks: Iterable[str] = (),
        approve_active_replay: bool = False,
        approve_post_exploit: bool = False,
        tls_verify: bool = True,
        tls_ca_bundle: Optional[str] = None,
        dry_run: bool = False,
        plan_only: bool = False,
        session_policy: str = "ask",
        mission_profile: str = "",
        deadline_seconds: float = 0.0,
        policy_file: Optional[str] = None,
    ) -> "AgentRuntimePolicy":
        data: Dict[str, Any] = {}
        if policy_file:
            path = Path(policy_file).expanduser()
            with path.open("r", encoding="utf-8") as handle:
                if path.suffix.lower() == ".json":
                    data = json.load(handle) or {}
                else:
                    try:
                        import tomllib
                    except ImportError:  # pragma: no cover - Python 3.10 fallback
                        import tomli as tomllib  # type: ignore
                    data = tomllib.loads(handle.read()) or {}
            if not isinstance(data, dict):
                raise ValueError("Agent policy must contain an object/table")

        approved = {
            str(value).strip().lower()
            for value in approved_risks
            if str(value).strip().lower() in VALID_RISKS
        }
        approved.update(
            str(value).strip().lower()
            for value in (data.get("approved_risks") or [])
            if str(value).strip().lower() in VALID_RISKS
        )
        ports = {
            int(value)
            for value in (data.get("allowed_ports") or [])
            if str(value).isdigit() and 1 <= int(value) <= 65535
        }
        protocols = {
            str(value).strip().lower()
            for value in (data.get("allowed_protocols") or [])
            if str(value).strip()
        }
        denied = {
            str(value).strip().lower().strip(".")
            for value in (data.get("deny") or data.get("denied_targets") or [])
            if str(value).strip()
        }
        deadline = None
        seconds = float(data.get("deadline_seconds") or deadline_seconds or 0.0)
        if seconds > 0:
            deadline = time.monotonic() + seconds
        mission = normalize_mission_profile(
            data.get("catalog_policy")
            or data.get("mission_profile")
            or data.get("profile")
            or mission_profile
        )

        return cls(
            safety_profile=str(data.get("safety_profile") or safety_profile or "normal").lower(),
            approved_risks=approved,
            approve_active_replay=bool(
                data.get("approve_active_replay", approve_active_replay)
            ),
            approve_post_exploit=bool(
                data.get("approve_post_exploit", approve_post_exploit)
            ),
            tls_verify=bool(data.get("tls_verify", tls_verify)),
            tls_ca_bundle=str(data.get("tls_ca_bundle") or tls_ca_bundle or "") or None,
            dry_run=bool(data.get("dry_run", dry_run)),
            plan_only=bool(data.get("plan_only", plan_only)),
            session_policy=str(data.get("session_policy") or session_policy or "ask"),
            mission_profile=mission,
            deadline_at=deadline,
            allowed_ports=ports,
            allowed_protocols=protocols,
            denied_targets=denied,
        )

    def tls_verify_value(self) -> Any:
        return self.tls_ca_bundle or self.tls_verify

    def risk_approved(self, risk: ModuleRisk) -> bool:
        if risk.level in self.approved_risks:
            return True
        return any(
            RISK_ORDER.get(approved, -1) >= RISK_ORDER.get(risk.level, 99)
            for approved in self.approved_risks
        )


def assess_module_risk(module_or_info: Any, module_path: str = "") -> ModuleRisk:
    """Prefer declared metadata, with a conservative compatibility fallback."""
    if isinstance(module_or_info, dict):
        info = module_or_info
    else:
        info = getattr(module_or_info, "__info__", {}) or {}
    agent = info.get("agent") if isinstance(info, dict) else None
    if isinstance(agent, dict):
        raw_level = str(agent.get("risk") or agent.get("risk_level") or "").strip().lower()
        level = "read" if raw_level == "passive" else raw_level
        if level in VALID_RISKS:
            effects = tuple(
                str(value).strip().lower()
                for value in (agent.get("effects") or [])
                if str(value).strip()
            )
            expected = agent.get("expected_requests", 1)
            try:
                expected_requests = max(1, int(expected or 1))
            except (TypeError, ValueError):
                expected_requests = 1
            return ModuleRisk(
                level=level,
                effects=effects,
                expected_requests=expected_requests,
                reversible=bool(agent.get("reversible", level != "destructive")),
                approval_required=bool(
                    agent.get("approval_required", level in {"intrusive", "destructive"})
                ),
                declared=True,
                reason="declared module agent metadata",
            )
        return ModuleRisk(
            "read",
            (),
            1,
            True,
            False,
            False,
            "invalid or incomplete agent metadata",
        )

    path = str(module_path or info.get("path") or "").lower()
    tags = {str(tag).lower() for tag in (info.get("tags") or [])} if isinstance(info, dict) else set()
    blob = " ".join((path, " ".join(tags)))
    if any(token in blob for token in ("wipe", "delete", "persistence", "dos", "ransom", "cleanup")):
        return ModuleRisk("destructive", ("target_modification",), 1, False, True, False, "legacy heuristic")
    if path.startswith(("exploit/", "exploits/", "post/")) or any(
        token in blob for token in ("bruteforce", "password", "credential", "upload", "write_access")
    ):
        return ModuleRisk("intrusive", ("active_exploitation",), 1, False, True, False, "legacy heuristic")
    if path.startswith(("scanner/", "auxiliary/scanner/")):
        return ModuleRisk("active", ("network_probe",), 1, True, False, False, "legacy heuristic")
    return ModuleRisk("read", (), 1, True, False, False, "legacy heuristic")


def normalize_mission_profile(value: Any) -> str:
    key = str(value or "").strip().lower().replace("_", "-")
    return MISSION_PROFILE_ALIASES.get(key, key)


def _mission_catalog_block_reason(
    policy: AgentRuntimePolicy,
    risk: ModuleRisk,
    *,
    module_path: str,
    knowledge_base: Optional[Dict[str, Any]] = None,
) -> str:
    mission = normalize_mission_profile(getattr(policy, "mission_profile", ""))
    if not mission or mission == "internal-lab":
        return ""

    path = str(module_path or "").strip().lower()
    effects = {str(value).lower() for value in (risk.effects or ())}

    if mission == "bug-bounty-safe":
        if path.startswith(BUG_BOUNTY_BLOCK_PREFIXES):
            return "bug-bounty-safe catalog policy blocks post-exploit, payload, listener, DoS, and backdoor modules"
        if any(token in path for token in BUG_BOUNTY_BLOCK_TOKENS):
            return "bug-bounty-safe catalog policy blocks credential attacks, persistence, destructive writes, and noisy actions"
        if risk.level in {"intrusive", "destructive"}:
            return f"bug-bounty-safe catalog policy blocks {risk.level} modules"
        if effects.intersection(NON_IDEMPOTENT_EFFECTS):
            return "bug-bounty-safe catalog policy blocks non-idempotent target changes"
        return ""

    if mission == "ot-safe":
        try:
            from interfaces.command_system.builtin.agent.ot_policy import (
                is_ot_destructive_module,
                is_ot_module_path,
                is_ot_recon_module,
            )
        except Exception:  # pragma: no cover - minimal import environments
            is_ot_destructive_module = lambda _path: False  # type: ignore
            is_ot_module_path = lambda _path: "/ics/" in str(_path).lower()  # type: ignore
            is_ot_recon_module = lambda _path: "scanner/ics/" in str(_path).lower()  # type: ignore

        if is_ot_destructive_module(path):
            return "ot-safe catalog policy blocks PLC control, write, exploit, and DoS modules"
        if path.startswith(OT_SAFE_BLOCK_PREFIXES):
            return "ot-safe catalog policy blocks exploit, payload, listener, DoS, and backdoor modules"
        if path.startswith("post/") and not is_ot_recon_module(path):
            return "ot-safe catalog policy allows only OT gather/report post modules"
        if is_ot_module_path(path) and not is_ot_recon_module(path):
            return "ot-safe catalog policy allows OT recon/gather modules only"
        if risk.level in {"intrusive", "destructive"}:
            return f"ot-safe catalog policy blocks {risk.level} modules"
        if effects.intersection(NON_IDEMPOTENT_EFFECTS):
            return "ot-safe catalog policy blocks non-idempotent target changes"
        return ""

    if mission == "europol-passive":
        if not any(path.startswith(prefix) for prefix in EUROPOL_PASSIVE_ALLOW_PREFIXES):
            return "europol-passive catalog policy allows only passive OSINT and reporting modules"
        if any(token in path for token in EUROPOL_PASSIVE_BLOCK_TOKENS):
            return "europol-passive catalog policy blocks active scanning, credential attacks, and exploitation"
        if path.startswith(("exploit/", "exploits/", "post/", "payloads/", "listeners/", "backdoors/")):
            return "europol-passive catalog policy blocks offensive modules"
        if risk.level in {"active", "intrusive", "destructive"}:
            return f"europol-passive catalog policy blocks {risk.level} modules"
        if effects.intersection(NON_IDEMPOTENT_EFFECTS):
            return "europol-passive catalog policy blocks non-idempotent target changes"
        return ""

    if mission == "infra-discovery":
        if path.startswith(INFRA_DISCOVERY_BLOCK_PREFIXES):
            return "infra-discovery catalog policy allows scanner modules only"
        if not any(path.startswith(prefix) for prefix in INFRA_DISCOVERY_ALLOW_PREFIXES):
            return "infra-discovery catalog policy allows scanner/ and auxiliary/scanner/ modules only"
        if any(token in path for token in INFRA_DISCOVERY_BLOCK_TOKENS):
            return "infra-discovery catalog policy blocks bruteforce, DoS, and persistence modules"
        if risk.level in {"intrusive", "destructive"}:
            return f"infra-discovery catalog policy blocks {risk.level} modules"
        if effects.intersection(NON_IDEMPOTENT_EFFECTS):
            return "infra-discovery catalog policy blocks non-idempotent target changes"
        return ""

    return ""


def module_policy_decision(
    policy: AgentRuntimePolicy,
    risk: ModuleRisk,
    *,
    phase: str = "",
    module_path: str = "",
) -> Tuple[bool, str]:
    block = evaluate_module_policy(policy, risk, phase=phase, module_path=module_path)
    if block is not None:
        return False, block.reason
    return True, "allowed by agent runtime policy"


def evaluate_module_catalog_policy(
    policy: AgentRuntimePolicy,
    module_or_info: Any,
    module_path: str = "",
    *,
    phase: str = "catalog",
    knowledge_base: Optional[Dict[str, Any]] = None,
) -> Optional[PolicyBlock]:
    """
    Runtime + mission-profile decision for catalog filtering and module launch.

    ``evaluate_module_policy`` keeps the baseline risk approval semantics; this
    wrapper adds mission presets such as ``ot-safe`` and ``bug-bounty-safe`` so
    rejected modules are removed before ranking and explained consistently.
    """
    risk = assess_module_risk(module_or_info, module_path)
    reason = _mission_catalog_block_reason(
        policy,
        risk,
        module_path=module_path,
        knowledge_base=knowledge_base,
    )
    if reason:
        return PolicyBlock(
            phase=phase,
            module=module_path,
            risk=risk.level,
            reason=reason,
            approval_needed=False,
        )

    block = evaluate_module_policy(
        policy,
        risk,
        phase=phase,
        module_path=module_path,
    )
    if block is not None:
        return block

    try:
        from interfaces.command_system.builtin.agent.ot_policy import ot_module_block_reason

        ot_reason = ot_module_block_reason(
            module_path=module_path,
            safety_profile=str(policy.safety_profile or "normal"),
            knowledge_base=knowledge_base if isinstance(knowledge_base, dict) else {},
            risk_approved=bool(policy.risk_approved(risk)),
        )
    except Exception:  # pragma: no cover - minimal import environments
        ot_reason = ""
    if ot_reason:
        return PolicyBlock(
            phase=phase,
            module=module_path,
            risk=risk.level,
            reason=ot_reason,
            approval_needed=False,
        )
    return None


def evaluate_module_policy(
    policy: AgentRuntimePolicy,
    risk: ModuleRisk,
    *,
    phase: str = "",
    module_path: str = "",
) -> Optional[PolicyBlock]:
    profile = str(policy.safety_profile or "normal").lower()
    if profile == "safe":
        if not risk.declared:
            return PolicyBlock(
                phase=phase,
                module=module_path,
                risk=risk.level,
                reason="safe profile requires explicit agent risk metadata",
                approval_needed=False,
            )
        if risk.level not in {"read", "active"}:
            return PolicyBlock(
                phase=phase,
                module=module_path,
                risk=risk.level,
                reason=f"safe profile blocks {risk.level} actions",
                approval_needed=False,
            )
    elif profile == "discreet" and risk.level in {"intrusive", "destructive"}:
        if not policy.risk_approved(risk):
            return PolicyBlock(
                phase=phase,
                module=module_path,
                risk=risk.level,
                reason=f"discreet profile requires approval for {risk.level} actions",
                approval_needed=True,
            )
    elif risk.level == "destructive" and not policy.risk_approved(risk):
        return PolicyBlock(
            phase=phase,
            module=module_path,
            risk=risk.level,
            reason="destructive action requires explicit --approve-risk destructive",
            approval_needed=True,
        )

    if risk.approval_required and not policy.risk_approved(risk):
        return PolicyBlock(
            phase=phase,
            module=module_path,
            risk=risk.level,
            reason=f"{risk.level} action requires explicit risk approval",
            approval_needed=True,
        )
    return None


def http_replay_policy_decision(
    policy: AgentRuntimePolicy,
    *,
    mode: str,
    method: str,
    phase: str = "replay",
) -> Optional[PolicyBlock]:
    mode = str(mode or "safe").lower()
    method = str(method or "GET").upper()
    if mode == "active" and not policy.approve_active_replay:
        return PolicyBlock(
            phase=phase,
            module="http_replay",
            risk="active",
            reason="mutating HTTP replay requires explicit approval",
            approval_needed=True,
        )
    if method in MUTATING_HTTP_METHODS and not policy.approve_active_replay:
        return PolicyBlock(
            phase=phase,
            module="http_replay",
            risk="active",
            reason=f"{method} replay requires explicit approval",
            approval_needed=True,
        )
    return None


def shell_hunter_policy_decision(
    policy: AgentRuntimePolicy,
    *,
    phase: str = "exploit",
) -> Optional[PolicyBlock]:
    if not policy.risk_approved(ModuleRisk("intrusive", ("active_exploitation",), 1, False, True, True)):
        return PolicyBlock(
            phase=phase,
            module="shell_hunter",
            risk="intrusive",
            reason="shell hunter requires intrusive risk approval",
            approval_needed=True,
        )
    return None


def action_is_non_idempotent(risk: ModuleRisk) -> bool:
    if risk.level in {"intrusive", "destructive"}:
        return True
    return any(effect in NON_IDEMPOTENT_EFFECTS for effect in risk.effects)


class AgentScopeGuard:
    """Validate direct and redirected destinations against engagement scope."""

    def __init__(self, scope_manager: Any, policy: AgentRuntimePolicy):
        self.scope_manager = scope_manager
        self.policy = policy
        self._dns_pins: Dict[str, Set[str]] = {}

    def validate_url(self, url: str) -> Tuple[bool, str]:
        parsed = urlsplit(str(url or ""))
        host = (parsed.hostname or "").lower().strip(".")
        if not host:
            return False, "URL has no hostname"
        port = parsed.port or (443 if parsed.scheme in {"https", "wss"} else 80)
        protocol = (parsed.scheme or "http").lower()
        return self.validate_destination(host, port, protocol)

    def validate_destination(self, host: str, port: int, protocol: str) -> Tuple[bool, str]:
        host = str(host or "").lower().strip(".")
        if not host:
            return False, "empty destination"
        if host in self.policy.denied_targets:
            return False, f"destination {host} is denied by agent policy"
        if self.policy.allowed_ports and int(port) not in self.policy.allowed_ports:
            return False, f"port {port} is outside agent policy"
        if self.policy.allowed_protocols and protocol.lower() not in self.policy.allowed_protocols:
            return False, f"protocol {protocol} is outside agent policy"

        manager = self.scope_manager
        if manager is not None and getattr(manager, "enabled", False):
            decision = manager.is_target_allowed(host)
            if not decision.allowed:
                return False, decision.reason

        addresses = self._resolve(host, port)
        if not addresses:
            return False, f"could not resolve {host}"
        previous = self._dns_pins.get(host)
        if previous is not None and addresses != previous:
            return False, f"DNS rebinding detected for {host}"
        self._dns_pins.setdefault(host, addresses)

        for address in addresses:
            ip = ipaddress.ip_address(address)
            if (
                not self._host_is_ip(host)
                and (ip.is_loopback or ip.is_link_local or ip.is_unspecified)
                and not self._ip_explicitly_allowed(address)
            ):
                return False, f"{host} resolves to protected address {address}"
        return True, f"{host}:{port} is in scope"

    def validate_redirect_chain(
        self,
        requested_url: str,
        final_url: str,
        history: Sequence[Any] = (),
    ) -> Tuple[bool, str]:
        urls = [requested_url]
        urls.extend(str(getattr(item, "url", "") or "") for item in history)
        urls.append(final_url)
        for url in urls:
            if not url:
                continue
            allowed, reason = self.validate_url(url)
            if not allowed:
                return False, f"redirect scope violation: {reason}"
        return True, "redirect chain remained in scope"

    def _ip_explicitly_allowed(self, address: str) -> bool:
        manager = self.scope_manager
        if manager is None or not getattr(manager, "enabled", False):
            return False
        return bool(getattr(manager, "_ip_allowed", lambda _value: False)(address))

    @staticmethod
    def _host_is_ip(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    @staticmethod
    def _resolve(host: str, port: int) -> Set[str]:
        try:
            return {
                row[4][0]
                for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
                if row and row[4]
            }
        except OSError:
            return set()


class CancellationToken:
    def __init__(self) -> None:
        self._event = Event()
        self.reason = ""

    def cancel(self, reason: str = "operator_cancelled") -> None:
        self.reason = str(reason or "operator_cancelled")
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def is_cancelled(self) -> bool:
        return self.cancelled


class StopConditionEvaluator:
    """Evaluate hard and plan-provided terminal conditions consistently."""

    def evaluate(self, state: Any, *, phase: str = "") -> Optional[str]:
        token = getattr(state, "cancellation_token", None)
        if token is not None and getattr(token, "cancelled", False):
            return getattr(token, "reason", "") or "operator_cancelled"

        policy = getattr(state, "runtime_policy", None)
        deadline = getattr(policy, "deadline_at", None)
        if deadline is not None and time.monotonic() >= float(deadline):
            return "deadline_reached"
        phase_timeout = float(getattr(state, "phase_timeout", 0.0) or 0.0)
        phase_started = float(getattr(state, "phase_started_at", 0.0) or 0.0)
        if phase_timeout > 0 and phase_started > 0:
            if time.monotonic() - phase_started >= phase_timeout:
                return f"phase_timeout:{phase}"

        if getattr(state, "campaign_stop_reason", None):
            return str(state.campaign_stop_reason)

        budget = getattr(state, "network_budget", None)
        if budget is not None and budget.bounded and budget.remaining == 0:
            return "request_budget_exhausted"

        conditions = (getattr(state, "execution_plan", {}) or {}).get("stop_conditions", [])
        conditions = {str(value).strip().lower() for value in conditions if str(value).strip()}
        if "shell_obtained" in conditions and getattr(state, "new_sessions", None):
            return "shell_obtained"
        if "target_unreachable" in conditions and getattr(state, "target_reachable", None) is False:
            return "target_unreachable"
        if "waf_or_blocking_detected" in conditions:
            signals = {
                str(value).lower()
                for value in (getattr(state, "knowledge_base", {}) or {}).get("risk_signals", [])
            }
            if "waf_or_blocking_detected" in signals:
                return "waf_or_blocking_detected"
        if "no_vulnerabilities" in conditions and phase in {"reason", "exploit"}:
            if not getattr(state, "vulnerable_results", None):
                return "no_vulnerabilities"
        if "stop_if_no_exploit_path" in conditions and phase == "exploit":
            actions = (getattr(state, "execution_plan", {}) or {}).get("next_actions", [])
            has_exploit = any(
                isinstance(row, dict) and row.get("type") == "run_exploit"
                for row in actions
            )
            if has_exploit:
                return None
            # Soft-target scanners (SQLi/LFI/RCE follow-ups) are an active path —
            # do not abort before the operator has chased confirmed vulns.
            # Match path segments only (avoid "rce" ⊆ "source", "lfi" ⊆ noise).
            weaponizable_segments = {
                "sqli",
                "sqli_engine",
                "sql_injection",
                "lfi",
                "lfi_fuzzer",
                "rfi",
                "ssrf",
                "ssrf_scanner",
                "xxe",
                "rce",
                "ssti",
                "command_injection",
                "file_read",
                "path_traversal",
                "deserialization",
                "xss_scanner",
            }
            for row in actions:
                if not isinstance(row, dict):
                    continue
                if row.get("type") not in {"run_followup", "prioritize", "run_exploit"}:
                    continue
                path_low = str(row.get("path", "") or "").lower().replace("-", "_")
                basename = path_low.rsplit("/", 1)[-1]
                segments = {piece for piece in basename.split("_") if piece}
                if basename in weaponizable_segments or segments.intersection(weaponizable_segments):
                    return None
            kb = getattr(state, "knowledge_base", {}) or {}
            signals = {
                str(value).lower()
                for value in (kb.get("risk_signals", []) or [])
                if str(value).strip()
            }
            if signals.intersection({
                "sql_signal",
                "sqli_confirmed",
                "lfi_signal",
                "xss_signal",
                "ssrf_signal",
                "rce_signal",
            }):
                return None
            findings = (
                getattr(state, "contextual_findings", None)
                or getattr(state, "vulnerable_results", None)
                or []
            )
            if any(
                isinstance(row, dict)
                and row.get("vulnerable")
                and str(row.get("decision_class", "")).lower() in {"exploit", "followup"}
                for row in findings
            ):
                return None
            return "no_exploit_path"
        return None


_ACTIVE_POLICY: ContextVar[Optional[AgentRuntimePolicy]] = ContextVar(
    "kittysploit_agent_runtime_policy",
    default=None,
)
_ACTIVE_SCOPE_GUARD: ContextVar[Optional[AgentScopeGuard]] = ContextVar(
    "kittysploit_agent_scope_guard",
    default=None,
)


def active_runtime_policy() -> Optional[AgentRuntimePolicy]:
    return _ACTIVE_POLICY.get()


def active_scope_guard() -> Optional[AgentScopeGuard]:
    return _ACTIVE_SCOPE_GUARD.get()


@contextmanager
def runtime_policy_context(
    policy: Optional[AgentRuntimePolicy],
    scope_guard: Optional[AgentScopeGuard],
) -> Iterator[None]:
    policy_token = _ACTIVE_POLICY.set(policy)
    scope_token = _ACTIVE_SCOPE_GUARD.set(scope_guard)
    try:
        yield
    finally:
        _ACTIVE_SCOPE_GUARD.reset(scope_token)
        _ACTIVE_POLICY.reset(policy_token)
