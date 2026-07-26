#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Per-run network request budgeting for the autonomous agent."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Callable, Dict, Iterator, Optional


class NetworkBudgetExceeded(RuntimeError):
    """Raised before a request that would exceed the hard campaign budget."""


@dataclass
class NetworkBudget:
    """Thread-safe hard request budget shared by agent workers."""

    limit: int = 0
    used: int = 0
    skipped: int = 0
    phase: str = ""
    last_action: str = ""
    on_change: Optional[Callable[[int, int], None]] = None
    _lock: Lock = field(default_factory=Lock, repr=False, compare=False)

    @property
    def bounded(self) -> bool:
        return int(self.limit or 0) > 0

    @property
    def remaining(self) -> Optional[int]:
        if not self.bounded:
            return None
        with self._lock:
            return max(0, int(self.limit) - int(self.used))

    def consume(self, units: int = 1, *, reason: str = "network request", phase: str = "") -> None:
        units = max(1, int(units or 1))
        with self._lock:
            if phase:
                self.phase = str(phase)
            self.last_action = str(reason or "network request")[:240]
            if self.bounded and self.used + units > self.limit:
                self.skipped += units
                self._notify()
                raise NetworkBudgetExceeded(
                    f"request budget exhausted before {reason} "
                    f"({self.used}/{self.limit} used)"
                )
            self.used += units
            self._notify()

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            remaining = None
            if self.bounded:
                remaining = max(0, int(self.limit) - int(self.used))
            return {
                "limit": int(self.limit),
                "used": int(self.used),
                "skipped": int(self.skipped),
                "remaining": remaining,
                "phase": self.phase,
                "last_action": self.last_action,
            }

    def record_skipped(self, units: int = 1) -> None:
        with self._lock:
            self.skipped += max(1, int(units or 1))
            self._notify()

    def _notify(self) -> None:
        if self.on_change:
            self.on_change(int(self.used), int(self.skipped))


_ACTIVE_BUDGET: ContextVar[Optional[NetworkBudget]] = ContextVar(
    "kittysploit_agent_network_budget",
    default=None,
)
_REQUESTS_HOOK_LOCK = Lock()
_REQUESTS_HOOK_INSTALLED = False
_AIOHTTP_HOOK_LOCK = Lock()
_AIOHTTP_HOOK_INSTALLED = False


def active_network_budget() -> Optional[NetworkBudget]:
    return _ACTIVE_BUDGET.get()


def sync_metrics_from_budget(state: Any) -> Dict[str, Any]:
    """Copy ``NetworkBudget`` counters into ``state.metrics`` when present."""
    budget = getattr(state, "network_budget", None)
    metrics = getattr(state, "metrics", None)
    if budget is None:
        return {}
    snapshot = budget.snapshot()
    if metrics is not None:
        metrics.network_units_used = int(snapshot.get("used", 0))
        metrics.network_units_skipped = int(snapshot.get("skipped", 0))
    return snapshot


def module_budget_units(module_or_info: Any, module_path: str = "", default: int = 1) -> int:
    from interfaces.command_system.builtin.agent.runtime_policy import assess_module_risk

    payload = module_or_info
    if isinstance(payload, dict) and isinstance(payload.get("__info__"), dict):
        payload = payload["__info__"]
    risk = assess_module_risk(payload, module_path)
    if risk.declared:
        return max(1, int(risk.expected_requests or 1))
    return max(1, int(default or 1))


def try_consume_budget(
    state: Any,
    units: int = 1,
    *,
    reason: str = "network request",
    phase: str = "",
) -> bool:
    """Consume budget units or record a skip. Returns False when exhausted."""
    units = max(1, int(units or 1))
    budget = getattr(state, "network_budget", None)
    current_phase = phase or str(getattr(state, "current_phase", "") or "")
    if budget is not None:
        try:
            budget.consume(units, reason=reason, phase=current_phase)
            sync_metrics_from_budget(state)
            return True
        except NetworkBudgetExceeded:
            sync_metrics_from_budget(state)
            return False
    metrics = getattr(state, "metrics", None)
    request_budget = int(getattr(state, "request_budget", 0) or 0)
    if request_budget <= 0:
        if metrics is not None:
            metrics.network_units_used = int(getattr(metrics, "network_units_used", 0)) + units
        return True
    used = int(getattr(metrics, "network_units_used", 0) or 0)
    if used + units > request_budget:
        if metrics is not None:
            metrics.network_units_skipped = int(getattr(metrics, "network_units_skipped", 0)) + units
        return False
    if metrics is not None:
        metrics.network_units_used = used + units
    return True


def consume_network_request(
    reason: str = "network request",
    units: int = 1,
    *,
    phase: str = "",
) -> None:
    budget = active_network_budget()
    if budget is not None:
        budget.consume(units, reason=reason, phase=phase or budget.phase)


def install_requests_budget_hook() -> None:
    """Instrument requests.Session.request once; inactive contexts are untouched."""
    global _REQUESTS_HOOK_INSTALLED
    if _REQUESTS_HOOK_INSTALLED:
        return
    with _REQUESTS_HOOK_LOCK:
        if _REQUESTS_HOOK_INSTALLED:
            return
        import requests

        original = requests.sessions.Session.send

        def _agent_send(session, request, **kwargs):
            budget = active_network_budget()
            if budget is not None:
                from interfaces.command_system.builtin.agent.egress_gateway import assert_egress_allowed
                from interfaces.command_system.builtin.agent.runtime_policy import (
                    ScopeViolationError,
                    active_runtime_policy,
                    active_scope_guard,
                )

                method = str(getattr(request, "method", "REQUEST") or "REQUEST").upper()
                url = str(getattr(request, "url", "") or "")
                assert_egress_allowed(url=url, method=method)
                guard = active_scope_guard()
                if guard is not None:
                    allowed, reason = guard.validate_url(url)
                    if not allowed:
                        raise ScopeViolationError(
                            f"Agent scope blocked {method} {url}: {reason}",
                            url=url,
                        )
                policy = active_runtime_policy()
                if policy is not None and url.lower().startswith("https://"):
                    kwargs["verify"] = policy.tls_verify_value()
                response = original(session, request, **kwargs)
                history = list(getattr(response, "history", []) or [])
                final_url = str(getattr(response, "url", url) or url)
                if guard is not None and (history or final_url != url):
                    ok, reason = guard.validate_redirect_chain(url, final_url, history)
                    if not ok:
                        raise ScopeViolationError(reason, url=final_url)
                budget.consume(
                    1 + len(history),
                    reason=f"{method} {url}",
                )
                return response
            return original(session, request, **kwargs)

        requests.sessions.Session.send = _agent_send
        _REQUESTS_HOOK_INSTALLED = True


def install_aiohttp_budget_hook() -> None:
    """Instrument aiohttp when available; no-op otherwise."""
    global _AIOHTTP_HOOK_INSTALLED
    if _AIOHTTP_HOOK_INSTALLED:
        return
    try:
        import aiohttp
    except ImportError:
        return
    with _AIOHTTP_HOOK_LOCK:
        if _AIOHTTP_HOOK_INSTALLED:
            return
        original = aiohttp.ClientSession._request

        async def _agent_request(self, method, url, **kwargs):
            budget = active_network_budget()
            if budget is not None:
                from interfaces.command_system.builtin.agent.egress_gateway import assert_egress_allowed
                from interfaces.command_system.builtin.agent.runtime_policy import (
                    ScopeViolationError,
                    active_scope_guard,
                )

                guard = active_scope_guard()
                url_str = str(url or "")
                assert_egress_allowed(url=url_str, method=str(method or "GET"))
                if guard is not None:
                    allowed, reason = guard.validate_url(url_str)
                    if not allowed:
                        raise ScopeViolationError(
                            f"Agent scope blocked {method} {url_str}: {reason}",
                            url=url_str,
                        )
                budget.consume(1, reason=f"{method} {url_str}")
            return await original(self, method, url, **kwargs)

        aiohttp.ClientSession._request = _agent_request
        _AIOHTTP_HOOK_INSTALLED = True


@contextmanager
def network_budget_context(budget: Optional[NetworkBudget]) -> Iterator[None]:
    install_requests_budget_hook()
    install_aiohttp_budget_hook()
    token = _ACTIVE_BUDGET.set(budget)
    try:
        yield
    finally:
        _ACTIVE_BUDGET.reset(token)
