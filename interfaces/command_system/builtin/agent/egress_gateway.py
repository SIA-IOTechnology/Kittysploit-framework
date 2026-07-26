#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Last-mile egress gate for agent module execution and network clients."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator, Optional, Set

from interfaces.command_system.builtin.agent.runtime_policy import (
    ScopeViolationError,
    active_scope_guard,
    evaluate_module_policy,
)


class EgressRevokedError(PermissionError):
    """Raised when cancellation or revocation blocks outbound I/O."""

    def __init__(self, reason: str = "egress_revoked", *, url: str = "") -> None:
        self.reason = str(reason or "egress_revoked")
        self.url = str(url or "")
        super().__init__(self.reason)


class PendingEgressRegistry:
    """Track in-flight module actions so cancellation can revoke pending egress."""

    def __init__(self) -> None:
        self._pending: Set[str] = set()
        self.revoked_reason: Optional[str] = None

    def register(self, action_key: str) -> None:
        if self.revoked_reason:
            raise EgressRevokedError(self.revoked_reason)
        self._pending.add(str(action_key))

    def release(self, action_key: str) -> None:
        self._pending.discard(str(action_key))

    def revoke_all(self, reason: str) -> int:
        count = len(self._pending)
        self.revoked_reason = str(reason or "revoked")
        self._pending.clear()
        return count

    @property
    def pending_count(self) -> int:
        return len(self._pending)


_ACTIVE_CANCELLATION: ContextVar[Any] = ContextVar(
    "kittysploit_agent_cancellation",
    default=None,
)
_EGRESS_REVOKED: ContextVar[bool] = ContextVar(
    "kittysploit_agent_egress_revoked",
    default=False,
)
_ACTIVE_PENDING: ContextVar[Optional[PendingEgressRegistry]] = ContextVar(
    "kittysploit_agent_pending_egress",
    default=None,
)


def active_cancellation_token() -> Any:
    return _ACTIVE_CANCELLATION.get()


def active_pending_registry() -> Optional[PendingEgressRegistry]:
    return _ACTIVE_PENDING.get()


def is_cancellation_requested(token: Any = None) -> bool:
    token = token if token is not None else active_cancellation_token()
    if token is None:
        return False
    if getattr(token, "cancelled", False):
        return True
    checker = getattr(token, "is_cancelled", None)
    return bool(checker()) if callable(checker) else False


def revoke_pending_egress(reason: str = "revoked") -> int:
    _EGRESS_REVOKED.set(True)
    registry = active_pending_registry()
    if registry is not None:
        return registry.revoke_all(reason)
    return 0


def register_pending_egress(action_key: str) -> None:
    registry = active_pending_registry()
    if registry is not None:
        registry.register(action_key)


def release_pending_egress(action_key: str) -> None:
    registry = active_pending_registry()
    if registry is not None:
        registry.release(action_key)


def assert_egress_allowed(*, url: str = "", method: str = "GET") -> None:
    """Revalidate cancellation, revocation and scope immediately before network I/O."""
    if _EGRESS_REVOKED.get():
        registry = active_pending_registry()
        reason = registry.revoked_reason if registry is not None else None
        raise EgressRevokedError(reason or "egress_revoked", url=url)

    if is_cancellation_requested():
        token = active_cancellation_token()
        reason = getattr(token, "reason", "") if token is not None else ""
        revoke_pending_egress(reason or "cancelled")
        raise EgressRevokedError(reason or "cancelled", url=url)

    if not url:
        return

    guard = active_scope_guard()
    if guard is None:
        return
    allowed, reason = guard.validate_url(url)
    if not allowed:
        raise ScopeViolationError(
            f"Agent scope blocked {method} {url}: {reason}",
            url=url,
        )


def revalidate_module_execution(
    state: Any,
    *,
    module_path: str,
    phase: str,
    risk: Any,
) -> Optional[Any]:
    """Final executor-level policy and scope check before module side effects."""
    assert_egress_allowed()

    target_info = getattr(state, "target_info", {}) or {}
    raw_target = str(getattr(state, "raw_target", "") or "")
    url = str(target_info.get("url") or raw_target or "")
    if url:
        assert_egress_allowed(url=url, method="MODULE")

    policy = getattr(state, "runtime_policy", None)
    if policy is not None:
        return evaluate_module_policy(
            policy,
            risk,
            phase=phase,
            module_path=module_path,
        )
    return None


@contextmanager
def agent_egress_context(
    cancellation_token: Any = None,
    *,
    registry: Optional[PendingEgressRegistry] = None,
) -> Iterator[PendingEgressRegistry]:
    """Bind cancellation and pending-action registry for a run or test."""
    reg = registry or PendingEgressRegistry()
    cancel_token = _ACTIVE_CANCELLATION.set(cancellation_token)
    pending_token = _ACTIVE_PENDING.set(reg)
    revoked_token = _EGRESS_REVOKED.set(False)
    try:
        yield reg
    finally:
        _EGRESS_REVOKED.reset(revoked_token)
        _ACTIVE_PENDING.reset(pending_token)
        _ACTIVE_CANCELLATION.reset(cancel_token)
