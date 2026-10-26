#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Long-horizon ad hoc autonomy (terminal, browser, framework commands off-catalog)."""

from __future__ import annotations

import os
from typing import Any


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _env_falsy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"0", "false", "no", "off"}


def adhoc_autonomy_enabled(state: Any = None) -> bool:
    if _env_falsy("KITTYSPLOIT_AGENT_ADHOC"):
        return False
    if state is None:
        return _env_truthy("KITTYSPLOIT_AGENT_ADHOC")
    if getattr(state, "adhoc_autonomy", None) is False:
        return False
    if getattr(state, "adhoc_autonomy", None) is True:
        return True
    if getattr(state, "dry_run", False) or getattr(state, "plan_only", False):
        return False
    if _env_truthy("KITTYSPLOIT_AGENT_ADHOC"):
        return True
    pursuit = False
    try:
        from interfaces.command_system.builtin.agent.session_pursuit import session_pursuit_active

        pursuit = session_pursuit_active(state)
    except Exception:
        pursuit = False
    if pursuit or getattr(state, "llm_local", False):
        return True
    return False


def adhoc_max_turns(state: Any = None) -> int:
    raw = os.environ.get("KITTYSPLOIT_AGENT_ADHOC_MAX_TURNS", "").strip()
    if raw.isdigit():
        return max(1, min(int(raw), 48))
    if state is not None and getattr(state, "until_session", False):
        return 20
    return 12


def shell_exec_allowed(state: Any) -> bool:
    if getattr(state, "approve_shell_exec", False):
        return True
    if _env_truthy("KITTYSPLOIT_AGENT_APPROVE_SHELL"):
        return True
    profile = str(getattr(state, "safety_profile", "") or "").lower()
    return profile == "aggressive"
