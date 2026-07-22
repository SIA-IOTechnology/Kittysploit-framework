#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Deterministic rules for when specialist delegation is worth the cost."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from interfaces.command_system.builtin.agent.specialist_registry import (
    MAX_FAN_OUT,
    MAX_SUBAGENT_DEPTH,
    SpecialistProfile,
)


@dataclass(frozen=True)
class DelegationDecision:
    allowed: bool
    specialist: str
    reason: str
    mode: str = "shadow"
    expected_gain: float = 0.0
    estimated_cost: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "specialist": self.specialist,
            "reason": self.reason,
            "mode": self.mode,
            "expected_gain": self.expected_gain,
            "estimated_cost": self.estimated_cost,
        }


class DelegationPolicy:
    """Gate specialist calls by depth, fan-out, maturity, and expected benefit."""

    min_gain_ratio: float = 1.15
    critic_risk_levels = frozenset({"intrusive", "destructive"})
    critic_phases = frozenset({"exploit", "act"})

    def evaluate(
        self,
        profile: SpecialistProfile,
        *,
        depth: int = 0,
        fan_out: int = 0,
        phase: str = "",
        action_risk: str = "read",
        terminal_action: bool = False,
        contradiction: bool = False,
        llm_available: bool = True,
        propose_only: bool = False,
    ) -> DelegationDecision:
        if depth > MAX_SUBAGENT_DEPTH:
            return DelegationDecision(False, profile.key, "depth_limit", mode="blocked")
        if fan_out >= MAX_FAN_OUT:
            return DelegationDecision(False, profile.key, "fan_out_limit", mode="blocked")
        if profile.maturity == "planned":
            return DelegationDecision(False, profile.key, "specialist_not_ready", mode="blocked")

        estimated_cost = float(max(1, profile.budget_requests))
        expected_gain = self._estimate_gain(profile, phase=phase, terminal_action=terminal_action)

        if profile.key == "analyst":
            if not (terminal_action or contradiction or action_risk in self.critic_risk_levels):
                return DelegationDecision(
                    False,
                    profile.key,
                    "critic_only_for_terminal_or_contradiction",
                    expected_gain=expected_gain,
                    estimated_cost=estimated_cost,
                )
            mode = "critic"
        elif profile.read_only:
            mode = "read_only"
        else:
            mode = "sequential"

        if not llm_available and profile.key not in {"coordinator", "scanner", "recon"}:
            return DelegationDecision(
                False,
                profile.key,
                "llm_unavailable_heuristic_only",
                mode="fallback",
                expected_gain=expected_gain,
                estimated_cost=estimated_cost,
            )

        if (
            not propose_only
            and expected_gain / estimated_cost < self.min_gain_ratio
            and profile.key not in {"coordinator"}
        ):
            return DelegationDecision(
                False,
                profile.key,
                "insufficient_expected_gain",
                mode=mode,
                expected_gain=expected_gain,
                estimated_cost=estimated_cost,
            )

        return DelegationDecision(
            True,
            profile.key,
            "delegation_allowed",
            mode=mode,
            expected_gain=expected_gain,
            estimated_cost=estimated_cost,
        )

    @staticmethod
    def _estimate_gain(profile: SpecialistProfile, *, phase: str, terminal_action: bool) -> float:
        base = 1.0 + 0.25 * len(profile.capabilities)
        if terminal_action and profile.key in {"exploiter", "infiltrator", "analyst"}:
            base += 1.5
        if phase in {"exploit", "act"} and profile.key in {"exploiter", "scanner"}:
            base += 0.75
        if profile.key in SPECIALIST_HIGH_VALUE:
            base += 0.5
        return base


SPECIALIST_HIGH_VALUE = frozenset({"sqli", "lfi", "auth", "exploiter", "coordinator"})
