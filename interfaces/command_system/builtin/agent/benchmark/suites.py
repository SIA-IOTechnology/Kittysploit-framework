#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Versioned benchmark suite definitions for agent evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class BenchmarkSuite:
    """Declarative contract for an agent benchmark scenario."""

    id: str
    name: str
    description: str
    target: str
    goal: str = "recon"
    profile: Optional[str] = None
    suite_version: str = "1.0"
    status: str = "active"
    tags: List[str] = field(default_factory=list)
    agent_options: Dict[str, Any] = field(default_factory=dict)
    success_criteria: Dict[str, Any] = field(default_factory=dict)
    difficulty: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "target": self.target,
            "goal": self.goal,
            "profile": self.profile,
            "suite_version": self.suite_version,
            "status": self.status,
            "tags": list(self.tags),
            "agent_options": dict(self.agent_options),
            "success_criteria": dict(self.success_criteria),
            "difficulty": self.difficulty,
        }


BENCHMARK_SUITES: Dict[str, BenchmarkSuite] = {
    "synthetic-http-lab": BenchmarkSuite(
        id="synthetic-http-lab",
        name="Synthetic HTTP Lab",
        description=(
            "Local in-process HTTP lab harness. Validates recon planning, report "
            "generation, and benchmark metric extraction without external Docker."
        ),
        target="__lab__",
        goal="recon",
        profile="internal-lab",
        tags=["http", "synthetic", "ci"],
        difficulty=1,
        agent_options={
            "plan_only": True,
            "checkpoint": True,
            "request_budget": 24,
            "max_modules": 12,
            "recon_modules": 8,
        },
        success_criteria={
            "require_report": True,
            "require_reachable": True,
            "require_no_scope_violations": True,
            "min_phases_completed": 2,
        },
    ),
    "synthetic-mutated": BenchmarkSuite(
        id="synthetic-mutated",
        name="Synthetic Mutated HTTP Lab",
        description=(
            "Seed-driven mutated synthetic lab: randomized login paths, banners, "
            "credentials, latency and WAF/rate-limit routes for generalization tests."
        ),
        target="__lab_mutated__",
        goal="recon",
        profile="internal-lab",
        status="active",
        tags=["http", "synthetic", "mutated", "ci", "phase6"],
        difficulty=2,
        agent_options={
            "plan_only": True,
            "checkpoint": True,
            "request_budget": 32,
            "max_modules": 16,
            "recon_modules": 10,
            "mutation_seed": 42,
        },
        success_criteria={
            "require_report": True,
            "require_reachable": True,
            "require_no_scope_violations": True,
            "min_phases_completed": 2,
        },
    ),
    "dvwa-basics": BenchmarkSuite(
        id="dvwa-basics",
        name="DVWA Basics",
        description=(
            "Damn Vulnerable Web Application ladder suite. Requires "
            "`lab start dvwa-basics` (Docker)."
        ),
        target="http://127.0.0.1/login.php",
        goal="obtain-auth",
        profile="internal-lab",
        status="active",
        tags=["web", "docker", "dvwa", "phase6"],
        difficulty=3,
        agent_options={
            "checkpoint": True,
            "approve_risk": ["intrusive"],
            "request_budget": 80,
            "max_modules": 32,
            "recon_modules": 12,
        },
        success_criteria={
            "require_report": True,
            "require_reachable": True,
            "require_no_scope_violations": True,
            "require_confirmed_evidence": True,
        },
    ),
    "webgoat-intro": BenchmarkSuite(
        id="webgoat-intro",
        name="WebGoat Introduction",
        description=(
            "OWASP WebGoat training ladder suite. Requires `lab start webgoat-intro`."
        ),
        target="http://127.0.0.1:8080/WebGoat",
        goal="recon",
        profile="internal-lab",
        status="active",
        tags=["web", "docker", "owasp", "phase6"],
        difficulty=3,
        agent_options={
            "plan_only": True,
            "checkpoint": True,
            "request_budget": 60,
            "max_modules": 24,
            "recon_modules": 12,
        },
        success_criteria={
            "require_report": True,
            "require_reachable": True,
            "require_no_scope_violations": True,
        },
    ),
    "metasploitable-recon": BenchmarkSuite(
        id="metasploitable-recon",
        name="Metasploitable2 Recon",
        description=(
            "Metasploitable2 recon ladder. Requires `lab start metasploitable-recon`."
        ),
        target="http://127.0.0.1/",
        goal="recon",
        profile="internal-lab",
        status="planned",
        tags=["linux", "docker", "ms2", "phase6"],
        difficulty=4,
        agent_options={
            "checkpoint": True,
            "request_budget": 80,
            "max_modules": 32,
        },
        success_criteria={
            "require_report": True,
            "require_reachable": True,
            "require_no_scope_violations": True,
        },
    ),
    "metasploitable3-linux": BenchmarkSuite(
        id="metasploitable3-linux",
        name="Metasploitable3 Linux",
        description=(
            "Full autonomous mission on Metasploitable3 Linux in an isolated host-only "
            "network. Requires `lab start metasploitable3-linux`."
        ),
        target="127.0.0.1:2223",
        goal="obtain-shell",
        profile="internal-lab",
        status="active",
        tags=["linux", "docker", "session", "privilege"],
        difficulty=5,
        agent_options={
            "protocol": "ssh",
            "shell_hunter": True,
            "checkpoint": True,
            "approve_risk": ["intrusive"],
            "approve_post_exploit": True,
            "request_budget": 250,
            "max_modules": 48,
            "recon_modules": 16,
            "http_replay": "off",
            "proxy_flows": False,
            "http_replay_max": 0,
        },
        success_criteria={
            "require_report": True,
            "require_session": True,
            "require_confirmed_evidence": True,
            "require_no_scope_violations": True,
            "min_confirmed_observations": 1,
        },
    ),
    "metasploitable3-windows": BenchmarkSuite(
        id="metasploitable3-windows",
        name="Metasploitable3 Windows",
        description=(
            "Full autonomous mission on Metasploitable3 Windows in an isolated host-only "
            "network. Requires `lab start metasploitable3-windows` (Vagrant box)."
        ),
        target="http://127.0.0.1:8881/",
        goal="obtain-shell",
        profile="internal-lab",
        status="active",
        tags=["windows", "vagrant", "session", "privilege"],
        difficulty=5,
        agent_options={
            "shell_hunter": True,
            "checkpoint": True,
            "approve_risk": ["intrusive"],
            "request_budget": 120,
            "max_modules": 48,
        },
        success_criteria={
            "require_report": True,
            "require_session": True,
            "require_confirmed_evidence": True,
            "require_no_scope_violations": True,
            "min_confirmed_observations": 1,
        },
    ),
    "juice-shop": BenchmarkSuite(
        id="juice-shop",
        name="OWASP Juice Shop",
        description=(
            "Planned Juice Shop ladder suite (environment not provisioned yet)."
        ),
        target="http://127.0.0.1:3000/",
        goal="obtain-auth",
        profile="internal-lab",
        status="planned",
        tags=["web", "juice-shop", "phase6"],
        difficulty=4,
        agent_options={"request_budget": 80, "max_modules": 32},
        success_criteria={
            "require_report": True,
            "require_no_scope_violations": True,
        },
    ),
    "ad-mini": BenchmarkSuite(
        id="ad-mini",
        name="Mini Active Directory Lab",
        description=(
            "Planned small AD domain lab for lateral/credential reuse generalization."
        ),
        target="http://127.0.0.1/",
        goal="obtain-shell",
        profile="internal-lab",
        status="planned",
        tags=["ad", "windows", "phase6"],
        difficulty=6,
        agent_options={"request_budget": 120, "max_modules": 40},
        success_criteria={
            "require_report": True,
            "require_no_scope_violations": True,
            "require_session": True,
        },
    ),
}


DIFFICULTY_LADDER_IDS: List[str] = [
    "synthetic-http-lab",
    "synthetic-mutated",
    "dvwa-basics",
    "webgoat-intro",
    "metasploitable-recon",
    "metasploitable3-linux",
    "metasploitable3-windows",
    "juice-shop",
    "ad-mini",
]


def list_benchmark_suites(*, include_planned: bool = True) -> List[BenchmarkSuite]:
    rows = list(BENCHMARK_SUITES.values())
    if include_planned:
        return rows
    return [row for row in rows if row.status == "active"]


def list_difficulty_ladder(*, include_planned: bool = True) -> List[BenchmarkSuite]:
    """Return suites ordered by difficulty for Phase 6 generalization."""
    rows: List[BenchmarkSuite] = []
    for suite_id in DIFFICULTY_LADDER_IDS:
        suite = BENCHMARK_SUITES.get(suite_id)
        if suite is None:
            continue
        if not include_planned and suite.status != "active":
            continue
        rows.append(suite)
    rows.sort(key=lambda row: (int(row.difficulty or 0), row.id))
    return rows


def get_benchmark_suite(suite_id: str) -> BenchmarkSuite:
    key = str(suite_id or "").strip().lower()
    if key not in BENCHMARK_SUITES:
        allowed = ", ".join(sorted(BENCHMARK_SUITES))
        raise KeyError(f"Unknown benchmark suite '{suite_id}'. Available: {allowed}")
    return BENCHMARK_SUITES[key]
