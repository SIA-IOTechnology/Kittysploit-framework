#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Seed-driven synthetic lab mutation for Phase 6 generalization."""

from __future__ import annotations

import random
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Tuple

from interfaces.command_system.builtin.agent.benchmark.lab_server import SyntheticHttpLab


LOGIN_PATHS = ("/login", "/auth/signin", "/user/login.php", "/session/new")
COOKIE_NAMES = ("session", "PHPSESSID", "lab_token", "sid")
SERVER_BANNERS = ("SyntheticLab/1.0", "nginx/1.18.0", "Apache/2.4.41", "Kestrel")
CREDENTIALS = (
    ("admin", "password"),
    ("admin", "admin"),
    ("dvwa", "password"),
    ("test", "test"),
)


@dataclass(frozen=True)
class MutationSpec:
    seed: int
    login_path: str
    dashboard_path: str
    waf_path: str
    rate_limit_path: str
    cookie_name: str
    cookie_value: str
    server_banner: str
    username: str
    password: str
    latency_ms: int
    route_order: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def mutation_spec_from_seed(seed: int) -> MutationSpec:
    rng = random.Random(int(seed))
    login = rng.choice(LOGIN_PATHS)
    dashboard = "/dashboard" if login == "/login" else f"{login.rstrip('/')}/home"
    waf = rng.choice(("/waf", "/blocked", "/security/deny"))
    rate = rng.choice(("/rate-limit", "/throttle", "/too-many"))
    cookie = rng.choice(COOKIE_NAMES)
    banner = rng.choice(SERVER_BANNERS)
    user, password = rng.choice(CREDENTIALS)
    latency = rng.choice((0, 5, 15, 40, 80))
    routes = (login, dashboard, waf, rate, "/")
    shuffled = list(routes)
    rng.shuffle(shuffled)
    return MutationSpec(
        seed=int(seed),
        login_path=login,
        dashboard_path=dashboard,
        waf_path=waf,
        rate_limit_path=rate,
        cookie_name=cookie,
        cookie_value=f"lab-{seed}",
        server_banner=banner,
        username=user,
        password=password,
        latency_ms=latency,
        route_order=tuple(shuffled),
    )


def routes_from_spec(spec: MutationSpec) -> Dict[str, Dict[str, object]]:
    return {
        "/": {
            "status": 200,
            "body": f"lab-root seed={spec.seed}",
            "server": spec.server_banner,
            "latency_ms": spec.latency_ms,
        },
        spec.login_path: {
            "status": 302,
            "location": spec.dashboard_path,
            "set_cookie": f"{spec.cookie_name}={spec.cookie_value}",
            "server": spec.server_banner,
            "latency_ms": spec.latency_ms,
        },
        spec.dashboard_path: {
            "status": 200,
            "body": f"authenticated as {spec.username}",
            "server": spec.server_banner,
            "latency_ms": spec.latency_ms,
        },
        spec.rate_limit_path: {
            "status": 429,
            "body": "slow down",
            "server": spec.server_banner,
            "latency_ms": spec.latency_ms,
        },
        spec.waf_path: {
            "status": 403,
            "body": "request blocked by waf",
            "server": spec.server_banner,
            "latency_ms": spec.latency_ms,
        },
    }


def build_mutated_lab(seed: int, *, host: str = "127.0.0.1", port: int = 0) -> Tuple[SyntheticHttpLab, MutationSpec]:
    """Create a synthetic lab whose routes/banners/creds depend on ``seed``."""
    spec = mutation_spec_from_seed(seed)
    routes = routes_from_spec(spec)
    lab = SyntheticHttpLab(host=host, port=port, routes=routes, mutation=spec.to_dict())
    return lab, spec


def specs_differ(a: MutationSpec, b: MutationSpec) -> bool:
    if a.seed == b.seed:
        return False
    return any(
        getattr(a, key) != getattr(b, key)
        for key in (
            "login_path",
            "waf_path",
            "cookie_name",
            "server_banner",
            "username",
            "password",
            "latency_ms",
            "route_order",
        )
    )
