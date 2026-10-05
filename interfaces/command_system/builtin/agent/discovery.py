#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Discovery mode: application model, module-free hypotheses, differential oracles.

Catalog exploitation and novel discovery are separate scores. This module never
selects an exploit, never emits a request, and never treats an HTTP status
alone as a confirmed finding. A hypothesis stays open until two evidenced
observations disagree across role or object identity.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

_AUTO_PROFILES = frozenset({
    "bug-bounty-safe",
    "api-review",
    "authenticated-audit",
    "training-lab",
    "discovery",
})
_EXPLICIT_PROFILES = _AUTO_PROFILES | frozenset({"internal-lab", "safe-web"})
_ID_PARAMS = frozenset({
    "id",
    "uid",
    "uuid",
    "user_id",
    "account_id",
    "order_id",
    "object_id",
    "resource_id",
})
_MAX_HYPOTHESES = 12
_ORACLE_VERDICTS = frozenset({"confirmed", "refuted", "inconclusive", "blocked"})


@dataclass
class SurfaceRoute:
    path: str
    params: List[str] = field(default_factory=list)
    requires_auth: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ApplicationSurface:
    """Routes, parameters, roles and objects already observed. Not a target list."""

    routes: List[SurfaceRoute] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    spec_paths: List[str] = field(default_factory=list)
    catalog_routes: List[str] = field(default_factory=list)
    covered_routes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "routes": [row.to_dict() for row in self.routes],
            "roles": list(self.roles),
            "spec_paths": list(self.spec_paths),
            "catalog_routes": list(self.catalog_routes),
            "covered_routes": list(self.covered_routes),
        }


@dataclass
class DiscoveryHypothesis:
    statement: str
    invariant: str
    fingerprint: str
    kind: str
    route: str = ""
    status: str = "open"
    origin: str = "novel"
    module_path: Optional[str] = None
    support_ids: List[str] = field(default_factory=list)
    contradict_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["counts_toward_mission_completion"] = False
        return payload


@dataclass
class DifferentialObservation:
    role: str
    object_id: str
    status: int
    body_hash: str
    length: int = 0
    evidence_id: str = ""

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "DifferentialObservation":
        data = dict(payload or {})
        return cls(
            role=str(data.get("role") or ""),
            object_id=str(data.get("object_id") or ""),
            status=int(data.get("status", 0) or 0),
            body_hash=str(data.get("body_hash") or ""),
            length=int(data.get("length", 0) or 0),
            evidence_id=str(data.get("evidence_id") or ""),
        )


def discovery_mode_enabled(state: Any) -> bool:
    """Enable discovery only for an explicit research profile.

    ``discovery_enabled=False`` always wins. ``True`` still requires a mission
    in the allowlist, including ``internal-lab`` and ``safe-web``. Other
    missions never turn discovery on by themselves.
    """
    flag = getattr(state, "discovery_enabled", None)
    if flag is False:
        return False
    mission = _mission_name(state)
    if flag is True:
        return mission in _EXPLICIT_PROFILES
    return mission in _AUTO_PROFILES


def build_application_surface(kb: Mapping[str, Any]) -> ApplicationSurface:
    routes = _routes_from_kb(kb)
    return ApplicationSurface(
        routes=routes,
        roles=_roles_from_kb(kb),
        spec_paths=_string_list(kb.get("openapi_paths")),
        catalog_routes=_string_list(kb.get("known_issue_routes")),
        covered_routes=_string_list(kb.get("covered_routes")),
    )


def propose_hypotheses(surface: ApplicationSurface) -> List[DiscoveryHypothesis]:
    """Structural hypotheses only. None of them name a module or a request."""
    found: List[DiscoveryHypothesis] = []
    role_key = ",".join(surface.roles)
    crawled = {row.path for row in surface.routes}
    for route in surface.routes:
        if _route_in(route.path, surface.catalog_routes):
            found.append(_hypothesis(
                kind="catalog_overlap",
                route=route.path,
                origin="catalog",
                statement=f"{route.path} is already covered by a known issue route.",
                invariant="A catalog match is an exploitation prior, not a novel finding.",
                fingerprint=f"catalog_overlap:{route.path}",
            ))
            continue
        if route.path not in set(surface.covered_routes):
            found.append(_hypothesis(
                kind="uncovered_surface",
                route=route.path,
                statement=f"{route.path} was observed and has no coverage evidence yet.",
                invariant="An observed route stays uncovered until an evidenced observation is recorded.",
                fingerprint=f"uncovered_surface:{route.path}",
            ))
        id_params = [name for name in route.params if name in _ID_PARAMS]
        if id_params and len(surface.roles) >= 2:
            param = id_params[0]
            found.append(_hypothesis(
                kind="cross_role_invariant",
                route=route.path,
                statement=(
                    f"The same {param} on {route.path} must not yield different bodies "
                    f"for roles {role_key} unless ownership is evidenced."
                ),
                invariant="Cross-role body difference on one object identifier requires two evidence ids.",
                fingerprint=f"cross_role_invariant:{route.path}:{param}:{role_key}",
            ))
    for spec_path in surface.spec_paths:
        if spec_path not in crawled:
            found.append(_hypothesis(
                kind="spec_drift",
                route=spec_path,
                statement=f"{spec_path} is declared by the specification and absent from crawled routes.",
                invariant="Specification drift is a coverage gap until the route is observed.",
                fingerprint=f"spec_drift:{spec_path}",
            ))
    return found[:_MAX_HYPOTHESES]


def judge_differential(
    left: DifferentialObservation,
    right: DifferentialObservation,
) -> str:
    """Confirm only a cross-identity content difference backed by evidence.

    Identical hashes with a different status stay inconclusive. Same-identity
    differences are not access-control proof.
    """
    if not left.evidence_id or not right.evidence_id:
        return "blocked"
    content_differs = bool(left.body_hash) and bool(right.body_hash) and left.body_hash != right.body_hash
    status_differs = left.status != right.status
    same_identity = left.role == right.role and left.object_id == right.object_id
    if same_identity:
        return "inconclusive" if (content_differs or status_differs) else "refuted"
    if content_differs:
        return "confirmed"
    if status_differs:
        return "inconclusive"
    return "refuted"


def apply_oracle(
    hypothesis: DiscoveryHypothesis,
    left: DifferentialObservation,
    right: DifferentialObservation,
) -> DiscoveryHypothesis:
    verdict = judge_differential(left, right)
    if verdict not in _ORACLE_VERDICTS:
        verdict = "blocked"
    hypothesis.status = {
        "confirmed": "confirmed",
        "refuted": "refuted",
        "blocked": "blocked",
    }.get(verdict, "open")
    if verdict == "confirmed":
        hypothesis.support_ids = _uniq([left.evidence_id, right.evidence_id])
        hypothesis.contradict_ids = []
    elif verdict == "refuted":
        hypothesis.contradict_ids = _uniq([left.evidence_id, right.evidence_id])
    return hypothesis


def score_novelty(hypotheses: Sequence[DiscoveryHypothesis], surface: ApplicationSurface) -> Dict[str, Any]:
    novel = [row for row in hypotheses if row.origin != "catalog"]
    novel_open = [row for row in novel if row.status == "open"]
    novel_confirmed = [row for row in novel if row.status == "confirmed"]
    catalog_matches = [row for row in hypotheses if row.origin == "catalog"]
    uncovered = [
        row.path for row in surface.routes
        if row.path not in set(surface.covered_routes) and not _route_in(row.path, surface.catalog_routes)
    ]
    return {
        "discovery_score": len(novel_confirmed) * 2 + len(novel_open),
        "novel_open": len(novel_open),
        "novel_confirmed": len(novel_confirmed),
        "catalog_matches": len(catalog_matches),
        "uncovered_routes": uncovered,
        "counts_toward_mission_completion": False,
    }


def sync_discovery(state: Any) -> Dict[str, Any]:
    """Refresh ``kb['discovery']`` when the mode is on. Does not plan actions."""
    if not discovery_mode_enabled(state):
        return {"enabled": False, "actions": []}
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        kb = {}
        state.knowledge_base = kb
    surface = build_application_surface(kb)
    previous = kb.get("discovery") if isinstance(kb.get("discovery"), dict) else {}
    merged = _merge_hypotheses(previous.get("hypotheses") or [], propose_hypotheses(surface))
    novelty = score_novelty(merged, surface)
    record = {
        "enabled": True,
        "mission_profile": _mission_name(state),
        "surface": surface.to_dict(),
        "hypotheses": [row.to_dict() for row in merged],
        "novelty": novelty,
        "actions": [],
    }
    kb["discovery"] = record
    return record


def discovery_summary(kb: Mapping[str, Any]) -> Dict[str, Any]:
    raw = kb.get("discovery") if isinstance(kb, Mapping) else None
    if not isinstance(raw, dict) or not raw.get("enabled"):
        return {"enabled": False}
    novelty = raw.get("novelty") if isinstance(raw.get("novelty"), dict) else {}
    statements = []
    for row in list(raw.get("hypotheses") or [])[:3]:
        if isinstance(row, dict) and row.get("statement"):
            statements.append({
                "status": row.get("status"),
                "origin": row.get("origin"),
                "statement": row.get("statement"),
            })
    return {
        "enabled": True,
        "discovery_score": novelty.get("discovery_score", 0),
        "novel_open": novelty.get("novel_open", 0),
        "novel_confirmed": novelty.get("novel_confirmed", 0),
        "catalog_matches": novelty.get("catalog_matches", 0),
        "hypotheses": statements,
        "counts_toward_mission_completion": False,
    }


def _merge_hypotheses(
    previous: Sequence[Any],
    proposed: Sequence[DiscoveryHypothesis],
) -> List[DiscoveryHypothesis]:
    by_fp: Dict[str, DiscoveryHypothesis] = {}
    for row in previous:
        if not isinstance(row, dict):
            continue
        fingerprint = str(row.get("fingerprint") or "")
        if not fingerprint:
            continue
        by_fp[fingerprint] = DiscoveryHypothesis(
            statement=str(row.get("statement") or ""),
            invariant=str(row.get("invariant") or ""),
            fingerprint=fingerprint,
            kind=str(row.get("kind") or ""),
            route=str(row.get("route") or ""),
            status=str(row.get("status") or "open"),
            origin=str(row.get("origin") or "novel"),
            module_path=None,
            support_ids=[str(item) for item in (row.get("support_ids") or [])],
            contradict_ids=[str(item) for item in (row.get("contradict_ids") or [])],
        )
    for row in proposed:
        current = by_fp.get(row.fingerprint)
        if current is None:
            by_fp[row.fingerprint] = row
            continue
        if current.status in {"confirmed", "refuted", "blocked"}:
            continue
        current.statement = row.statement
        current.invariant = row.invariant
    ordered = list(by_fp.values())
    ordered.sort(key=lambda row: (row.origin == "catalog", row.fingerprint))
    return ordered[:_MAX_HYPOTHESES]


def _hypothesis(**kwargs: Any) -> DiscoveryHypothesis:
    kwargs["module_path"] = None
    return DiscoveryHypothesis(**kwargs)


def _mission_name(state: Any) -> str:
    policy = getattr(state, "runtime_policy", None)
    raw = str(getattr(policy, "mission_profile", "") or "") if policy is not None else ""
    if not raw:
        kb = getattr(state, "knowledge_base", None)
        if isinstance(kb, dict):
            raw = str(kb.get("mission_profile") or "")
    return raw.strip().lower()


def _routes_from_kb(kb: Mapping[str, Any]) -> List[SurfaceRoute]:
    params_by_route: Dict[str, List[str]] = {}
    loose_params = _param_names(kb.get("discovered_params"))
    for row in kb.get("discovered_params") or []:
        if isinstance(row, Mapping):
            route = _clean_path(row.get("route") or row.get("path"))
            name = _param_name(row.get("name") or row.get("param"))
            if route and name:
                params_by_route.setdefault(route, [])
                if name not in params_by_route[route]:
                    params_by_route[route].append(name)
    login = set(_string_list(kb.get("login_paths")))
    routes: List[SurfaceRoute] = []
    seen = set()
    for raw in list(kb.get("discovered_endpoints") or []) + list(kb.get("login_paths") or []):
        path = _clean_path(raw if isinstance(raw, str) else (raw.get("path") if isinstance(raw, Mapping) else ""))
        if not path or path in seen:
            continue
        seen.add(path)
        routes.append(SurfaceRoute(
            path=path,
            params=list(params_by_route.get(path) or []),
            requires_auth=path in login or path.startswith("/admin"),
        ))
    unbound = [row for row in routes if not row.params and row.path not in login]
    if len(unbound) == 1 and loose_params:
        unbound[0].params = list(loose_params)
    return routes


def _roles_from_kb(kb: Mapping[str, Any]) -> List[str]:
    roles: List[str] = []
    for source in (kb.get("roles"), kb.get("identities")):
        roles.extend(_role_names(source))
    return _uniq(roles)


def _role_names(value: Any) -> Iterable[str]:
    if not isinstance(value, list):
        return []
    names: List[str] = []
    for row in value:
        if isinstance(row, str) and row.strip():
            names.append(row.strip())
        elif isinstance(row, Mapping):
            token = str(row.get("role") or row.get("name") or "").strip()
            if token:
                names.append(token)
    return names


def _param_names(value: Any) -> List[str]:
    names: List[str] = []
    for row in value or []:
        if isinstance(row, str):
            name = _param_name(row)
        elif isinstance(row, Mapping) and not (row.get("route") or row.get("path")):
            name = _param_name(row.get("name") or row.get("param"))
        else:
            name = ""
        if name:
            names.append(name)
    return _uniq(names)


def _param_name(value: Any) -> str:
    return str(value or "").strip().lower()


def _string_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    out: List[str] = []
    for row in value:
        path = _clean_path(row if isinstance(row, str) else "")
        if path:
            out.append(path)
    return _uniq(out)


def _clean_path(value: Any) -> str:
    text = str(value or "").strip()
    if not text.startswith("/"):
        return ""
    return text.split("?", 1)[0]


def _route_in(path: str, routes: Sequence[str]) -> bool:
    return path in set(routes)


def _uniq(items: Sequence[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items:
        token = str(item or "").strip()
        if not token or token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out
