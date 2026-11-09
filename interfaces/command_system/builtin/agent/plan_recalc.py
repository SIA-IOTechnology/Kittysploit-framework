#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect campaign asset deltas and trigger plan recalculation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.campaign_world import campaign_world_from_kb
from interfaces.command_system.builtin.agent.redaction import sanitize_nested

SCHEMA_VERSION = "1.0"

ASSET_KINDS: Tuple[str, ...] = ("identity", "credential", "session", "route")


@dataclass
class CampaignAssetSnapshot:
    identity: Tuple[str, ...] = field(default_factory=tuple)
    credential: Tuple[str, ...] = field(default_factory=tuple)
    session: Tuple[str, ...] = field(default_factory=tuple)
    route: Tuple[str, ...] = field(default_factory=tuple)
    tech: Tuple[str, ...] = field(default_factory=tuple)
    endpoints: Tuple[str, ...] = field(default_factory=tuple)
    interesting_urls: Tuple[str, ...] = field(default_factory=tuple)

    def fingerprint(self) -> str:
        parts = [
            f"identity:{','.join(self.identity)}",
            f"credential:{','.join(self.credential)}",
            f"session:{','.join(self.session)}",
            f"route:{','.join(self.route)}",
            f"tech:{','.join(self.tech)}",
            f"endpoints:{','.join(self.endpoints[:20])}",
            f"urls:{','.join(self.interesting_urls[:8])}",
        ]
        digest = hashlib.sha256("|".join(parts).encode("utf-8", errors="replace")).hexdigest()
        return digest[:20]

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "identity": list(self.identity),
            "credential": list(self.credential),
            "session": list(self.session),
            "route": list(self.route),
            "tech": list(self.tech),
            "endpoints": list(self.endpoints),
            "interesting_urls": list(self.interesting_urls),
            "fingerprint": self.fingerprint(),
        })


@dataclass
class PlanRecalcDecision:
    replan_required: bool = False
    reasons: List[str] = field(default_factory=list)
    revision: int = 0
    snapshot: Optional[CampaignAssetSnapshot] = None
    previous_snapshot: Optional[CampaignAssetSnapshot] = None

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "replan_required": self.replan_required,
            "reasons": self.reasons[:8],
            "revision": self.revision,
            "snapshot": self.snapshot.to_dict() if self.snapshot else {},
            "previous_snapshot": (
                self.previous_snapshot.to_dict() if self.previous_snapshot else {}
            ),
        })


def _sorted_tokens(values: Sequence[str]) -> Tuple[str, ...]:
    return tuple(sorted({str(item).strip() for item in values if str(item).strip()}))


def _identity_tokens(kb: Mapping[str, Any], state: Any = None) -> Tuple[str, ...]:
    tokens: List[str] = []
    for row in kb.get("credential_store") or []:
        if not isinstance(row, dict):
            continue
        username = str(row.get("username") or row.get("authenticated_as") or "").strip().lower()
        if username:
            tokens.append(f"user:{username}")
    active = kb.get("active_auth_context")
    if isinstance(active, dict):
        username = str(active.get("username") or active.get("authenticated_as") or "").strip().lower()
        if username:
            tokens.append(f"user:{username}")
    primitives = kb.get("host_primitives") if isinstance(kb.get("host_primitives"), dict) else {}
    for session_id, bundle in primitives.items():
        if not isinstance(bundle, dict):
            continue
        current = bundle.get("identity.current_user")
        if isinstance(current, dict):
            parsed = current.get("parsed")
            if isinstance(parsed, dict):
                raw = str(parsed.get("raw") or "").strip().lower()
                if raw:
                    tokens.append(f"primitive:{session_id}:{raw[:80]}")
    for name in kb.get("identity_names") or []:
        token = str(name or "").strip().lower()
        if token:
            tokens.append(f"name:{token}")
    verified = list(getattr(state, "verified_sessions", []) or []) if state is not None else []
    for sid in verified:
        tokens.append(f"session_identity:{sid}")
    return _sorted_tokens(tokens)


def _credential_tokens(kb: Mapping[str, Any], *, state: Any = None) -> Tuple[str, ...]:
    tokens: List[str] = []
    for row in kb.get("credential_store") or []:
        if not isinstance(row, dict):
            continue
        username = str(row.get("username") or "").strip().lower()
        password = str(row.get("password") or row.get("authenticated_password") or "").strip()
        source = str(row.get("source_module") or row.get("origin") or "").strip().lower()
        if username or password:
            pw_token = password if password.startswith("vault:") else hashlib.sha256(password.encode()).hexdigest()[:12] if password else ""
            tokens.append(f"cred:{username}:{pw_token}:{source}")
    persistent = kb.get("persistent_vault") if isinstance(kb.get("persistent_vault"), dict) else {}
    for row in persistent.get("entries") or []:
        if not isinstance(row, dict):
            continue
        cid = str(row.get("credential_id") or "").strip()
        handle = str(row.get("handle") or "").strip()
        if cid:
            tokens.append(f"vault_db:{cid}")
        if handle:
            tokens.append(f"vault_handle:{handle}")
    lateral = kb.get("scope_lateral") if isinstance(kb.get("scope_lateral"), dict) else {}
    for row in lateral.get("credentials") or []:
        if not isinstance(row, dict):
            continue
        cid = str(row.get("credential_id") or "").strip()
        if cid:
            tokens.append(f"scoped:{cid}")
    vault_index = kb.get("credential_vault_index") if isinstance(kb.get("credential_vault_index"), dict) else {}
    for handle in sorted(vault_index.keys()):
        tokens.append(f"vault:{handle}")
    return _sorted_tokens(tokens)


def _session_tokens(kb: Mapping[str, Any], state: Any = None) -> Tuple[str, ...]:
    tokens: List[str] = []
    for sid in getattr(state, "verified_sessions", []) or [] if state is not None else []:
        tokens.append(f"verified:{sid}")
    for sid in getattr(state, "new_sessions", []) or [] if state is not None else []:
        tokens.append(f"new:{sid}")
    broker = kb.get("session_broker") if isinstance(kb.get("session_broker"), dict) else {}
    for sid in broker.get("verified_session_ids") or []:
        tokens.append(f"broker:{sid}")
    world = campaign_world_from_kb(kb)
    for sid, row in world.sessions.items():
        if row.verified:
            tokens.append(f"world:{sid}:{row.service_id}")
    return _sorted_tokens(tokens)


def _tech_tokens(kb: Mapping[str, Any]) -> Tuple[str, ...]:
    return _sorted_tokens([str(h).lower() for h in (kb.get("tech_hints") or []) if str(h).strip()])


def _endpoint_tokens(kb: Mapping[str, Any]) -> Tuple[str, ...]:
    return _sorted_tokens([str(ep).lower() for ep in (kb.get("discovered_endpoints") or [])[:60] if str(ep).strip()])


def _interesting_url_tokens(kb: Mapping[str, Any]) -> Tuple[str, ...]:
    tokens: List[str] = []
    intel = kb.get("request_intel") if isinstance(kb.get("request_intel"), Mapping) else {}
    for row in intel.get("interesting_requests") or []:
        if not isinstance(row, Mapping):
            continue
        if int(row.get("interesting_score") or 0) < 8:
            continue
        url = str(row.get("url") or row.get("path") or "").strip().lower()
        if url:
            tokens.append(url)
    return _sorted_tokens(tokens)


def _route_tokens(kb: Mapping[str, Any]) -> Tuple[str, ...]:
    tokens: List[str] = []
    world = campaign_world_from_kb(kb)
    for host in world.hosts.values():
        for svc in host.services.values():
            tokens.append(f"svc:{host.host_id}:{svc.service_id}:{svc.capability_rung}")
    lateral = kb.get("scope_lateral") if isinstance(kb.get("scope_lateral"), dict) else {}
    for row in lateral.get("destinations") or []:
        if not isinstance(row, dict):
            continue
        host = str(row.get("host") or "")
        port = str(row.get("port") or "")
        if host:
            tokens.append(f"dest:{host}:{port}")
    for row in lateral.get("proposals") or []:
        if not isinstance(row, dict):
            continue
        tokens.append(
            f"proposal:{row.get('action')}:{row.get('target_host')}:{row.get('target_port')}:{row.get('credential_id')}"
        )
    if world.active_host_id:
        tokens.append(f"focus_host:{world.active_host_id}")
    if world.active_service_id:
        tokens.append(f"focus_service:{world.active_service_id}")
    return _sorted_tokens(tokens)


def build_campaign_asset_snapshot(kb: Mapping[str, Any], *, state: Any = None) -> CampaignAssetSnapshot:
    return CampaignAssetSnapshot(
        identity=_identity_tokens(kb, state=state),
        credential=_credential_tokens(kb, state=state),
        session=_session_tokens(kb, state=state),
        route=_route_tokens(kb),
        tech=_tech_tokens(kb),
        endpoints=_endpoint_tokens(kb),
        interesting_urls=_interesting_url_tokens(kb),
    )


def _delta_reasons(previous: CampaignAssetSnapshot, current: CampaignAssetSnapshot) -> List[str]:
    reasons: List[str] = []
    if current.identity != previous.identity:
        reasons.append("new_identity")
    if current.credential != previous.credential:
        reasons.append("new_credential")
    if current.session != previous.session:
        reasons.append("new_session")
    if current.route != previous.route:
        reasons.append("new_route")
    if current.tech != previous.tech:
        reasons.append("new_tech")
    if current.endpoints != previous.endpoints:
        reasons.append("new_endpoint")
    if current.interesting_urls != previous.interesting_urls:
        reasons.append("interesting_url")
    if any(
        r in {"new_tech", "new_endpoint", "interesting_url"}
        for r in reasons
    ):
        reasons.append("new_surface")
    return reasons


def evaluate_plan_recalc(
    kb: MutableMapping[str, Any],
    *,
    state: Any = None,
    force: bool = False,
) -> PlanRecalcDecision:
    current = build_campaign_asset_snapshot(kb, state=state)
    store = kb.get("plan_recalc") if isinstance(kb.get("plan_recalc"), dict) else {}
    previous_raw = store.get("snapshot") if isinstance(store.get("snapshot"), dict) else {}
    previous = CampaignAssetSnapshot(
        identity=tuple(previous_raw.get("identity") or []),
        credential=tuple(previous_raw.get("credential") or []),
        session=tuple(previous_raw.get("session") or []),
        route=tuple(previous_raw.get("route") or []),
    )
    revision = int(store.get("revision") or 0)
    reasons = _delta_reasons(previous, current) if store else (["initial_snapshot"] if force else [])
    replan_required = bool(reasons) and (
        force
        or any(
            reason in {
                "new_identity",
                "new_credential",
                "new_session",
                "new_route",
                "new_tech",
                "new_endpoint",
                "interesting_url",
                "new_surface",
            }
            for reason in reasons
        )
    )
    if replan_required and reasons != ["initial_snapshot"]:
        revision += 1
    decision = PlanRecalcDecision(
        replan_required=replan_required and reasons != ["initial_snapshot"],
        reasons=reasons if replan_required else [],
        revision=revision,
        snapshot=current,
        previous_snapshot=previous if store else None,
    )
    kb["plan_recalc"] = sanitize_nested({
        "schema_version": SCHEMA_VERSION,
        "revision": revision,
        "replan_required": decision.replan_required,
        "reasons": decision.reasons,
        "snapshot": current.to_dict(),
        "last_fingerprint": current.fingerprint(),
    })
    return decision


def apply_plan_recalc_to_state(state: Any, decision: PlanRecalcDecision) -> None:
    if not decision.replan_required:
        return
    state.replan_pending = True
    execution_plan = getattr(state, "execution_plan", None)
    if isinstance(execution_plan, dict):
        execution_plan["stale"] = True
        execution_plan["replan_reasons"] = list(decision.reasons)
        state.execution_plan = execution_plan
    hierarchical = getattr(state, "hierarchical_plan", None)
    if isinstance(hierarchical, dict):
        hierarchical["stale"] = True
        state.hierarchical_plan = hierarchical
    try:
        from interfaces.command_system.builtin.agent.reactive_surface_orchestrator import (
            on_surface_replan,
        )

        on_surface_replan(
            state,
            reasons=decision.reasons,
            previous_snapshot=(
                decision.previous_snapshot.to_dict() if decision.previous_snapshot else {}
            ),
            current_snapshot=decision.snapshot.to_dict() if decision.snapshot else {},
        )
    except Exception:
        pass
    if decision.replan_required and isinstance(getattr(state, "knowledge_base", None), dict):
        try:
            from interfaces.command_system.builtin.agent.plan_subtask_refiner import refine_after_recalc

            refine_after_recalc(
                state.knowledge_base,
                reasons=decision.reasons,
                state=state,
            )
        except Exception:
            pass


def sync_plan_recalc(
    kb: MutableMapping[str, Any],
    *,
    state: Any = None,
) -> PlanRecalcDecision:
    decision = evaluate_plan_recalc(kb, state=state)
    if state is not None:
        apply_plan_recalc_to_state(state, decision)
    return decision


def consume_plan_recalc(state: Any) -> List[str]:
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return []
    store = kb.get("plan_recalc") if isinstance(kb.get("plan_recalc"), dict) else {}
    if not store.get("replan_required"):
        return []
    reasons = [str(item) for item in (store.get("reasons") or []) if str(item).strip()]
    store["replan_required"] = False
    kb["plan_recalc"] = store
    state.replan_pending = False
    return reasons
