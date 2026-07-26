#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Compact decision episodes with fingerprinted context for verified learning."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

from interfaces.command_system.builtin.agent.attack_chain_memory import (
    OBS_CONFIRMED,
    OBS_REFUTED,
    extract_observation_from_result,
)
from interfaces.command_system.builtin.agent.learning_governance import contains_secret_blob
from interfaces.command_system.builtin.agent.module_performance_memory import classify_target_profile
from interfaces.command_system.builtin.agent.redaction import sanitize_nested

VERDICT_CONFIRMED = "confirmed"
VERDICT_REFUTED = "refuted"
LEARNABLE_VERDICTS = frozenset({VERDICT_CONFIRMED, VERDICT_REFUTED})

MISSION_MEMORY_KEY = "learning_mission"
EPISODE_SCHEMA_VERSION = "1.0"
MAX_EPISODES_MISSION = 128
MAX_SAFE_PARAMS = 12


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def is_learnable_verdict(verdict: str) -> bool:
    return str(verdict or "").strip().lower() in LEARNABLE_VERDICTS


def sanitize_episode_params(params: Mapping[str, Any]) -> Dict[str, Any]:
    safe: Dict[str, Any] = {}
    if not isinstance(params, Mapping):
        return safe
    blocked_keys = {
        "password",
        "pass",
        "passwd",
        "username",
        "user",
        "token",
        "api_key",
        "secret",
        "cookie",
        "session_cookie",
        "authorization",
    }
    for key, value in list(params.items())[:MAX_SAFE_PARAMS]:
        name = str(key or "").strip().lower()
        if not name or name in blocked_keys:
            continue
        if isinstance(value, (str, int, float, bool)):
            text = str(value)
            if contains_secret_blob(text):
                continue
            safe[name] = text[:180] if isinstance(value, str) else value
    return safe


def build_context_index(state: Any, kb: Mapping[str, Any]) -> Dict[str, Any]:
    target_info = getattr(state, "target_info", {}) or {}
    host_profile = getattr(state, "host_profile", {}) or {}
    services: List[str] = []
    if isinstance(host_profile, dict):
        for row in host_profile.get("service_fingerprints") or []:
            if not isinstance(row, dict):
                continue
            label = str(row.get("protocol") or row.get("service") or row.get("name") or "").strip()
            port = row.get("port")
            version = str(row.get("version") or "").strip()
            if label and port is not None:
                services.append(f"{label}:{port}:{version}" if version else f"{label}:{port}")
            elif label:
                services.append(label)
    for item in kb.get("identified_services") or []:
        token = str(item or "").strip()
        if token and token not in services:
            services.append(token)

    tech_hints = [str(x).lower() for x in (kb.get("tech_hints") or [])[:8]]
    signals = {str(x).lower() for x in (kb.get("risk_signals") or [])}
    auth = "session" if "authenticated_session" in signals else (
        "login" if signals.intersection({"login_form_detected", "login_surface_detected"}) else "none"
    )
    os_family = str(host_profile.get("os_family") or kb.get("os_family") or "unknown").lower()
    arch = str(host_profile.get("architecture") or kb.get("architecture") or "unknown").lower()
    protections = sorted(
        token for token in signals
        if any(marker in token for marker in ("waf", "blocking", "rate", "captcha", "mfa"))
    )[:6]
    failure_type = str(getattr(state, "campaign_stop_reason", "") or kb.get("last_failure_type") or "")[:120]
    return sanitize_nested({
        "os": os_family,
        "architecture": arch,
        "services": services[:8],
        "auth": auth,
        "protections": protections,
        "tech_hints": tech_hints,
        "target_profile": classify_target_profile(kb if isinstance(kb, dict) else {}),
        "failure_type": failure_type,
        "protocol": str(getattr(state, "protocol", "") or kb.get("protocol") or "").lower(),
    })


def build_context_fingerprint(index: Mapping[str, Any]) -> str:
    services = ",".join(sorted(str(x) for x in (index.get("services") or [])))
    tech = ",".join(sorted(str(x) for x in (index.get("tech_hints") or [])))
    prot = ",".join(sorted(str(x) for x in (index.get("protections") or [])))
    digest = hashlib.sha256(
        (
            f"{index.get('os')}|{index.get('architecture')}|{index.get('auth')}|"
            f"{index.get('target_profile')}|{services}|{tech}|{prot}|{index.get('protocol')}"
        ).encode("utf-8", "ignore"),
    ).hexdigest()
    return f"ctx_{digest[:12]}"


@dataclass
class DecisionEpisode:
    episode_id: str = ""
    schema_version: str = EPISODE_SCHEMA_VERSION
    context_fingerprint: str = ""
    context_index: Dict[str, Any] = field(default_factory=dict)
    action_path: str = ""
    safe_params: Dict[str, Any] = field(default_factory=dict)
    verdict: str = ""
    real_gain: float = 0.0
    failure_type: str = ""
    phase: str = ""
    module_version: str = ""
    tenant_id: str = ""
    run_id: str = ""
    recorded_at: str = ""

    def __post_init__(self) -> None:
        self.action_path = str(self.action_path or "").strip()[:300]
        self.verdict = str(self.verdict or "").strip().lower()
        self.phase = str(self.phase or "").strip()[:80]
        self.failure_type = str(self.failure_type or "").strip()[:120]
        self.module_version = str(self.module_version or "unknown").strip()[:40]
        self.tenant_id = str(self.tenant_id or "default").strip()[:120]
        self.run_id = str(self.run_id or "").strip()[:80]
        if not self.recorded_at:
            self.recorded_at = _now_iso()
        if not self.episode_id:
            digest = hashlib.sha256(
                f"{self.context_fingerprint}:{self.action_path}:{self.verdict}:{self.recorded_at}".encode(
                    "utf-8", "ignore",
                ),
            ).hexdigest()
            self.episode_id = digest[:12]

    @property
    def learnable(self) -> bool:
        return is_learnable_verdict(self.verdict)

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested(asdict(self))


def verdict_from_observation_status(status: str) -> str:
    token = str(status or "").strip().lower()
    if token == OBS_CONFIRMED:
        return VERDICT_CONFIRMED
    if token == OBS_REFUTED:
        return VERDICT_REFUTED
    return ""


def compute_real_gain(
    *,
    verdict: str,
    vulnerable: bool,
    auth_gain: bool = False,
    shell_gain: bool = False,
    delta_info: float = 0.0,
) -> float:
    if verdict == VERDICT_CONFIRMED:
        gain = 1.0 + max(0.0, float(delta_info or 0.0)) * 0.15
        if vulnerable:
            gain += 1.5
        if auth_gain:
            gain += 2.0
        if shell_gain:
            gain += 3.5
        return round(gain, 4)
    if verdict == VERDICT_REFUTED:
        return round(-0.35 - min(0.5, max(0.0, float(delta_info or 0.0)) * 0.05), 4)
    return 0.0


def episode_from_module_result(
    state: Any,
    result: Mapping[str, Any],
    *,
    phase: str = "",
    agent_meta: Optional[Mapping[str, Any]] = None,
    safe_params: Optional[Mapping[str, Any]] = None,
    tenant_id: str = "",
) -> Optional[DecisionEpisode]:
    if not isinstance(result, Mapping):
        return None
    kb = getattr(state, "knowledge_base", None)
    kb_map = kb if isinstance(kb, dict) else {}
    observation = extract_observation_from_result(
        str(result.get("path") or ""),
        result,
        agent_meta,
        phase=phase,
    )
    verdict = verdict_from_observation_status(observation.status)
    if not is_learnable_verdict(verdict):
        return None
    index = build_context_index(state, kb_map)
    fingerprint = build_context_fingerprint(index)
    details = result.get("details") if isinstance(result.get("details"), dict) else {}
    params = sanitize_episode_params(safe_params or details)
    agent = agent_meta if isinstance(agent_meta, dict) else {}
    module_version = str(agent.get("version") or agent.get("module_version") or "unknown")
    return DecisionEpisode(
        context_fingerprint=fingerprint,
        context_index=index,
        action_path=str(result.get("path") or ""),
        safe_params=params,
        verdict=verdict,
        real_gain=compute_real_gain(
            verdict=verdict,
            vulnerable=bool(result.get("vulnerable")),
        ),
        failure_type=str(index.get("failure_type") or ""),
        phase=phase,
        module_version=module_version,
        tenant_id=tenant_id,
        run_id=str(getattr(state, "run_id", "") or ""),
    )


def mission_memory(kb: MutableMapping[str, Any]) -> Dict[str, Any]:
    raw = kb.get(MISSION_MEMORY_KEY)
    if not isinstance(raw, dict):
        raw = {"episodes": [], "preferences": []}
        kb[MISSION_MEMORY_KEY] = raw
    if not isinstance(raw.get("episodes"), list):
        raw["episodes"] = []
    if not isinstance(raw.get("preferences"), list):
        raw["preferences"] = []
    return raw


def append_mission_episode(kb: MutableMapping[str, Any], episode: DecisionEpisode) -> None:
    store = mission_memory(kb)
    episodes: List[Dict[str, Any]] = list(store.get("episodes") or [])
    episodes.append(episode.to_dict())
    store["episodes"] = episodes[-MAX_EPISODES_MISSION:]
    kb[MISSION_MEMORY_KEY] = store


def append_preference_pair(
    kb: MutableMapping[str, Any],
    *,
    context_fingerprint: str,
    chosen_path: str,
    rejected_path: str,
    outcome: str,
    tenant_id: str = "",
) -> None:
    if not context_fingerprint or not chosen_path or not rejected_path:
        return
    if chosen_path == rejected_path:
        return
    store = mission_memory(kb)
    prefs: List[Dict[str, Any]] = list(store.get("preferences") or [])
    prefs.append(sanitize_nested({
        "context_fingerprint": context_fingerprint,
        "chosen_path": chosen_path[:300],
        "rejected_path": rejected_path[:300],
        "outcome": str(outcome or "")[:40],
        "tenant_id": tenant_id[:120],
        "recorded_at": _now_iso(),
    }))
    store["preferences"] = prefs[-MAX_EPISODES_MISSION:]
    kb[MISSION_MEMORY_KEY] = store


def retrieve_mission_episodes(
    kb: Mapping[str, Any],
    *,
    context_fingerprint: str = "",
    limit: int = 4,
) -> List[Dict[str, Any]]:
    store = kb.get(MISSION_MEMORY_KEY) if isinstance(kb, Mapping) else None
    if not isinstance(store, dict):
        return []
    rows = [row for row in (store.get("episodes") or []) if isinstance(row, dict)]
    if context_fingerprint:
        rows = [row for row in rows if row.get("context_fingerprint") == context_fingerprint]
    return rows[-max(1, int(limit or 1)):]
