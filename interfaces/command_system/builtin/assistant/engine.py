#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Suggestion engine: metadata + results + OT/IoT/shell heuristics (no LLM)."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from interfaces.command_system.builtin.assistant.context import AssistantContext, Suggestion

_MAX_SUGGESTIONS = 5

_SESSION_TYPE_POST: Dict[str, List[tuple]] = {
    "shell": [
        ("use post/shell/multi/gather/privesc_suggester", "privilege escalation hints"),
        ("use post/shell/linux/busybox/firmware_info", "firmware / device fingerprint"),
    ],
    "meterpreter": [
        ("sessions interact {sid}", "open the Meterpreter session"),
    ],
    "mqtt": [
        ("use post/mqtt/gather/broker_audit", "audit MQTT broker from session"),
    ],
    "coap": [
        ("sessions interact {sid}", "open CoAP session shell"),
    ],
    "onvif": [
        ("use auxiliary/admin/http/camera/onvif_device_info", "ONVIF device info"),
        ("use auxiliary/admin/http/camera/onvif_snapshot", "grab camera snapshot"),
    ],
    "rtsp": [
        ("sessions interact {sid}", "open RTSP session shell"),
    ],
    "upnp": [
        ("sessions interact {sid}", "open UPnP session shell"),
    ],
    "bacnet": [
        ("sessions interact {sid}", "open BACnet session shell"),
    ],
    "dnp3": [
        ("sessions interact {sid}", "open DNP3 session shell"),
    ],
    "iec104": [
        ("sessions interact {sid}", "open IEC-104 session shell"),
    ],
    "iec61850": [
        ("sessions interact {sid}", "open IEC-61850 session shell"),
    ],
    "ble": [
        ("sessions interact {sid}", "open BLE GATT session"),
    ],
    "matter": [
        ("sessions interact {sid}", "open Matter session shell"),
    ],
    "browser": [
        ("sessions access {sid}", "interact with browser session"),
    ],
}

_PROTOCOL_TOKENS = (
    "modbus", "s7comm", "s7", "dnp3", "bacnet", "iec104", "iec61850", "mms",
    "enip", "opcua", "mqtt", "coap", "onvif", "upnp", "ssdp", "rtsp",
    "matter", "ble", "mdns", "bonjour",
)


def _resolve_module_path(module: Any, explicit: str = "") -> str:
    if explicit:
        return str(explicit).strip()
    if module is None:
        return ""
    for attr in ("module_path", "path"):
        candidate = getattr(module, attr, None)
        if candidate:
            return str(candidate).strip()
    info = getattr(module, "__info__", {}) or {}
    for key in ("path", "module_path", "fullname"):
        if info.get(key):
            return str(info[key]).strip()
    raw = str(getattr(module, "__module__", "") or "")
    for prefix in ("modules.",):
        if raw.startswith(prefix):
            return raw[len(prefix):].replace(".", "/")
    return raw.replace(".", "/") if raw else ""


def _flatten_text(value: Any, *, limit: int = 4000) -> str:
    chunks: List[str] = []

    def _walk(item: Any, depth: int = 0) -> None:
        if item is None or depth > 4:
            return
        if isinstance(item, str):
            text = item.strip()
            if text:
                chunks.append(text)
            return
        if isinstance(item, dict):
            for key, val in item.items():
                chunks.append(str(key))
                _walk(val, depth + 1)
            return
        if isinstance(item, (list, tuple, set)):
            for entry in item:
                _walk(entry, depth + 1)
            return
        chunks.append(str(item))

    _walk(value)
    return " ".join(chunks)[:limit].lower()


def _mini_kb_from_context(ctx: AssistantContext) -> Dict[str, Any]:
    kb: Dict[str, Any] = {}
    if isinstance(ctx.knowledge_base, dict):
        kb.update(ctx.knowledge_base)

    blob = " ".join(
        filter(
            None,
            [
                _flatten_text(ctx.finding),
                _flatten_text(ctx.evidence),
                str(ctx.module_path or "").lower(),
                str(ctx.session_type or "").lower(),
            ],
        )
    )
    protocols: Set[str] = set()
    for token in _PROTOCOL_TOKENS:
        if token in blob:
            protocols.add(token)

    if protocols:
        kb.setdefault("ot_passive_protocols", ",".join(sorted(protocols)))
        kb.setdefault("ot_context_established", True)
        assets = kb.setdefault("ot_assets", {})
        if isinstance(assets, dict) and "assistant" not in assets:
            assets["assistant"] = {"protocols": sorted(protocols)}

    if ctx.session_id or ctx.event == "session_created":
        caps = kb.setdefault("capabilities", set())
        if isinstance(caps, set):
            caps.add("shell")
        elif isinstance(caps, list):
            if "shell" not in caps:
                caps.append("shell")

    return kb


def _followups_from_module(module: Any, module_path: str) -> List[Suggestion]:
    info = getattr(module, "__info__", {}) or {} if module is not None else {}
    agent = info.get("agent") if isinstance(info, dict) else None
    path = module_path or _resolve_module_path(module)

    followups: List[str] = []
    try:
        from interfaces.command_system.builtin.agent.chain_meta import normalize_chain_block
        from interfaces.command_system.builtin.agent.metadata_chain_inference import (
            chain_is_empty,
            infer_chain_metadata,
        )

        chain = {}
        if isinstance(agent, dict):
            chain = normalize_chain_block(agent.get("chain"))
        if chain_is_empty(chain) and path:
            chain = infer_chain_metadata(path, info if isinstance(info, dict) else None)
        followups = list(chain.get("suggested_followups") or [])
    except Exception:
        followups = []

    out: List[Suggestion] = []
    for item in followups:
        path_s = str(item).strip()
        if not path_s:
            continue
        action = path_s if path_s.startswith(("use ", "sessions ", "run", "set ")) else f"use {path_s}"
        out.append(Suggestion(action=action, reason="module chain follow-up"))
    return out


def _suggestions_from_execution(ctx: AssistantContext) -> List[Suggestion]:
    out: List[Suggestion] = []
    sid = str(ctx.session_id or "").strip()
    if not sid and ctx.execution is not None:
        sid = str(getattr(ctx.execution, "session_id", "") or "").strip()
    if sid:
        out.append(
            Suggestion(
                action=f"sessions interact {sid}",
                reason="session created — open interactive shell",
            )
        )
    return out


def _suggestions_from_check(ctx: AssistantContext) -> List[Suggestion]:
    if not ctx.check_vulnerable:
        return []
    path = ctx.module_path or _resolve_module_path(ctx.module)
    if path:
        return [
            Suggestion(action="run", reason="target looks vulnerable — exploit with current module"),
            Suggestion(action=f"use {path}", reason="reload exploit if you switched modules"),
        ]
    return [Suggestion(action="run", reason="target looks vulnerable — run current exploit")]


def _suggestions_from_sessions_list(ctx: AssistantContext) -> List[Suggestion]:
    out: List[Suggestion] = []
    for session in ctx.sessions or []:
        if len(out) >= _MAX_SUGGESTIONS:
            break
        if isinstance(session, dict):
            sid = str(session.get("id") or "").strip()
            stype = str(session.get("type") or session.get("session_type") or "session").strip()
        else:
            sid = str(getattr(session, "id", "") or "").strip()
            stype = str(getattr(session, "session_type", "") or "session").strip()
        if not sid:
            continue
        verb = "access" if stype.lower() == "browser" else "interact"
        out.append(
            Suggestion(
                action=f"sessions {verb} {sid}",
                reason=f"active {stype} session",
            )
        )
    return out


def _suggestions_from_session_type(ctx: AssistantContext) -> List[Suggestion]:
    sid = str(ctx.session_id or "").strip() or "{sid}"
    stype = str(ctx.session_type or "").strip().lower()
    if not stype:
        return []
    templates = _SESSION_TYPE_POST.get(stype)
    if not templates:
        # fuzzy match keys contained in session type
        for key, rows in _SESSION_TYPE_POST.items():
            if key in stype:
                templates = rows
                break
    if not templates:
        if sid and sid != "{sid}":
            return [
                Suggestion(
                    action=f"sessions interact {sid}",
                    reason=f"new {stype or 'session'} — interact",
                )
            ]
        return []

    out: List[Suggestion] = []
    for action_tmpl, reason in templates:
        action = action_tmpl.replace("{sid}", sid if sid != "{sid}" else "<id>")
        out.append(Suggestion(action=action, reason=reason))
    return out


def _has_ot_iot_signal(ctx: AssistantContext, kb: Dict[str, Any]) -> bool:
    if kb.get("ot_passive_protocols") or kb.get("ot_context_established"):
        return True
    blob = " ".join(
        filter(
            None,
            [
                str(ctx.module_path or "").lower(),
                str(ctx.session_type or "").lower(),
                _flatten_text(ctx.finding),
                _flatten_text(ctx.evidence),
            ],
        )
    )
    markers = (
        "/ics/", "/iot/", "modbus", "s7comm", "bacnet", "dnp3", "iec104",
        "iec61850", "mqtt", "coap", "onvif", "upnp", "rtsp", "matter",
        "ble", "mdns", "ssdp", "opcua", "enip",
    )
    return any(m in blob for m in markers)


def _suggestions_from_heuristics(ctx: AssistantContext) -> List[Suggestion]:
    out: List[Suggestion] = []
    kb = _mini_kb_from_context(ctx)
    ot_signal = _has_ot_iot_signal(ctx, kb)

    if ot_signal:
        try:
            from interfaces.command_system.builtin.agent.ot_policy import (
                suggest_iot_discovery_path,
                suggest_ot_active_handoff,
            )

            handoffs = list(suggest_ot_active_handoff(kb) or [])
            for path in handoffs:
                path_s = str(path).strip()
                if path_s:
                    out.append(Suggestion(action=f"use {path_s}", reason="OT/IoT protocol handoff"))

            # Full IoT discovery baseline only when no protocol-specific handoff matched
            if not handoffs and ctx.event in ("run", "check", "session_created"):
                iot = suggest_iot_discovery_path(kb) or {}
                for path in (iot.get("suggested_modules") or [])[:3]:
                    path_s = str(path).strip()
                    if path_s:
                        out.append(Suggestion(action=f"use {path_s}", reason="IoT discovery path"))
        except Exception:
            pass

    stype = str(ctx.session_type or "").lower()
    if isinstance(ctx.knowledge_base, dict) and (
        ctx.session_id or ctx.event == "session_created"
    ):
        if stype in ("", "shell", "meterpreter", "beacon", "polling", "http_polling") or (
            "shell" in stype and "mqtt" not in stype
        ):
            try:
                from interfaces.command_system.builtin.agent.goal_planner import (
                    suggest_shell_plan_followups,
                )

                for path in suggest_shell_plan_followups(ctx.knowledge_base) or []:
                    path_s = str(path).strip()
                    if path_s:
                        out.append(Suggestion(action=f"use {path_s}", reason="shell progression"))
            except Exception:
                pass

    # Catalog follow-ups only when a real agent KB is already attached
    if isinstance(ctx.knowledge_base, dict) and ctx.knowledge_base.get("module_capability_catalog"):
        try:
            from interfaces.command_system.builtin.agent.attack_chain_memory import (
                suggest_chain_module_paths,
            )

            for path in sorted(suggest_chain_module_paths(ctx.knowledge_base) or []):
                path_s = str(path).strip()
                if path_s:
                    out.append(Suggestion(action=f"use {path_s}", reason="capability chain"))
        except Exception:
            pass

    return out


def _dedupe(suggestions: List[Suggestion], *, limit: int = _MAX_SUGGESTIONS) -> List[Suggestion]:
    seen: Set[str] = set()
    out: List[Suggestion] = []
    for item in suggestions:
        action = str(item.action or "").strip()
        if not action:
            continue
        key = re.sub(r"\s+", " ", action.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(Suggestion(action=action, reason=item.reason))
        if len(out) >= limit:
            break
    return out


class AssistantEngine:
    """Build ranked next-action suggestions from an AssistantContext."""

    @staticmethod
    def suggest(ctx: AssistantContext) -> List[Suggestion]:
        if ctx is None:
            return []

        path = ctx.module_path or _resolve_module_path(ctx.module)
        if path and not ctx.module_path:
            ctx.module_path = path

        # Pull finding/evidence from execution when not set explicitly
        if ctx.execution is not None:
            if ctx.finding is None:
                ctx.finding = getattr(ctx.execution, "finding", None)
            if ctx.evidence is None:
                ctx.evidence = getattr(ctx.execution, "evidence", None)
            if not ctx.session_id:
                ctx.session_id = str(getattr(ctx.execution, "session_id", "") or "")

        collected: List[Suggestion] = []

        if ctx.event == "check":
            collected.extend(_suggestions_from_check(ctx))

        if ctx.event == "sessions_list":
            collected.extend(_suggestions_from_sessions_list(ctx))

        if ctx.event in ("run", "check") and ctx.module is not None:
            collected.extend(_followups_from_module(ctx.module, path))

        if ctx.event == "run":
            collected.extend(_suggestions_from_execution(ctx))

        if ctx.event == "session_created":
            collected.extend(_suggestions_from_session_type(ctx))
            if ctx.session_id:
                collected.insert(
                    0,
                    Suggestion(
                        action=f"sessions interact {ctx.session_id}",
                        reason="new session available",
                    ),
                )

        collected.extend(_suggestions_from_heuristics(ctx))

        # Session-type post modules also useful after run that created a session
        if ctx.event == "run" and ctx.session_id and ctx.session_type:
            collected.extend(_suggestions_from_session_type(ctx))

        return _dedupe(collected)
