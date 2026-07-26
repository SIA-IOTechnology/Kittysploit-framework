#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Agent session broker: register, neutral verify, dedup, heartbeat, campaign sync."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.redaction import sanitize_nested

SCHEMA_VERSION = "1.0"
NEUTRAL_FAILURE_MARKERS = (
    "connection lost",
    "no response",
    "disconnected",
    "timed out",
    "session not found",
    "invalid session",
)
COMMAND_SESSION_TYPES = frozenset({
    "standard",
    "shell",
    "meterpreter",
    "ssh",
    "php",
    "http",
    "https",
    "android",
    "winrm",
    "smb",
})


@dataclass
class BrokerSessionRecord:
    session_id: str
    category: str = "standard"
    host: str = ""
    port: int = 0
    session_type: str = ""
    verified: bool = False
    verified_at: float = 0.0
    last_heartbeat: float = 0.0
    neutral_command: str = ""
    neutral_proof_hash: str = ""
    dedupe_key: str = ""
    status: str = "registered"
    verification_reason: str = ""
    service_id: str = ""
    host_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "session_id": self.session_id,
            "category": self.category,
            "host": self.host,
            "port": self.port,
            "session_type": self.session_type,
            "verified": self.verified,
            "verified_at": self.verified_at,
            "last_heartbeat": self.last_heartbeat,
            "neutral_command": self.neutral_command,
            "neutral_proof_hash": self.neutral_proof_hash,
            "dedupe_key": self.dedupe_key,
            "status": self.status,
            "verification_reason": self.verification_reason,
            "service_id": self.service_id,
            "host_id": self.host_id,
        })

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BrokerSessionRecord":
        port_raw = data.get("port")
        return cls(
            session_id=str(data.get("session_id") or ""),
            category=str(data.get("category") or "standard"),
            host=str(data.get("host") or ""),
            port=int(port_raw) if port_raw is not None and str(port_raw).strip().isdigit() else 0,
            session_type=str(data.get("session_type") or ""),
            verified=bool(data.get("verified", False)),
            verified_at=float(data.get("verified_at") or 0.0),
            last_heartbeat=float(data.get("last_heartbeat") or 0.0),
            neutral_command=str(data.get("neutral_command") or ""),
            neutral_proof_hash=str(data.get("neutral_proof_hash") or ""),
            dedupe_key=str(data.get("dedupe_key") or ""),
            status=str(data.get("status") or "registered"),
            verification_reason=str(data.get("verification_reason") or ""),
            service_id=str(data.get("service_id") or ""),
            host_id=str(data.get("host_id") or ""),
        )


from interfaces.command_system.builtin.agent.host_primitives import neutral_verify_command


def neutral_command_for_session_type(session_type: str) -> str:
    return neutral_verify_command(session_type)


SUCCESS_TEXT_MARKERS = ("success", "shell obtained", "session opened")


def neutral_output_valid(output: str, *, session_type: str = "") -> bool:
    text = str(output or "").strip()
    if not text or len(text) > 4000:
        return False
    lowered = text.lower()
    if any(marker in lowered for marker in NEUTRAL_FAILURE_MARKERS):
        return False
    if any(marker in lowered for marker in SUCCESS_TEXT_MARKERS) and "uid=" not in lowered and "\\" not in text:
        return False
    if "uid=" in lowered and "gid=" in lowered:
        return True
    token = str(session_type or "").lower()
    if token in {"winrm", "smb"} or "win" in token:
        return "\\" in text or "authority" in lowered
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return False
    primary = lines[0]
    if len(primary) >= 2 and primary.lower() not in {"error", "failed", "unknown"}:
        return True
    return False


def _proof_hash(output: str) -> str:
    digest = hashlib.sha256(str(output or "").encode("utf-8", errors="replace")).hexdigest()
    return digest[:16]


def _extract_command_output(result: Mapping[str, Any]) -> str:
    for key in ("output", "stdout", "message", "result"):
        value = result.get(key)
        if value is not None and str(value).strip():
            return str(value)
    details = result.get("details")
    if isinstance(details, dict):
        for key in ("command_output", "output", "stdout", "proof"):
            value = details.get(key)
            if value is not None and str(value).strip():
                return str(value)
    return ""


def neutral_proof_from_evidence(evidence_rows: Sequence[Mapping[str, Any]]) -> Tuple[bool, str]:
    for row in evidence_rows:
        if not isinstance(row, dict):
            continue
        for key in ("detail", "summary", "message", "proof", "command_output"):
            text = str(row.get(key) or "")
            if neutral_output_valid(text):
                return True, "neutral_evidence"
    return False, "no_neutral_evidence"


class SessionBroker:
    """Wrap SessionManager with verification, dedup and campaign-safe bookkeeping."""

    def __init__(self, framework: Any) -> None:
        self.framework = framework
        self._records: Dict[str, BrokerSessionRecord] = {}

    @classmethod
    def from_kb(cls, framework: Any, kb: Mapping[str, Any]) -> "SessionBroker":
        broker = cls(framework)
        blob = kb.get("session_broker") if isinstance(kb.get("session_broker"), dict) else {}
        for sid, row in (blob.get("sessions") if isinstance(blob.get("sessions"), dict) else {}).items():
            if isinstance(row, dict):
                broker._records[str(sid)] = BrokerSessionRecord.from_dict(row)
        return broker

    def load_from_kb(self, kb: Mapping[str, Any]) -> None:
        blob = kb.get("session_broker") if isinstance(kb.get("session_broker"), dict) else {}
        for sid, row in (blob.get("sessions") if isinstance(blob.get("sessions"), dict) else {}).items():
            if isinstance(row, dict):
                self._records[str(sid)] = BrokerSessionRecord.from_dict(row)

    def sync_to_kb(self, kb: MutableMapping[str, Any], *, state: Any = None) -> None:
        if not isinstance(kb, MutableMapping):
            return
        verified_ids = [sid for sid, row in self._records.items() if row.verified and row.status != "closed"]
        kb["session_broker"] = sanitize_nested({
            "schema_version": SCHEMA_VERSION,
            "sessions": {sid: row.to_dict() for sid, row in sorted(self._records.items())},
            "verified_session_ids": verified_ids,
            "stats": {
                "registered": len(self._records),
                "verified": len(verified_ids),
            },
        })
        if state is not None:
            state.verified_sessions = list(verified_ids)
        from interfaces.command_system.builtin.agent.campaign_world import attach_session_to_world

        attach_session_to_world(kb, self._records.values(), state=state)

    @staticmethod
    def _dedupe_key(host: str, port: int, session_type: str) -> str:
        return f"{host.lower()}:{int(port or 0)}:{session_type.lower()}"

    def _resolve_session(self, session_id: str) -> Tuple[Optional[Any], str]:
        manager = getattr(self.framework, "session_manager", None)
        if manager is None:
            return None, "standard"
        token = str(session_id or "").strip()
        if not token:
            return None, "standard"
        if token in getattr(manager, "browser_sessions", {}):
            return manager.get_browser_session(token), "browser"
        return manager.get_session(token), "standard"

    def register(
        self,
        session_id: str,
        *,
        category: str = "",
        host: str = "",
        port: int = 0,
        session_type: str = "",
        service_id: str = "",
        host_id: str = "",
    ) -> BrokerSessionRecord:
        token = str(session_id or "").strip()
        session_obj, inferred_category = self._resolve_session(token)
        category = category or inferred_category
        if session_obj is not None:
            host = host or str(getattr(session_obj, "host", "") or (session_obj.get("host") if isinstance(session_obj, dict) else "") or "")
            port = port or int(getattr(session_obj, "port", 0) or (session_obj.get("port") if isinstance(session_obj, dict) else 0) or 0)
            session_type = session_type or str(
                getattr(session_obj, "session_type", "")
                or (session_obj.get("session_type") if isinstance(session_obj, dict) else "")
                or ""
            )
        record = self._records.get(token) or BrokerSessionRecord(session_id=token, category=category)
        record.host = host or record.host
        record.port = port or record.port
        record.session_type = session_type or record.session_type
        record.service_id = service_id or record.service_id
        record.host_id = host_id or record.host_id
        record.dedupe_key = self._dedupe_key(record.host, record.port, record.session_type)
        record.last_heartbeat = time.time()
        if record.status == "closed":
            record.status = "registered"
        self._records[token] = record
        return record

    def supports_command_session(self, session_id: str) -> bool:
        session_obj, category = self._resolve_session(session_id)
        if session_obj is None or category == "browser":
            return False
        session_type = str(getattr(session_obj, "session_type", "") or "").lower()
        if session_type and session_type not in COMMAND_SESSION_TYPES:
            return False
        shell_manager = getattr(self.framework, "shell_manager", None)
        if shell_manager is not None and hasattr(shell_manager, "execute_command"):
            return True
        executor = getattr(session_obj, "execute_command", None) or getattr(session_obj, "cmd_exec", None)
        return callable(executor)

    def execute_neutral(
        self,
        session_id: str,
        *,
        evidence_rows: Optional[Sequence[Mapping[str, Any]]] = None,
        structured_details: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[bool, str, str]:
        record = self.register(session_id)
        command = neutral_command_for_session_type(record.session_type)
        record.neutral_command = command

        if self.supports_command_session(session_id):
            shell_manager = getattr(self.framework, "shell_manager", None)
            output = ""
            if shell_manager is not None and hasattr(shell_manager, "execute_command"):
                try:
                    result = shell_manager.execute_command(str(session_id), command, framework=self.framework)
                    if isinstance(result, dict):
                        output = _extract_command_output(result)
                    else:
                        output = str(result or "")
                except Exception as exc:
                    return False, f"neutral_exec_error:{str(exc)[:120]}", command
            else:
                session_obj, _category = self._resolve_session(session_id)
                executor = getattr(session_obj, "execute_command", None) or getattr(session_obj, "cmd_exec", None)
                if callable(executor):
                    try:
                        raw = executor(command)
                        output = _extract_command_output(raw if isinstance(raw, dict) else {"output": raw})
                    except Exception as exc:
                        return False, f"neutral_exec_error:{str(exc)[:120]}", command
            if neutral_output_valid(output, session_type=record.session_type):
                record.neutral_proof_hash = _proof_hash(output)
                return True, "neutral_command", command

        if structured_details:
            for key in ("command_output", "output", "proof", "authenticated_as"):
                text = str(structured_details.get(key) or "")
                if neutral_output_valid(text, session_type=record.session_type):
                    record.neutral_proof_hash = _proof_hash(text)
                    return True, "structured_neutral_proof", command

        if evidence_rows:
            ok, reason = neutral_proof_from_evidence(evidence_rows)
            if ok:
                record.neutral_proof_hash = _proof_hash(reason)
                return True, reason, command

        return False, "neutral_check_failed", command

    def verify_neutral(
        self,
        session_id: str,
        *,
        evidence_rows: Optional[Sequence[Mapping[str, Any]]] = None,
        structured_details: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[bool, str]:
        record = self.register(session_id)
        if record.verified and record.status == "verified":
            return True, record.verification_reason or "already_verified"
        ok, reason, _command = self.execute_neutral(
            session_id,
            evidence_rows=evidence_rows,
            structured_details=structured_details,
        )
        record.last_heartbeat = time.time()
        if ok:
            record.verified = True
            record.verified_at = time.time()
            record.status = "verified"
            record.verification_reason = reason
        else:
            record.status = "unverified"
            record.verification_reason = reason
        self._records[str(session_id)] = record
        return ok, reason

    def heartbeat(self, session_id: str) -> bool:
        record = self.register(session_id)
        if record.status == "closed":
            return False
        if self.supports_command_session(session_id):
            shell_manager = getattr(self.framework, "shell_manager", None)
            if shell_manager is not None:
                try:
                    result = shell_manager.execute_command(
                        str(session_id),
                        "echo ks_heartbeat",
                        framework=self.framework,
                    )
                    output = _extract_command_output(result if isinstance(result, dict) else {"output": result})
                    if "ks_heartbeat" in str(output):
                        record.last_heartbeat = time.time()
                        if record.status == "unverified":
                            record.status = "registered"
                        self._records[str(session_id)] = record
                        return True
                    from interfaces.command_system.builtin.agent.session_resilience import classify_shell_failure

                    failure_kind = classify_shell_failure(output, session_type=record.session_type)
                    if failure_kind == "session_lost":
                        record.status = "lost"
                        record.verified = False
                        self._records[str(session_id)] = record
                        return False
                except Exception:
                    record.status = "unstable"
                    self._records[str(session_id)] = record
                    return False
        record.last_heartbeat = time.time()
        self._records[str(session_id)] = record
        return True

    def close(self, session_id: str) -> bool:
        token = str(session_id or "").strip()
        record = self._records.get(token)
        if record is None:
            return False
        record.status = "closed"
        record.verified = False
        self._records[token] = record
        return True

    def dedupe_verified(self) -> List[str]:
        """Keep the newest verified session per dedupe_key; close duplicates."""
        winners: Dict[str, str] = {}
        for sid, record in sorted(self._records.items(), key=lambda item: item[1].verified_at, reverse=True):
            if not record.verified or record.status != "verified":
                continue
            key = record.dedupe_key or sid
            if key in winners:
                record.status = "closed"
                record.verified = False
                self._records[sid] = record
            else:
                winners[key] = sid
        return list(winners.values())

    def reconcile_detected_sessions(self, state: Any) -> List[str]:
        """Detect new framework sessions, verify neutrally, and update state.new_sessions."""
        manager = getattr(self.framework, "session_manager", None)
        if manager is None:
            return list(getattr(state, "verified_sessions", []) or [])

        before = getattr(state, "sessions_before", {}) or {}
        standard_before = set(before.get("standard") or [])
        browser_before = set(before.get("browser") or [])
        current_standard = set(getattr(manager, "sessions", {}).keys())
        current_browser = set(getattr(manager, "browser_sessions", {}).keys())
        detected = sorted((current_standard - standard_before) | (current_browser - browser_before))

        kb = getattr(state, "knowledge_base", None)
        if not isinstance(kb, dict):
            kb = {}
            state.knowledge_base = kb
        self.load_from_kb(kb)

        host_id = str(getattr(state, "active_host_id", "") or "")
        service_id = str(getattr(state, "active_service_id", "") or "")

        verified: List[str] = list(getattr(state, "verified_sessions", []) or [])
        for sid in detected:
            category = "browser" if sid in current_browser else "standard"
            self.register(sid, category=category, host_id=host_id, service_id=service_id)
            if sid in verified:
                continue
            if category == "browser":
                self._records[sid].verified = True
                self._records[sid].status = "verified"
                self._records[sid].verification_reason = "browser_session"
                verified.append(sid)
                continue
            ok, _reason = self.verify_neutral(sid)
            if ok and sid not in verified:
                verified.append(sid)

        verified = self.dedupe_verified()
        state.verified_sessions = verified
        state.new_sessions = list(verified)
        self.sync_to_kb(kb, state=state)
        return verified

    def gate_session_claim(
        self,
        session_id: str,
        *,
        evidence_rows: Optional[Sequence[Mapping[str, Any]]] = None,
        structured_details: Optional[Mapping[str, Any]] = None,
        state: Any = None,
    ) -> Tuple[bool, str]:
        ok, reason = self.verify_neutral(
            session_id,
            evidence_rows=evidence_rows,
            structured_details=structured_details,
        )
        kb = getattr(state, "knowledge_base", None) if state is not None else None
        if isinstance(kb, dict):
            self.dedupe_verified()
            self.sync_to_kb(kb, state=state)
            verified = list(getattr(state, "verified_sessions", []) or [])
            token = str(session_id or "").strip()
            if ok and token and token not in verified:
                verified.append(token)
                state.verified_sessions = self.dedupe_verified()
                state.new_sessions = list(state.verified_sessions)
        return ok, reason
