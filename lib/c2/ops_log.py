#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""C2 operations log — encrypted DB audit for polling implants.

Sensitive task data (commands, output, implant id, client IP) lives in the
workspace database via ``C2Task`` encrypted columns. Plaintext JSONL is
disabled by default and only used for unit tests / explicit opt-in.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_STATUSES = frozenset({"queued", "sent", "completed", "failed", "killed"})

_lock = threading.RLock()
_memory: List[Dict[str, Any]] = []
_MEMORY_CAP = 5000


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat() + "Z"


def _parse_since(value: Optional[str]) -> Optional[datetime]:
    """Parse ``1h``, ``30m``, ``2d``, or ISO timestamp into naive UTC datetime."""
    if not value:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    now = _utc_now()
    if text.endswith("h") and text[:-1].replace(".", "", 1).isdigit():
        return datetime.fromtimestamp(now.timestamp() - float(text[:-1]) * 3600)
    if text.endswith("m") and text[:-1].replace(".", "", 1).isdigit():
        return datetime.fromtimestamp(now.timestamp() - float(text[:-1]) * 60)
    if text.endswith("d") and text[:-1].replace(".", "", 1).isdigit():
        return datetime.fromtimestamp(now.timestamp() - float(text[:-1]) * 86400)
    if text.endswith("s") and text[:-1].replace(".", "", 1).isdigit():
        return datetime.fromtimestamp(now.timestamp() - float(text[:-1]))
    try:
        normalized = text.replace("z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError as exc:
        raise ValueError(f"invalid --since value: {value!r}") from exc


def default_jsonl_path(workspace: Optional[str] = None) -> Path:
    base = Path(os.path.expanduser("~/.kittysploit/c2_ops"))
    if workspace:
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in str(workspace))
        return base / f"{safe or 'default'}.jsonl"
    return base / "default.jsonl"


def _record_dict(
    *,
    task_id: str,
    session_id: str = "",
    implant_id: str = "",
    operator: str = "console",
    command: str = "",
    status: str = "queued",
    output_preview: str = "",
    client_ip: str = "",
    listener_type: str = "reverse_http_polling",
    created_at: Optional[datetime] = None,
    sent_at: Optional[datetime] = None,
    completed_at: Optional[datetime] = None,
    workspace: str = "default",
) -> Dict[str, Any]:
    created = created_at or _utc_now()
    output = str(output_preview or "")
    return {
        "task_id": task_id,
        "session_id": str(session_id or ""),
        "implant_id": str(implant_id or ""),
        "operator": str(operator or "console"),
        "command": str(command or ""),
        "status": status if status in _STATUSES else "queued",
        "output_preview": output,
        "output": output,
        "client_ip": str(client_ip or ""),
        "listener_type": str(listener_type or "reverse_http_polling"),
        "workspace": str(workspace or "default"),
        "created_at": _iso(created),
        "sent_at": _iso(sent_at),
        "completed_at": _iso(completed_at),
    }


class C2OpsLog:
    """Persist C2 task lifecycle events (queued → sent → completed) in encrypted DB."""

    def __init__(
        self,
        framework: Any = None,
        *,
        workspace: Optional[str] = None,
        jsonl_path: Optional[Path] = None,
        enable_jsonl: Optional[bool] = None,
    ):
        self.framework = framework
        self.workspace = workspace or self._detect_workspace() or "default"
        self.jsonl_path = Path(jsonl_path) if jsonl_path else default_jsonl_path(self.workspace)
        # Plaintext JSONL is opt-in only (tests). Production uses encrypted DB.
        if enable_jsonl is None:
            enable_jsonl = jsonl_path is not None and framework is None
        self.enable_jsonl = bool(enable_jsonl)
        self._jsonl_migrated = False

    def _detect_workspace(self) -> Optional[str]:
        try:
            wm = getattr(self.framework, "workspace_manager", None)
            if not wm:
                return None
            ws = wm.get_current_workspace()
            return getattr(ws, "name", None) if ws else None
        except Exception:
            return None

    def _workspace_id(self) -> Optional[int]:
        try:
            wm = getattr(self.framework, "workspace_manager", None)
            if not wm:
                return None
            ws = wm.get_current_workspace()
            return getattr(ws, "id", None) if ws else None
        except Exception:
            return None

    def storage_label(self) -> str:
        """Human-readable storage location for CLI banners."""
        db = getattr(self.framework, "db_manager", None) if self.framework else None
        if db:
            return f"workspace DB ({self.workspace}) — table c2_tasks"
        if self.enable_jsonl:
            return str(self.jsonl_path)
        return "memory (no framework DB)"

    def _append_memory(self, record: Dict[str, Any]) -> None:
        with _lock:
            _memory.append(dict(record))
            if len(_memory) > _MEMORY_CAP:
                del _memory[: len(_memory) - _MEMORY_CAP]

    def _append_jsonl(self, record: Dict[str, Any]) -> None:
        if not self.enable_jsonl:
            return
        try:
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            with _lock:
                with open(self.jsonl_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _upsert_db(self, record: Dict[str, Any]) -> None:
        db = getattr(self.framework, "db_manager", None) if self.framework else None
        if not db:
            return
        try:
            from core.models.models import C2Task

            ws_name = self.workspace or "default"
            with db.get_db_session(ws_name) as session:
                row = (
                    session.query(C2Task)
                    .filter(C2Task.task_id == record["task_id"])
                    .one_or_none()
                )
                if row is None:
                    row = C2Task(
                        task_id=record["task_id"],
                        workspace_id=self._workspace_id(),
                        session_id=record.get("session_id") or None,
                        implant_id=record.get("implant_id") or None,
                        operator=record.get("operator") or "console",
                        command=record.get("command") or "",
                        status=record.get("status") or "queued",
                        output_preview=record.get("output_preview") or "",
                        client_ip=record.get("client_ip") or None,
                        listener_type=record.get("listener_type") or "reverse_http_polling",
                    )
                    session.add(row)
                else:
                    row.status = record.get("status") or row.status
                    if record.get("command") is not None:
                        row.command = record.get("command")
                    if record.get("output_preview") is not None:
                        row.output_preview = record.get("output_preview")
                    row.operator = record.get("operator") or row.operator
                    if record.get("implant_id"):
                        row.implant_id = record.get("implant_id")
                    if record.get("client_ip"):
                        row.client_ip = record.get("client_ip")

                def _parse_iso(val: Optional[str]) -> Optional[datetime]:
                    if not val:
                        return None
                    try:
                        return datetime.fromisoformat(str(val).replace("Z", ""))
                    except ValueError:
                        return None

                if record.get("sent_at"):
                    row.sent_at = _parse_iso(record["sent_at"])
                if record.get("completed_at"):
                    row.completed_at = _parse_iso(record["completed_at"])
                session.commit()
        except Exception:
            # Never break the C2 path for logging failures
            pass

    def log_queued(
        self,
        *,
        session_id: str,
        command: str,
        implant_id: str = "",
        operator: str = "console",
        client_ip: str = "",
        listener_type: str = "reverse_http_polling",
        task_id: Optional[str] = None,
    ) -> str:
        tid = task_id or uuid.uuid4().hex[:16]
        record = _record_dict(
            task_id=tid,
            session_id=session_id,
            implant_id=implant_id,
            operator=operator,
            command=command,
            status="queued",
            client_ip=client_ip,
            listener_type=listener_type,
            workspace=self.workspace,
        )
        self._append_memory(record)
        self._append_jsonl(record)
        self._upsert_db(record)
        return tid

    def mark_sent(self, task_id: str) -> bool:
        return self._update_status(task_id, "sent", sent_at=_utc_now())

    def mark_completed(self, task_id: str, output: str = "") -> bool:
        return self._update_status(
            task_id,
            "completed",
            completed_at=_utc_now(),
            output_preview=str(output or ""),
        )

    def mark_failed(self, task_id: str, output: str = "") -> bool:
        return self._update_status(
            task_id,
            "failed",
            completed_at=_utc_now(),
            output_preview=str(output or ""),
        )

    def mark_killed(self, task_id: str) -> bool:
        return self._update_status(task_id, "killed", completed_at=_utc_now())

    def kill_pending_for_session(self, session_id: str) -> int:
        """Mark all queued/sent tasks for a session as killed. Returns count."""
        if not session_id:
            return 0
        pending = self.list_pending_for_session(str(session_id), include_sent=True, limit=500)
        n = 0
        for rec in pending:
            tid = str(rec.get("task_id") or "")
            if not tid:
                continue
            if self.mark_killed(tid):
                n += 1
        return n

    def _update_status(
        self,
        task_id: str,
        status: str,
        *,
        sent_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
        output_preview: Optional[str] = None,
    ) -> bool:
        if not task_id:
            return False
        updated: Optional[Dict[str, Any]] = None
        with _lock:
            for rec in reversed(_memory):
                if rec.get("task_id") == task_id:
                    rec["status"] = status
                    if sent_at is not None:
                        rec["sent_at"] = _iso(sent_at)
                    if completed_at is not None:
                        rec["completed_at"] = _iso(completed_at)
                    if output_preview is not None:
                        rec["output_preview"] = output_preview
                        rec["output"] = output_preview
                    updated = dict(rec)
                    break
        if updated is None:
            updated = _record_dict(
                task_id=task_id,
                status=status,
                sent_at=sent_at,
                completed_at=completed_at,
                output_preview=output_preview or "",
                workspace=self.workspace,
            )
        self._append_jsonl({"event": "status", **updated})
        self._upsert_db(updated)
        return True

    def list_tasks(
        self,
        *,
        session_id: Optional[str] = None,
        implant_id: Optional[str] = None,
        status: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        since_dt = _parse_since(since)
        rows = self._load_all()
        out: List[Dict[str, Any]] = []
        for rec in rows:
            if session_id and str(rec.get("session_id") or "") != str(session_id):
                # also allow prefix match (short ids shown in UI)
                sid = str(rec.get("session_id") or "")
                if not (sid.startswith(str(session_id)) or str(session_id).startswith(sid[:8])):
                    continue
            if implant_id and str(rec.get("implant_id") or "") != str(implant_id):
                iid = str(rec.get("implant_id") or "")
                if not (iid.startswith(str(implant_id)) or str(implant_id).startswith(iid[:8])):
                    continue
            if status and str(rec.get("status") or "") != str(status):
                continue
            if since_dt:
                created = rec.get("created_at") or ""
                try:
                    cdt = datetime.fromisoformat(str(created).replace("Z", ""))
                except ValueError:
                    continue
                if cdt < since_dt:
                    continue
            out.append(rec)
        out.sort(key=lambda r: str(r.get("created_at") or ""), reverse=True)
        return out[: max(1, int(limit or 100))]

    def list_pending_for_session(
        self,
        session_id: str,
        *,
        include_sent: bool = True,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        """Return queued (and optionally in-flight ``sent``) tasks for a session."""
        if not session_id:
            return []
        statuses = ["queued"]
        if include_sent:
            statuses.append("sent")

        db_rows: List[Dict[str, Any]] = []
        db = getattr(self.framework, "db_manager", None) if self.framework else None
        if db:
            try:
                from core.models.models import C2Task

                ws_name = self.workspace or "default"
                with db.get_db_session(ws_name) as session:
                    q = (
                        session.query(C2Task)
                        .filter(
                            C2Task.session_id == str(session_id),
                            C2Task.status.in_(statuses),
                        )
                        .order_by(C2Task.created_at.asc())
                        .limit(max(1, int(limit or 200)))
                    )
                    for row in q.all():
                        db_rows.append(row.to_dict())
            except Exception:
                db_rows = []

        if db_rows:
            return db_rows

        rows = self.list_tasks(session_id=str(session_id), limit=max(1, int(limit or 200) * 5))
        pending = [r for r in rows if str(r.get("status") or "") in set(statuses)]
        pending.sort(key=lambda r: str(r.get("created_at") or ""))
        return pending[: max(1, int(limit or 200))]

    def timeline(self, *, limit: int = 50, since: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.list_tasks(limit=limit, since=since)

    def _migrate_jsonl_into_db(self) -> None:
        """One-shot import of legacy plaintext JSONL into encrypted DB, then archive file."""
        if self._jsonl_migrated:
            return
        self._jsonl_migrated = True
        db = getattr(self.framework, "db_manager", None) if self.framework else None
        if not db or not self.jsonl_path.is_file():
            return
        try:
            imported = 0
            with open(self.jsonl_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    tid = rec.get("task_id")
                    if not tid:
                        continue
                    payload = {
                        "task_id": str(tid),
                        "session_id": str(rec.get("session_id") or ""),
                        "implant_id": str(rec.get("implant_id") or ""),
                        "operator": str(rec.get("operator") or "console"),
                        "command": str(rec.get("command") or ""),
                        "status": str(rec.get("status") or "queued"),
                        "output_preview": str(
                            rec.get("output_preview") or rec.get("output") or ""
                        ),
                        "client_ip": str(rec.get("client_ip") or ""),
                        "listener_type": str(
                            rec.get("listener_type") or "reverse_http_polling"
                        ),
                        "sent_at": rec.get("sent_at"),
                        "completed_at": rec.get("completed_at"),
                    }
                    self._upsert_db(payload)
                    imported += 1
            if imported:
                archived = self.jsonl_path.with_suffix(self.jsonl_path.suffix + ".migrated")
                try:
                    self.jsonl_path.replace(archived)
                except Exception:
                    pass
        except Exception:
            pass

    def _load_all(self) -> List[Dict[str, Any]]:
        """Load tasks: encrypted DB is authoritative; memory overlays; JSONL only if enabled."""
        by_id: Dict[str, Dict[str, Any]] = {}

        db = getattr(self.framework, "db_manager", None) if self.framework else None
        if db:
            self._migrate_jsonl_into_db()
            try:
                from core.models.models import C2Task

                with db.get_db_session(self.workspace or "default") as session:
                    for row in session.query(C2Task).all():
                        d = row.to_dict()
                        tid = d.get("task_id")
                        if not tid:
                            continue
                        by_id[tid] = d
            except Exception:
                pass

        if self.enable_jsonl:
            try:
                if self.jsonl_path.is_file():
                    with open(self.jsonl_path, "r", encoding="utf-8") as fh:
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                rec = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            tid = rec.get("task_id")
                            if not tid:
                                continue
                            prev = by_id.get(tid, {})
                            merged = dict(prev)
                            merged.update({k: v for k, v in rec.items() if k != "event" and v is not None})
                            by_id[tid] = merged
            except Exception:
                pass

        with _lock:
            for rec in _memory:
                tid = rec.get("task_id")
                if not tid:
                    continue
                prev = by_id.get(tid, {})
                merged = dict(prev)
                merged.update(rec)
                by_id[tid] = merged

        return list(by_id.values())


def get_ops_log(framework: Any = None, **kwargs: Any) -> C2OpsLog:
    """Convenience factory; reuses framework-attached instance when present."""
    if framework is not None:
        existing = getattr(framework, "c2_ops_log", None)
        if isinstance(existing, C2OpsLog):
            return existing
        log = C2OpsLog(framework, **kwargs)
        try:
            framework.c2_ops_log = log
        except Exception:
            pass
        return log
    return C2OpsLog(**kwargs)


def clear_memory_for_tests() -> None:
    """Reset in-memory buffer (unit tests only)."""
    with _lock:
        _memory.clear()
