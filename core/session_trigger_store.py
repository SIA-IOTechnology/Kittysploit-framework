#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Persist session lifecycle triggers in the workspace database."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from core.models.models import SessionTriggerRule
from core.session_triggers import SessionTrigger, SessionTriggerAction


def _serialize_actions(actions: List[SessionTriggerAction]) -> str:
    payload = []
    for action in actions:
        payload.append(
            {
                "type": action.type,
                "command": action.command,
                "module_path": action.module_path,
                "tag": action.tag,
                "options": dict(action.options or {}),
            }
        )
    return json.dumps(payload, separators=(",", ":"))


def _deserialize_actions(raw: str) -> List[SessionTriggerAction]:
    try:
        data = json.loads(raw or "[]")
    except Exception:
        return []
    actions: List[SessionTriggerAction] = []
    if not isinstance(data, list):
        return actions
    for entry in data:
        if not isinstance(entry, dict):
            continue
        actions.append(
            SessionTriggerAction(
                type=str(entry.get("type") or "command").strip().lower(),
                command=str(entry.get("command") or "").strip(),
                module_path=str(entry.get("module") or entry.get("module_path") or "").strip(),
                tag=str(entry.get("tag") or "").strip(),
                options=dict(entry.get("options") or {}),
            )
        )
    return actions


def _split_csv(raw: str) -> List[str]:
    return [part.strip() for part in str(raw or "").split(",") if part.strip()]


class SessionTriggerStore:
    def __init__(self, db_manager, workspace_name: str = "default"):
        self.db_manager = db_manager
        self.workspace_name = workspace_name or "default"

    def _workspace_id(self) -> Optional[int]:
        if not self.db_manager:
            return None
        try:
            session = self.db_manager.get_session(self.workspace_name)
            if not session:
                return None
            from core.models.models import Workspace

            row = session.query(Workspace).filter_by(name=self.workspace_name).first()
            return row.id if row else None
        except Exception:
            return None

    def _db_session(self):
        if not self.db_manager:
            return None
        return self.db_manager.get_session(self.workspace_name)

    @staticmethod
    def row_to_trigger(row: SessionTriggerRule) -> SessionTrigger:
        return SessionTrigger(
            event=str(row.event or "").strip().lower(),
            actions=_deserialize_actions(row.actions or "[]"),
            session_types=_split_csv(row.session_types or ""),
            listeners=_split_csv(row.listeners or ""),
            platforms=_split_csv(row.platforms or ""),
            enabled=bool(row.enabled),
            name=str(row.name or "").strip(),
        )

    def list_triggers(self) -> List[SessionTrigger]:
        db = self._db_session()
        workspace_id = self._workspace_id()
        if not db or workspace_id is None:
            return []
        rows = (
            db.query(SessionTriggerRule)
            .filter_by(workspace_id=workspace_id)
            .order_by(SessionTriggerRule.id.asc())
            .all()
        )
        return [self.row_to_trigger(row) for row in rows]

    def add_trigger(self, trigger: SessionTrigger) -> Optional[int]:
        db = self._db_session()
        workspace_id = self._workspace_id()
        if not db or workspace_id is None:
            return None
        row = SessionTriggerRule(
            workspace_id=workspace_id,
            name=trigger.name or trigger.event,
            event=trigger.event,
            enabled=bool(trigger.enabled),
            session_types=",".join(trigger.session_types or []),
            listeners=",".join(trigger.listeners or []),
            platforms=",".join(trigger.platforms or []),
            actions=_serialize_actions(trigger.actions or []),
        )
        db.add(row)
        db.commit()
        return row.id

    def remove_by_index(self, index: int) -> bool:
        db = self._db_session()
        workspace_id = self._workspace_id()
        if not db or workspace_id is None:
            return False
        rows = (
            db.query(SessionTriggerRule)
            .filter_by(workspace_id=workspace_id)
            .order_by(SessionTriggerRule.id.asc())
            .all()
        )
        if index < 0 or index >= len(rows):
            return False
        db.delete(rows[index])
        db.commit()
        return True

    def set_all_enabled(self, enabled: bool) -> int:
        db = self._db_session()
        workspace_id = self._workspace_id()
        if not db or workspace_id is None:
            return 0
        rows = db.query(SessionTriggerRule).filter_by(workspace_id=workspace_id).all()
        for row in rows:
            row.enabled = bool(enabled)
        if rows:
            db.commit()
        return len(rows)

    def replace_all(self, triggers: List[SessionTrigger]) -> None:
        db = self._db_session()
        workspace_id = self._workspace_id()
        if not db or workspace_id is None:
            return
        db.query(SessionTriggerRule).filter_by(workspace_id=workspace_id).delete()
        for trigger in triggers:
            db.add(
                SessionTriggerRule(
                    workspace_id=workspace_id,
                    name=trigger.name or trigger.event,
                    event=trigger.event,
                    enabled=bool(trigger.enabled),
                    session_types=",".join(trigger.session_types or []),
                    listeners=",".join(trigger.listeners or []),
                    platforms=",".join(trigger.platforms or []),
                    actions=_serialize_actions(trigger.actions or []),
                )
            )
        db.commit()
