#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Automatic actions fired on session lifecycle events."""

from __future__ import annotations

import importlib
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from core.framework.runtime.events import Event, EventType
from core.output_handler import print_error, print_info, print_warning


@dataclass
class SessionTriggerAction:
    type: str
    command: str = ""
    module_path: str = ""
    tag: str = ""
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionTrigger:
    event: str
    actions: List[SessionTriggerAction] = field(default_factory=list)
    session_types: List[str] = field(default_factory=list)
    listeners: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    enabled: bool = True
    name: str = ""


class SessionTriggerManager:
    """Run configured actions when sessions are created, reconnected, or closed."""

    EVENT_MAP = {
        "session.created": EventType.SESSION_CREATED,
        "session.reconnected": EventType.SESSION_RECONNECTED,
        "session.closed": EventType.SESSION_CLOSED,
    }

    def __init__(self, framework):
        self.framework = framework
        self.triggers: List[SessionTrigger] = []
        self._lock = threading.Lock()
        self._running: set = set()
        self._store = None
        self._load_triggers()
        self._subscribe()

    def _get_store(self):
        if self._store is None:
            from core.session_trigger_store import SessionTriggerStore

            workspace = "default"
            if hasattr(self.framework, "get_current_workspace_name"):
                workspace = self.framework.get_current_workspace_name() or "default"
            self._store = SessionTriggerStore(
                getattr(self.framework, "db_manager", None),
                workspace,
            )
        return self._store

    def _load_triggers(self) -> None:
        store = self._get_store()
        db_triggers = store.list_triggers()
        if db_triggers:
            self.triggers = db_triggers
            return
        self._load_from_config()
        if self.triggers:
            try:
                store.replace_all(self.triggers)
            except Exception:
                pass

    def _subscribe(self) -> None:
        bus = getattr(self.framework, "event_bus", None)
        if not bus:
            return
        for event_type in self.EVENT_MAP.values():
            bus.subscribe(event_type, self._handle_event)

    def _load_from_config(self) -> None:
        """One-time migration path for legacy config.toml session_triggers entries."""
        cfg = {}
        try:
            from core.config import Config

            cfg = Config.get_instance().get_config_value("session_triggers") or {}
        except Exception:
            cfg = {}

        raw_triggers = cfg.get("triggers") if isinstance(cfg, dict) else cfg
        if not isinstance(raw_triggers, list):
            return

        for entry in raw_triggers:
            trigger = self._parse_trigger(entry)
            if trigger:
                self.triggers.append(trigger)

    @staticmethod
    def _parse_trigger(entry: Dict[str, Any]) -> Optional[SessionTrigger]:
        if not isinstance(entry, dict):
            return None
        event = str(entry.get("event") or "").strip().lower()
        if not event:
            return None
        actions_raw = entry.get("actions") or []
        actions: List[SessionTriggerAction] = []
        for action in actions_raw:
            if not isinstance(action, dict):
                continue
            actions.append(
                SessionTriggerAction(
                    type=str(action.get("type") or "command").strip().lower(),
                    command=str(action.get("command") or "").strip(),
                    module_path=str(action.get("module") or action.get("module_path") or "").strip(),
                    tag=str(action.get("tag") or "").strip(),
                    options=dict(action.get("options") or {}),
                )
            )
        if not actions:
            return None
        return SessionTrigger(
            event=event,
            actions=actions,
            session_types=[str(x).lower() for x in (entry.get("session_types") or []) if str(x).strip()],
            listeners=[str(x) for x in (entry.get("listeners") or entry.get("listener") or []) if str(x).strip()],
            platforms=[str(x).lower() for x in (entry.get("platforms") or []) if str(x).strip()],
            enabled=bool(entry.get("enabled", True)),
            name=str(entry.get("name") or "").strip(),
        )

    def add_trigger(self, trigger: SessionTrigger) -> None:
        with self._lock:
            row_id = self._get_store().add_trigger(trigger)
            if row_id is not None:
                self.triggers = self._get_store().list_triggers()
            else:
                self.triggers.append(trigger)

    def remove_trigger(self, index: int) -> bool:
        with self._lock:
            if self._get_store().remove_by_index(index):
                self.triggers = self._get_store().list_triggers()
                return True
            if 0 <= index < len(self.triggers):
                self.triggers.pop(index)
                return True
        return False

    def set_all_enabled(self, enabled: bool) -> int:
        with self._lock:
            count = self._get_store().set_all_enabled(enabled)
            if count:
                self.triggers = self._get_store().list_triggers()
                return count
            for trigger in self.triggers:
                trigger.enabled = enabled
            return len(self.triggers)

    def reload_for_workspace(self, workspace_name: str) -> None:
        with self._lock:
            self._store = None
            self.triggers = []
            self._load_triggers()

    def reload_triggers(self) -> None:
        workspace = "default"
        if hasattr(self.framework, "get_current_workspace_name"):
            workspace = self.framework.get_current_workspace_name() or "default"
        self.reload_for_workspace(workspace)

    def list_triggers(self) -> List[SessionTrigger]:
        with self._lock:
            return list(self.triggers)

    def _handle_event(self, event: Event) -> None:
        event_key = event.event_type.value
        session_id = str((event.data or {}).get("session_id") or "")
        if not session_id:
            return
        session = self.framework.session_manager.get_session(session_id)
        if not session:
            return

        with self._lock:
            candidates = [
                t for t in self.triggers
                if t.enabled and t.event == event_key and self._matches(t, session)
            ]

        for trigger in candidates:
            key = (event_key, session_id, id(trigger))
            if key in self._running:
                continue
            self._running.add(key)
            threading.Thread(
                target=self._run_trigger,
                args=(trigger, session_id, session),
                kwargs={"key": key},
                daemon=True,
            ).start()

    @staticmethod
    def _matches(trigger: SessionTrigger, session) -> bool:
        data = session.data or {}
        if trigger.session_types:
            st = str(session.session_type or "").lower()
            if st not in [x.lower() for x in trigger.session_types]:
                return False
        if trigger.listeners:
            listener_mod = str(data.get("listener_module") or data.get("listener") or "")
            if not any(listener_mod.endswith(x) or x in listener_mod for x in trigger.listeners):
                return False
        if trigger.platforms:
            platform = str(data.get("platform") or data.get("os") or "").lower()
            if platform and platform not in [x.lower() for x in trigger.platforms]:
                return False
        return True

    def _run_trigger(self, trigger: SessionTrigger, session_id: str, session, *, key) -> None:
        try:
            label = trigger.name or trigger.event
            print_info(f"Session trigger '{label}' on {session_id[:8]}")
            for action in trigger.actions:
                self._execute_action(action, session_id, session)
        except Exception as exc:
            print_error(f"Session trigger failed: {exc}")
        finally:
            self._running.discard(key)

    def _execute_action(self, action: SessionTriggerAction, session_id: str, session) -> None:
        if action.type == "tag":
            if action.tag:
                data = session.data or {}
                tags = list(data.get("tags") or [])
                if action.tag not in tags:
                    tags.append(action.tag)
                    self.framework.session_manager.update_session_data(session_id, {"tags": tags})
            return

        if action.type == "command":
            if not action.command:
                return
            from core.session_job_manager import SessionJobManager

            mgr = SessionJobManager(self.framework)
            mgr.run_command_on_sessions([session_id], action.command, wait=True)
            return

        if action.type == "module":
            path = action.module_path
            if not path:
                return
            self._run_module_on_session(path, session_id, action.options)
            return

        print_warning(f"Unknown session trigger action type: {action.type}")

    def _run_module_on_session(self, module_path: str, session_id: str, options: Dict[str, Any]) -> None:
        loader = getattr(self.framework, "module_loader", None)
        if not loader:
            return
        try:
            module = loader.load_module(module_path)
        except Exception as exc:
            print_error(f"Trigger module load failed ({module_path}): {exc}")
            return
        if module is None:
            print_error(f"Trigger module not found: {module_path}")
            return
        module.framework = self.framework
        module.session_id = session_id
        for key, value in (options or {}).items():
            try:
                module.set_option(key, value)
            except Exception:
                pass
        try:
            if hasattr(module, "run") and callable(module.run):
                module.run()
            elif hasattr(module, "execute") and callable(module.execute):
                module.execute()
        except Exception as exc:
            print_error(f"Trigger module execution failed ({module_path}): {exc}")
