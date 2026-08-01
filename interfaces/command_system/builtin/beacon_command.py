#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tune HTTP polling beacon profile per session (sleep, kill date, hours)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_error, print_info, print_success, print_warning
from lib.c2.beacon_profile import BeaconProfile


class BeaconCommand(BaseCommand):
    """Operator control for polling beacon profiles."""

    @property
    def name(self) -> str:
        return "beacon"

    @property
    def description(self) -> str:
        return "Set HTTP polling beacon options (sleep, kill_date, working_hours)"

    @property
    def usage(self) -> str:
        return "beacon set <session_id> <key> <value> | beacon show <session_id>"

    @property
    def help_text(self) -> str:
        return """
Manage per-session beacon profiles on reverse_http_polling listeners.

Subcommands:
    show <session_id>              Show effective profile overrides
    set  <session_id> <key> <val>  Overlay a profile field
    help                           This help

Keys:
    sleep / poll_interval     Base poll interval (seconds)
    jitter / jitter_percent   Jitter percent (0-100)
    kill_date                 ISO date YYYY-MM-DD (empty clears)
    working_hours             HH:MM-HH:MM (empty = always)
    timezone                  e.g. UTC or Europe/Paris
    sleep_outside_hours       Seconds to sleep outside the window
    user_agent                UA hint echoed to the implant

Examples:
    beacon show abc123
    beacon set abc123 sleep 60
    beacon set abc123 kill_date 2026-09-01
    beacon set abc123 working_hours 09:00-18:00
    beacon set abc123 kill_date ""
        """

    def get_subcommands(self) -> List[str]:
        return ["set", "show", "help"]

    def execute(self, args: List[str], **kwargs) -> bool:
        if not args or args[0] in ("-h", "--help", "help"):
            self.show_help()
            return True

        sub = args[0].lower()
        if sub == "show":
            return self._show(args[1:])
        if sub == "set":
            return self._set(args[1:])
        print_error(f"Unknown subcommand: {sub}")
        print_info("Use: beacon show|set|help")
        return False

    def _resolve_session(self, session_id: str):
        sm = getattr(self.framework, "session_manager", None)
        if not sm:
            print_error("Session manager unavailable")
            return None
        sess = sm.get_session(session_id)
        if not sess:
            for s in sm.get_sessions() or []:
                sid = getattr(s, "id", None) or getattr(s, "session_id", None)
                if sid and str(sid).startswith(session_id):
                    return s
            print_error(f"Session not found: {session_id}")
            return None
        return sess

    def _session_data(self, sess) -> Dict[str, Any]:
        data = getattr(sess, "data", None) or {}
        return data if isinstance(data, dict) else {}

    def _listener_for(self, sess) -> Optional[Any]:
        data = self._session_data(sess)
        listener_id = data.get("listener_id")
        active = getattr(self.framework, "active_listeners", None) or {}
        if listener_id and listener_id in active:
            return active[listener_id]
        sid = getattr(sess, "id", None) or getattr(sess, "session_id", None)
        implant = str(data.get("implant_id") or data.get("client_id") or "").strip()
        for listener in active.values():
            if not hasattr(listener, "_profile_for"):
                continue
            session_map = getattr(listener, "_session_to_client_id", {}) or {}
            client_map = getattr(listener, "_client_id_to_session", {}) or {}
            if sid and sid in session_map:
                return listener
            if implant and (client_map.get(implant) == sid or implant in client_map):
                return listener
            if hasattr(listener, "set_session_profile") and sid in getattr(
                listener, "_pending_commands", {}
            ):
                return listener
        return None

    def _ensure_listener(self, sess) -> Optional[Any]:
        listener = self._listener_for(sess)
        if listener:
            return listener
        try:
            from lib.c2.durable_listeners import ensure_listener_for_session

            return ensure_listener_for_session(self.framework, sess)
        except Exception:
            return None

    def _offline_profile(self, sess) -> Tuple[BeaconProfile, Dict[str, Any], str]:
        """Build a profile from saved listener_bind + session overrides (no live listener)."""
        data = self._session_data(sess)
        overrides = dict(data.get("beacon_overrides") or {})
        bind = data.get("listener_bind") if isinstance(data.get("listener_bind"), dict) else {}
        opts = dict(bind.get("options") or {}) if bind else {}
        profile_keys = {
            "poll_interval",
            "jitter_percent",
            "kill_date",
            "working_hours",
            "timezone",
            "sleep_outside_hours",
            "user_agent",
        }
        base_kwargs = {k: opts[k] for k in profile_keys if k in opts and opts[k] not in (None, "")}
        if "kill_date" in base_kwargs and not str(base_kwargs["kill_date"]).strip():
            base_kwargs["kill_date"] = None
        if "working_hours" in base_kwargs and not str(base_kwargs["working_hours"]).strip():
            base_kwargs["working_hours"] = None
        try:
            base = BeaconProfile(**base_kwargs) if base_kwargs else BeaconProfile()
        except Exception:
            base = BeaconProfile()
        profile = base.with_overrides(**overrides) if overrides else base
        source = "saved listener_bind" if opts else "defaults (no listener_bind yet)"
        return profile, overrides, source

    def _print_profile(
        self, sid: str, profile: BeaconProfile, overrides: Dict[str, Any], *, note: str = ""
    ) -> None:
        print_info(f"Beacon profile for session {sid}")
        if note:
            print_info(note)
        print(f"  poll_interval        = {profile.poll_interval}")
        print(f"  jitter_percent       = {profile.jitter_percent}")
        print(f"  kill_date            = {profile.kill_date or '(none)'}")
        print(f"  working_hours        = {profile.working_hours or '(always)'}")
        print(f"  timezone             = {profile.timezone}")
        print(f"  sleep_outside_hours  = {profile.sleep_outside_hours}")
        print(f"  user_agent           = {profile.user_agent}")
        if overrides:
            print_info(f"Session overrides: {overrides}")
        else:
            print_info("No per-session overrides (using listener defaults)")

    def _persist_overrides(self, sid: str, overrides: Dict[str, Any]) -> None:
        sm = getattr(self.framework, "session_manager", None)
        if not sm:
            return
        try:
            sm.update_session_data(str(sid), {"beacon_overrides": dict(overrides)})
        except Exception:
            pass

    def _show(self, args: List[str]) -> bool:
        if not args:
            print_error("Usage: beacon show <session_id>")
            return False
        sess = self._resolve_session(args[0])
        if not sess:
            return False
        sid = str(getattr(sess, "id", None) or getattr(sess, "session_id", None))
        listener = self._ensure_listener(sess)
        if listener and hasattr(listener, "_profile_for"):
            data = self._session_data(sess)
            stored = data.get("beacon_overrides") or {}
            if stored and hasattr(listener, "set_session_profile"):
                try:
                    listener.set_session_profile(sid, **dict(stored))
                except Exception:
                    pass
            profile = listener._profile_for(sid)
            overrides = getattr(listener, "_session_profiles", {}).get(sid) or dict(stored)
            self._print_profile(sid, profile, overrides)
            return True

        profile, overrides, source = self._offline_profile(sess)
        self._print_profile(
            sid,
            profile,
            overrides,
            note=(
                f"Listener not running — showing {source}. "
                "Start reverse_http_polling (or wait for auto-start) for live control."
            ),
        )
        return True

    def _set(self, args: List[str]) -> bool:
        if len(args) < 3:
            print_error("Usage: beacon set <session_id> <key> <value>")
            return False
        sess = self._resolve_session(args[0])
        if not sess:
            return False
        sid = str(getattr(sess, "id", None) or getattr(sess, "session_id", None))
        key = args[1].lower().strip()
        value = " ".join(args[2:]).strip()
        if value in ('""', "''"):
            value = ""

        key_map = {
            "sleep": "poll_interval",
            "poll_interval": "poll_interval",
            "jitter": "jitter_percent",
            "jitter_percent": "jitter_percent",
            "kill_date": "kill_date",
            "working_hours": "working_hours",
            "timezone": "timezone",
            "sleep_outside_hours": "sleep_outside_hours",
            "user_agent": "user_agent",
        }
        field = key_map.get(key)
        if not field:
            print_error(f"Unknown key: {key}")
            print_info(
                "Keys: sleep, jitter, kill_date, working_hours, timezone, "
                "sleep_outside_hours, user_agent"
            )
            return False

        if field in ("poll_interval", "jitter_percent", "sleep_outside_hours"):
            if value == "":
                print_warning("Numeric fields cannot be cleared to empty; set an explicit number")
                return False
            try:
                coerced: Any = float(value) if "." in value else int(value)
            except ValueError:
                print_error(f"Invalid number: {value}")
                return False
        else:
            coerced = value or None

        data = self._session_data(sess)
        overrides = dict(data.get("beacon_overrides") or {})
        if coerced is None:
            overrides.pop(field, None)
        else:
            overrides[field] = coerced
        self._persist_overrides(sid, overrides)

        listener = self._ensure_listener(sess)
        if listener and hasattr(listener, "set_session_profile"):
            listener.set_session_profile(sid, **{field: coerced})
            print_success(f"beacon {sid}: {field}={coerced!r}")
            return True

        print_success(f"beacon {sid}: {field}={coerced!r} (saved; will apply when listener starts)")
        print_info(
            "No live HTTP polling listener yet — "
            "use listeners/multi/reverse_http_polling and run, "
            "or ensure durable_listeners.json has a bind for auto-start."
        )
        return True
