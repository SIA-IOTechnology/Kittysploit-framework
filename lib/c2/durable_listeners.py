#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Persist and auto-restart durable C2 listeners across framework restarts."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

_DURABLE_MODULE = "listeners/multi/reverse_http_polling"

# Options restored onto reverse_http_polling
_PERSIST_KEYS = (
    "lhost",
    "lport",
    "url_prefix",
    "poll_interval",
    "jitter_percent",
    "kill_date",
    "working_hours",
    "timezone",
    "sleep_outside_hours",
    "user_agent",
    "host_header",
    "payload_comms_host",
    "cover_traffic",
    "response_pad_min",
    "stale_timeout",
    "alert_on_stale",
    "implant_public_key",
    "allow_chained",
    "chain_token",
    "callback_notify_url",
    "ssl_cert",
    "ssl_key",
)


def _opt_value(module: Any, name: str, default: Any = None) -> Any:
    attr = getattr(module, name, default)
    if attr is None:
        return default
    if hasattr(attr, "value"):
        return getattr(attr, "value")
    return attr


def bind_key(options: Dict[str, Any], *, module: str = _DURABLE_MODULE) -> str:
    host = str(options.get("lhost") or "0.0.0.0")
    try:
        port = int(options.get("lport") or 8088)
    except (TypeError, ValueError):
        port = 8088
    prefix = "/" + str(options.get("url_prefix") or "/c2").strip("/")
    return f"{module}|{host}|{port}|{prefix}"


def snapshot_from_module(module: Any) -> Dict[str, Any]:
    """Build a durable listener record from a running listener module."""
    options: Dict[str, Any] = {}
    for key in _PERSIST_KEYS:
        if not hasattr(module, key):
            continue
        val = _opt_value(module, key, None)
        if val is None:
            continue
        options[key] = val
    module_path = "listeners/multi/reverse_http_polling"
    try:
        name = str(getattr(module, "name", "") or "")
        if "poll" in name.lower().replace(" ", "_"):
            module_path = _DURABLE_MODULE
        info = getattr(module, "__info__", None) or {}
        # Prefer explicit path if module loader stamped one
        stamped = getattr(module, "module_path", None) or info.get("path")
        if stamped and "listener" in str(stamped).lower():
            module_path = str(stamped).replace("\\", "/")
            if module_path.startswith("modules/"):
                module_path = module_path[len("modules/") :]
    except Exception:
        pass
    return {
        "module": module_path if "reverse_http_polling" in module_path else _DURABLE_MODULE,
        "options": options,
        "updated_at": time.time(),
        "key": bind_key(options, module=_DURABLE_MODULE),
    }


def registry_path(workspace: str = "default") -> Path:
    root = Path.home() / ".kittysploit" / "workspaces" / str(workspace or "default")
    return root / "durable_listeners.json"


def load_registry(workspace: str = "default") -> Dict[str, Dict[str, Any]]:
    path = registry_path(workspace)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {str(k): v for k, v in data.items() if isinstance(v, dict)}
    except Exception:
        pass
    return {}


def save_registry(workspace: str, records: Dict[str, Dict[str, Any]]) -> None:
    path = registry_path(workspace)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def upsert_listener(workspace: str, record: Dict[str, Any]) -> str:
    records = load_registry(workspace)
    key = str(record.get("key") or bind_key(record.get("options") or {}))
    record = dict(record)
    record["key"] = key
    record["updated_at"] = time.time()
    records[key] = record
    save_registry(workspace, records)
    return key


def save_module_listener(framework: Any, module: Any) -> Optional[str]:
    """Persist a running durable listener so it can be auto-started next boot."""
    try:
        record = snapshot_from_module(module)
        if "reverse_http_polling" not in str(record.get("module") or ""):
            # Only HTTP polling beacons are durable for now
            name = str(getattr(module, "name", "") or "").lower()
            if "http polling" not in name and "http_polling" not in name:
                return None
            record["module"] = _DURABLE_MODULE
        ws = _workspace_name(framework)
        return upsert_listener(ws, record)
    except Exception:
        return None


def _workspace_name(framework: Any) -> str:
    try:
        wm = getattr(framework, "workspace_manager", None)
        if wm:
            ws = wm.get_current_workspace()
            name = getattr(ws, "name", None) if ws else None
            if name:
                return str(name)
    except Exception:
        pass
    return str(getattr(framework, "current_workspace", None) or "default")


def _session_bind_records(session_manager: Any) -> List[Dict[str, Any]]:
    """Derive listener bind snapshots from restored Waiting beacon sessions."""
    out: List[Dict[str, Any]] = []
    seen = set()
    try:
        sessions = list(session_manager.get_sessions() or [])
    except Exception:
        return out
    for session in sessions:
        data = session.data if isinstance(getattr(session, "data", None), dict) else {}
        if not data:
            continue
        bind = data.get("listener_bind")
        if isinstance(bind, dict) and bind.get("options"):
            rec = {
                "module": bind.get("module") or _DURABLE_MODULE,
                "options": dict(bind.get("options") or {}),
                "key": bind.get("key") or bind_key(bind.get("options") or {}),
            }
        else:
            # Legacy: only know module name — skip unless registry has full options
            continue
        key = rec["key"]
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out


def collect_listeners_to_start(framework: Any) -> List[Dict[str, Any]]:
    """Union of session-derived binds and registry entries needed by Waiting sessions."""
    sm = getattr(framework, "session_manager", None)
    ws = _workspace_name(framework)
    registry = load_registry(ws)
    wanted: Dict[str, Dict[str, Any]] = {}

    for rec in _session_bind_records(sm) if sm else []:
        wanted[rec["key"]] = rec

    # If Waiting durable sessions exist but lack listener_bind, use full registry
    waiting = 0
    if sm:
        try:
            for session in sm.get_sessions() or []:
                data = session.data if isinstance(getattr(session, "data", None), dict) else {}
                if sm._is_durable_beacon_session(session.session_type, data):
                    waiting += 1
        except Exception:
            waiting = 0

    if waiting and not wanted and registry:
        wanted.update(registry)
    elif waiting and registry:
        # Fill gaps from registry (legacy sessions)
        for key, rec in registry.items():
            if key not in wanted:
                wanted[key] = rec

    return list(wanted.values())


def _port_already_served(framework: Any, options: Dict[str, Any]) -> bool:
    try:
        port = int(options.get("lport") or 0)
    except (TypeError, ValueError):
        return False
    if not port:
        return False
    prefix = "/" + str(options.get("url_prefix") or "/c2").strip("/")
    for listener in (getattr(framework, "active_listeners", None) or {}).values():
        try:
            lp = int(_opt_value(listener, "lport", 0) or 0)
            lprefix = "/" + str(_opt_value(listener, "url_prefix", "/c2") or "/c2").strip("/")
            if lp == port and lprefix == prefix and getattr(listener, "running", False):
                return True
        except Exception:
            continue
    return False


def _apply_options(module: Any, options: Dict[str, Any]) -> None:
    for key, value in (options or {}).items():
        if not hasattr(module, "set_option"):
            try:
                setattr(module, key, value)
            except Exception:
                pass
            continue
        try:
            if not module.set_option(key, value):
                # Fallback: direct assign for descriptors
                setattr(module, key, value)
        except Exception:
            try:
                setattr(module, key, value)
            except Exception:
                pass


def _start_one_listener(framework: Any, rec: Dict[str, Any]) -> Optional[Any]:
    """Start a single durable listener from a bind record. Returns module or None."""
    from core.output_handler import print_success, print_warning
    from core.framework.module_executor import ModuleExecutor

    options = dict(rec.get("options") or {})
    module_path = str(rec.get("module") or _DURABLE_MODULE).replace("\\", "/")
    if module_path.startswith("modules/"):
        module_path = module_path[len("modules/") :]
    if _port_already_served(framework, options):
        # Return the already-running instance
        try:
            port = int(options.get("lport") or 0)
        except (TypeError, ValueError):
            port = 0
        prefix = "/" + str(options.get("url_prefix") or "/c2").strip("/")
        for listener in (getattr(framework, "active_listeners", None) or {}).values():
            try:
                lp = int(_opt_value(listener, "lport", 0) or 0)
                lprefix = "/" + str(_opt_value(listener, "url_prefix", "/c2") or "/c2").strip("/")
                if lp == port and lprefix == prefix and getattr(listener, "running", False):
                    return listener
            except Exception:
                continue
        return None
    try:
        module = framework.module_loader.load_module(
            module_path, load_only=True, framework=framework, silent=True
        )
        if not module:
            print_warning(f"Durable listener: failed to load {module_path}")
            return None
        module.framework = framework
        _apply_options(module, options)
        if hasattr(module, "listener_id"):
            import uuid

            module.listener_id = str(uuid.uuid4())
        ok = module.run(background=True)
        if not ok:
            print_warning(
                f"Durable listener failed to bind "
                f"{options.get('lhost', '0.0.0.0')}:{options.get('lport', '?')}"
            )
            return None
        ModuleExecutor.register_background_job(module, framework)
        if hasattr(framework, "active_listeners"):
            framework.active_listeners[module.listener_id] = module
        host = options.get("lhost", "0.0.0.0")
        port = options.get("lport", "?")
        print_success(f"Auto-started durable listener {module_path} on {host}:{port}")
        return module
    except OSError as exc:
        print_warning(f"Durable listener bind error: {exc}")
    except Exception as exc:
        print_warning(f"Durable listener auto-start failed: {exc}")
    return None


def ensure_listener_for_session(framework: Any, session: Any) -> Optional[Any]:
    """Find or start the HTTP polling listener that owns this durable session."""
    if not framework or session is None:
        return None
    data = session.data if isinstance(getattr(session, "data", None), dict) else {}
    sid = getattr(session, "id", None) or getattr(session, "session_id", None)
    implant = str(data.get("implant_id") or data.get("client_id") or "").strip()

    active = getattr(framework, "active_listeners", None) or {}
    listener_id = data.get("listener_id")
    if listener_id and listener_id in active:
        return active[listener_id]
    for listener in active.values():
        if not hasattr(listener, "set_session_profile"):
            continue
        session_map = getattr(listener, "_session_to_client_id", {}) or {}
        client_map = getattr(listener, "_client_id_to_session", {}) or {}
        if sid and sid in session_map:
            return listener
        if implant and client_map.get(implant) == sid:
            return listener
        if implant and implant in client_map:
            return listener

    # Start from session listener_bind or workspace registry
    rec = None
    bind = data.get("listener_bind")
    if isinstance(bind, dict) and bind.get("options"):
        rec = {
            "module": bind.get("module") or _DURABLE_MODULE,
            "options": dict(bind.get("options") or {}),
            "key": bind.get("key") or bind_key(bind.get("options") or {}),
        }
    if not rec:
        ws = _workspace_name(framework)
        registry = load_registry(ws)
        if len(registry) == 1:
            rec = next(iter(registry.values()))
        elif registry:
            # Prefer a registry entry that matches session module hint
            for candidate in registry.values():
                rec = candidate
                break

    if not rec:
        return None
    return _start_one_listener(framework, rec)


def start_durable_listeners(framework: Any) -> int:
    """Auto-start persisted HTTP polling listeners for Waiting beacon sessions.

    Returns number of listeners successfully started.
    """
    if not framework or not getattr(framework, "durable_sessions", True):
        return 0
    try:
        from core.config import Config

        cfg = Config.get_instance()
        auto = cfg.get_config_value_by_path("sessions.auto_start_listeners")
        if auto is False:
            return 0
    except Exception:
        pass

    sm = getattr(framework, "session_manager", None)
    waiting = 0
    if sm:
        try:
            for session in sm.get_sessions() or []:
                data = session.data if isinstance(getattr(session, "data", None), dict) else {}
                if sm._is_durable_beacon_session(session.session_type, data):
                    waiting += 1
        except Exception:
            waiting = 0
    if not waiting:
        return 0

    records = collect_listeners_to_start(framework)
    if not records:
        try:
            from core.output_handler import print_info

            print_info(
                f"{waiting} Waiting beacon session(s) found, but no saved listener bind yet. "
                "Run listeners/multi/reverse_http_polling once — next restart will auto-start it."
            )
        except Exception:
            pass
        return 0

    from core.output_handler import print_info

    started = 0
    for rec in records:
        options = dict(rec.get("options") or {})
        already = _port_already_served(framework, options)
        mod = _start_one_listener(framework, rec)
        if mod and not already:
            started += 1

    if started:
        print_info(
            f"Durable C2: {started} listener(s) restored — Waiting sessions can check in"
        )
    return started
