#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Encrypted and signed configuration blob for prestage embedding."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any, Dict, Optional


def _derive_key(secret: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode("utf-8", errors="replace"),
        salt,
        120_000,
        dklen=32,
    )


def _xor_stream(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return bytes(out)


def pack_signed_config(
    config: Dict[str, Any],
    *,
    secret: str,
    sign_key: str,
) -> str:
    """Serialize, sign, encrypt, and base64-wrap a config dict for implant embedding."""
    plain = json.dumps(config, separators=(",", ":")).encode("utf-8")
    sign_secret = (sign_key or secret or "kitty-signed-config").encode("utf-8", errors="replace")
    signature = hmac.new(sign_secret, plain, hashlib.sha256).hexdigest()
    enc_secret = secret or sign_key or "kitty-signed-config"
    salt = os.urandom(16)
    key = _derive_key(enc_secret, salt)
    payload = _xor_stream(plain, key)
    envelope = {
        "v": 1,
        "sig": signature,
        "salt": base64.b64encode(salt).decode("ascii"),
        "data": base64.b64encode(payload).decode("ascii"),
    }
    return base64.b64encode(json.dumps(envelope, separators=(",", ":")).encode("utf-8")).decode("ascii")


def build_signed_config_bootstrap(blob_b64: str, *, secret: str, sign_key: str) -> str:
    """Return Python source that verifies and decrypts an embedded config blob."""
    blob_lit = blob_b64 or ""
    secret_lit = secret or "kitty-signed-config"
    sign_lit = sign_key or secret_lit
    return f"""
import base64 as _b64
import hashlib as _hashlib
import hmac as _hmac
import json as _json

_kitty_signed_config_blob = "{blob_lit}"
_kitty_signed_config_secret = {secret_lit!r}
_kitty_signed_config_sign_key = {sign_lit!r}

def _kitty_derive_key(_secret, _salt):
    return _hashlib.pbkdf2_hmac("sha256", _secret.encode("utf-8", errors="replace"), _salt, 120000, dklen=32)

def _kitty_xor_stream(_data, _key):
    _out = bytearray(len(_data))
    for _i, _b in enumerate(_data):
        _out[_i] = _b ^ _key[_i % len(_key)]
    return bytes(_out)

def _kitty_unpack_signed_config(_blob_b64, _secret, _sign_key):
    _outer = _b64.b64decode(_blob_b64.encode("ascii"))
    _env = _json.loads(_outer.decode("utf-8", errors="replace"))
    _salt = _b64.b64decode(str(_env.get("salt") or "").encode("ascii"))
    _payload = _b64.b64decode(str(_env.get("data") or "").encode("ascii"))
    _key = _kitty_derive_key(_secret or "kitty-signed-config", _salt)
    _plain = _kitty_xor_stream(_payload, _key)
    _sig = _hmac.new(
        (_sign_key or _secret or "kitty-signed-config").encode("utf-8", errors="replace"),
        _plain,
        _hashlib.sha256,
    ).hexdigest()
    if _sig != str(_env.get("sig") or ""):
        raise ValueError("signed_config signature mismatch")
    _cfg = _json.loads(_plain.decode("utf-8", errors="replace"))
    if not isinstance(_cfg, dict):
        raise ValueError("signed_config payload is not an object")
    return _cfg

_kitty_signed_config = None
_kitty_signed_config_error = ""
try:
    if _kitty_signed_config_blob:
        _kitty_signed_config = _kitty_unpack_signed_config(
            _kitty_signed_config_blob,
            _kitty_signed_config_secret,
            _kitty_signed_config_sign_key,
        )
except Exception as _kitty_cfg_exc:
    _kitty_signed_config_error = str(_kitty_cfg_exc)
    try:
        _kitty_telemetry_record("signed_config", "unpack_failed", _kitty_signed_config_error)
    except Exception:
        pass
""".strip()


def load_config_dict(raw: str, config_file: str = "") -> Dict[str, Any]:
    """Parse operator-side config from JSON string or file path."""
    if config_file and os.path.isfile(config_file):
        with open(config_file, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    text = str(raw or "").strip()
    if not text:
        return {}
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("signed_config expects a JSON object")
    return data
