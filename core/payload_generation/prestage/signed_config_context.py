#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Resolve signed_config prestage options from payload context and module options."""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

from lib.c2.signed_config import load_config_dict, pack_signed_config


def _opt_value(module, name: str, default: Any = "") -> Any:
    if module is None:
        return default
    opt = getattr(module, name, None)
    if opt is not None and hasattr(opt, "value"):
        return opt.value
    return opt if opt is not None else default


def resolve_signed_config_context(
    module=None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    ctx = dict(context or {})
    config_json = str(ctx.get("config_json") or _opt_value(module, "config_json", "") or "").strip()
    config_file = str(ctx.get("config_file") or _opt_value(module, "config_file", "") or "").strip()
    if not config_file:
        payload_file = str(ctx.get("prestage_config_file") or "").strip()
        if payload_file and os.path.isfile(payload_file):
            config_file = payload_file
    if not config_json:
        config_json = str(ctx.get("prestage_config") or "").strip()

    secret = str(
        ctx.get("config_secret")
        or ctx.get("prestage_config_secret")
        or _opt_value(module, "config_secret", "")
        or ""
    ).strip()
    sign_key = str(
        ctx.get("config_sign_key")
        or ctx.get("prestage_config_sign_key")
        or _opt_value(module, "config_sign_key", "")
        or ""
    ).strip()
    if not secret:
        secret = "kitty-signed-config"
    if not sign_key:
        sign_key = secret

    config = load_config_dict(config_json, config_file)
    blob_b64 = pack_signed_config(config, secret=secret, sign_key=sign_key) if config else ""
    return {
        "blob_b64": blob_b64,
        "config_secret": secret,
        "config_sign_key": sign_key,
    }
