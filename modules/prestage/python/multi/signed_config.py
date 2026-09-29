#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from core.payload_generation.prestage.signed_config_context import resolve_signed_config_context


class Module(Prestage):
    PRESTAGE_ID = "signed_config"

    __info__ = {
        "name": "Signed Config (Python)",
        "description": "Embed encrypted and signed operator config separate from the payload body",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["python"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "config", "python"],
    }

    config_json = OptString("", "Inline JSON object to encrypt/sign at generation time", False)
    config_file = OptFile("", "JSON config file on operator machine", False)
    config_secret = OptString("", "Encryption secret (default: kitty-signed-config)", False)
    config_sign_key = OptString("", "HMAC signing key (default: config_secret)", False)

    def generate_python(self, context: Dict[str, Any] = None) -> str:
        from lib.c2.signed_config import build_signed_config_bootstrap

        cfg = resolve_signed_config_context(self, context)
        blob_b64 = str(cfg.get("blob_b64") or "").strip()
        if not blob_b64:
            return "pass  # signed_config: set prestage_config or config_json"
        return build_signed_config_bootstrap(
            blob_b64,
            secret=str(cfg.get("config_secret") or "kitty-signed-config"),
            sign_key=str(cfg.get("config_sign_key") or cfg.get("config_secret") or "kitty-signed-config"),
        )
