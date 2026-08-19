#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Bootstrap encrypted agent-side task storage before callback (Python emitter)."""

from typing import Any, Dict

from kittysploit import *
from core.payload_generation.prestage.agent_store_context import resolve_agent_store_context


class Module(Prestage):
    PRESTAGE_ID = "agent_store"

    __info__ = {
        "name": "Agent Local Store (Python)",
        "description": "Bootstrap encrypted local task storage on the implant before callback",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["python"],
        "dependencies": [],
        "tags": ["prestage", "offline", "persistence", "tasks", "python"],
    }

    store_path = OptString("", "Store file path on target (default: temp/.kitty_store)", False)
    store_secret = OptString("", "Encryption secret (default: kitty-agent-store)", False)

    def generate_python(self, context: Dict[str, Any] = None) -> str:
        cfg = resolve_agent_store_context(self, context)
        store_path = cfg["store_path"]
        store_secret = cfg["store_secret"]

        from lib.c2.agent_store import build_agent_store_bootstrap

        if store_path:
            return build_agent_store_bootstrap(store_path, store_secret, var_name="_kitty_store")

        return (
            'import tempfile as _tmp\n'
            '_kitty_store_path = _tmp.gettempdir() + "/.kitty_store"\n'
            + build_agent_store_bootstrap(
                "_kitty_store_path",
                store_secret,
                var_name="_kitty_store",
                path_is_expression=True,
            )
        ).strip()
