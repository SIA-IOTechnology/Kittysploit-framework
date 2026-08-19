#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Offload listener registration stub for distributed C2 edges."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class OffloadListenerSpec:
    listener_id: str
    bind_host: str
    bind_port: int
    upstream: str
    token: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)


class OffloadListenerRegistry:
    """In-memory registry until distributed listener orchestration lands."""

    def __init__(self):
        self._entries: Dict[str, OffloadListenerSpec] = {}

    def register(self, spec: OffloadListenerSpec) -> None:
        self._entries[spec.listener_id] = spec

    def unregister(self, listener_id: str) -> bool:
        return self._entries.pop(listener_id, None) is not None

    def list(self) -> List[OffloadListenerSpec]:
        return list(self._entries.values())

    def to_json(self) -> str:
        payload = []
        for item in self.list():
            payload.append(
                {
                    "listener_id": item.listener_id,
                    "bind": f"{item.bind_host}:{item.bind_port}",
                    "upstream": item.upstream,
                    "registered_at": time.time(),
                    "meta": item.meta,
                }
            )
        return json.dumps(payload, separators=(",", ":"))


def build_offload_announce(listener_id: str, bind_host: str, bind_port: int, upstream: str) -> Dict[str, Any]:
    return {
        "type": "offload_listener",
        "listener_id": listener_id,
        "bind_host": bind_host,
        "bind_port": int(bind_port),
        "upstream": upstream,
    }
