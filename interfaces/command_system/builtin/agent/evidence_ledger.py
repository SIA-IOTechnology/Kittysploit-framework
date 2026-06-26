#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Hash-chained evidence ledger for agent runs."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _canonical_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def hash_record(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


class EvidenceLedger:
    def __init__(self, run_id: str, policy_hash: str = "") -> None:
        self.run_id = run_id
        self.policy_hash = policy_hash
        self.entries: List[Dict[str, Any]] = []
        self._last_hash = ""

    def append(
        self,
        kind: str,
        payload: Dict[str, Any],
        *,
        module: str = "",
        target: str = "",
        parent_hash: str = "",
    ) -> Dict[str, Any]:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "kind": kind,
            "module": module,
            "target": target,
            "policy_hash": self.policy_hash,
            "parent_hash": parent_hash or self._last_hash,
            "payload": payload,
        }
        record["hash"] = hash_record(record)
        self.entries.append(record)
        self._last_hash = record["hash"]
        return record

    def verify(self) -> bool:
        previous = ""
        for entry in self.entries:
            expected_parent = previous
            if entry.get("parent_hash", "") != expected_parent:
                return False
            digest = entry.get("hash", "")
            copy = dict(entry)
            copy.pop("hash", None)
            if hash_record(copy) != digest:
                return False
            previous = digest
        return True

    def to_list(self) -> List[Dict[str, Any]]:
        return list(self.entries)
