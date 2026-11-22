#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Local JSON vault for WLAN captures, hash files, and recovered secrets."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class WlanVaultEntry:
    entry_id: str
    nickname: str
    ssid: str
    bssid: str
    secret_type: str = ""
    secret: str = ""
    hash_file: str = ""
    pcap_file: str = ""
    notes: str = ""
    created_at: float = field(default_factory=time.time)
    verified_at: float = 0.0
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WlanVaultEntry":
        return cls(
            entry_id=str(data.get("entry_id", uuid.uuid4().hex[:12])),
            nickname=str(data.get("nickname", "")),
            ssid=str(data.get("ssid", "")),
            bssid=str(data.get("bssid", "")).lower(),
            secret_type=str(data.get("secret_type", "")),
            secret=str(data.get("secret", "")),
            hash_file=str(data.get("hash_file", "")),
            pcap_file=str(data.get("pcap_file", "")),
            notes=str(data.get("notes", "")),
            created_at=float(data.get("created_at", time.time())),
            verified_at=float(data.get("verified_at", 0.0)),
            tags=[str(t) for t in (data.get("tags") or [])],
        )


class WlanVaultStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._entries: dict[str, WlanVaultEntry] = {}
        self.load()

    def load(self) -> None:
        self._entries.clear()
        if not self.path.is_file():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for raw in payload.get("entries") or []:
            if isinstance(raw, dict):
                ent = WlanVaultEntry.from_dict(raw)
                self._entries[ent.entry_id] = ent

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        body = {
            "schema_version": 1,
            "updated_at": time.time(),
            "entries": [e.to_dict() for e in self._entries.values()],
        }
        self.path.write_text(json.dumps(body, indent=2), encoding="utf-8")

    def add(self, entry: WlanVaultEntry) -> WlanVaultEntry:
        if not entry.entry_id:
            entry.entry_id = uuid.uuid4().hex[:12]
        self._entries[entry.entry_id] = entry
        self.save()
        return entry

    def upsert_credential(
        self,
        *,
        ssid: str,
        bssid: str,
        secret_type: str,
        secret: str,
        nickname: str = "",
        hash_file: str = "",
        pcap_file: str = "",
        notes: str = "",
        tags: list[str] | None = None,
    ) -> WlanVaultEntry:
        bssid_l = str(bssid or "").lower()
        for ent in self._entries.values():
            if ent.bssid == bssid_l and ent.ssid == ssid and ent.secret_type == secret_type:
                if secret:
                    ent.secret = secret
                if nickname:
                    ent.nickname = nickname
                if hash_file:
                    ent.hash_file = hash_file
                if pcap_file:
                    ent.pcap_file = pcap_file
                if notes:
                    ent.notes = notes
                if tags:
                    ent.tags = list(tags)
                self.save()
                return ent
        label = nickname or f"{ssid or 'net'}-{secret_type}"
        return self.add(
            WlanVaultEntry(
                entry_id=uuid.uuid4().hex[:12],
                nickname=label,
                ssid=ssid,
                bssid=bssid_l,
                secret_type=secret_type,
                secret=secret,
                hash_file=hash_file,
                pcap_file=pcap_file,
                notes=notes,
                tags=list(tags or []),
            )
        )

    def list_entries(self, *, bssid: str = "") -> list[WlanVaultEntry]:
        rows = list(self._entries.values())
        filt = str(bssid or "").strip().lower()
        if filt:
            rows = [e for e in rows if e.bssid == filt]
        return sorted(rows, key=lambda e: e.created_at, reverse=True)

    def get(self, entry_id: str) -> WlanVaultEntry | None:
        return self._entries.get(str(entry_id or "").strip())

    def mark_verified(self, entry_id: str) -> bool:
        ent = self.get(entry_id)
        if not ent:
            return False
        ent.verified_at = time.time()
        self.save()
        return True

    def delete(self, entry_id: str) -> bool:
        key = str(entry_id or "").strip()
        if key not in self._entries:
            return False
        del self._entries[key]
        self.save()
        return True