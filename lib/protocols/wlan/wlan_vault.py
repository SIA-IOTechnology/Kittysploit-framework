#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WLAN local vault mixin."""

from __future__ import annotations

import os
from pathlib import Path

from core.framework.base_module import BaseModule

from lib.protocols.wlan.hc22000 import parse_hc22000_line
from lib.protocols.wlan.vault_store import WlanVaultEntry, WlanVaultStore


class Wlan_vault(BaseModule):
    def wlan_vault_default_path(self) -> Path:
        base = os.environ.get("KITTYSPLOIT_WLAN_VAULT", "").strip()
        if base:
            return Path(base).expanduser()
        home = Path.home()
        return home / ".kittysploit" / "wlan_vault.json"

    def wlan_vault_open(self, path: str | Path | None = None) -> WlanVaultStore:
        target = Path(path) if path else self.wlan_vault_default_path()
        return WlanVaultStore(target)

    def wlan_vault_store(
        self,
        *,
        ssid: str,
        bssid: str,
        secret_type: str,
        secret: str = "",
        nickname: str = "",
        hash_file: str = "",
        pcap_file: str = "",
        notes: str = "",
        vault_path: str | Path | None = None,
    ) -> WlanVaultEntry:
        return self.wlan_vault_open(vault_path).upsert_credential(
            ssid=ssid,
            bssid=bssid,
            secret_type=secret_type,
            secret=secret,
            nickname=nickname,
            hash_file=hash_file,
            pcap_file=pcap_file,
            notes=notes,
        )

    def wlan_vault_verify_psk(self, entry_id: str, *, vault_path: str | Path | None = None) -> bool:
        store = self.wlan_vault_open(vault_path)
        ent = store.get(entry_id)
        if not ent or ent.secret_type not in ("psk", "wpa_psk") or not ent.secret:
            return False
        if not ent.hash_file or not Path(ent.hash_file).is_file():
            return False
        matched = False
        for line in Path(ent.hash_file).read_text(encoding="utf-8", errors="replace").splitlines():
            parsed = parse_hc22000_line(line)
            if parsed and self.wlan_try_password(ent.secret, parsed):
                matched = True
                break
        if matched:
            store.mark_verified(entry_id)
        return matched