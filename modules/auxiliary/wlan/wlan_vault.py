#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""List, import, and verify WLAN secrets in the local KittySploit vault."""

from __future__ import annotations
from pathlib import Path
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi Local Vault",
        "description": (
            "Manage ~/.kittysploit/wlan_vault.json — store PSK/PIN/hash paths, "
            "list entries, and verify recovered keys against .22000 captures."
        ),
        "author": ["KittySploit Team"],
        "tags": ["wlan", "wifi", "vault", "credential"],
        "references": ["https://attack.mitre.org/techniques/T1555/"],
    }

    action = OptEnum(["list", "add", "verify", "delete"], "list", "Vault action", required=False)
    vault_path = OptString("", "Vault JSON path (default ~/.kittysploit/wlan_vault.json)", required=False)
    entry_id = OptString("", "Entry id for verify/delete", required=False)
    nickname = OptString("", "Human label", required=False)
    ssid = OptString("", "Network SSID", required=False)
    bssid = OptString("", "AP BSSID", required=False)
    secret_type = OptEnum(["psk", "wps_pin", "hash_ref"], "psk", "Stored secret kind", required=False)
    secret = OptString("", "PSK or PIN text", required=False)
    hash_file = OptFile("", "Linked .22000 file", required=False)
    pcap_file = OptFile("", "Linked PCAP", required=False)

    def run(self):
        path = str(self.vault_path or "").strip() or None
        store = self.wlan_vault_open(path)
        act = str(self.action or "list").strip().lower()

        if act == "list":
            rows = store.list_entries(bssid=str(self.bssid or ""))
            if not rows:
                print_warning("Vault is empty")
                return True
            print_info("=" * 72)
            for ent in rows:
                verified = "yes" if ent.verified_at else "no"
                print_success(
                    f"{ent.entry_id} | {ent.nickname} | {ent.ssid} | {ent.bssid} | "
                    f"{ent.secret_type} | verified={verified}"
                )
                if ent.secret:
                    print_status(f"  secret={ent.secret[:3]}***")
                if ent.hash_file:
                    print_status(f"  hash={ent.hash_file}")
            return True

        if act == "add":
            if not str(self.ssid or "").strip() or not str(self.bssid or "").strip():
                print_error("SSID and BSSID required for add")
                return False
            ent = self.wlan_vault_store(
                ssid=str(self.ssid).strip(),
                bssid=str(self.bssid).strip().lower(),
                secret_type=str(self.secret_type or "psk"),
                secret=str(self.secret or ""),
                nickname=str(self.nickname or ""),
                hash_file=str(self.hash_file or ""),
                pcap_file=str(self.pcap_file or ""),
                vault_path=path,
            )
            print_success(f"Stored entry {ent.entry_id} ({ent.nickname})")
            return True

        if act == "verify":
            eid = str(self.entry_id or "").strip()
            if not eid:
                print_error("ENTRY_ID required")
                return False
            if self.wlan_vault_verify_psk(eid, vault_path=path):
                print_success(f"Entry {eid} verified against hash file")
                return True
            print_warning(f"Verification failed for {eid}")
            return False

        if act == "delete":
            eid = str(self.entry_id or "").strip()
            if not eid:
                print_error("ENTRY_ID required")
                return False
            if store.delete(eid):
                print_success(f"Deleted {eid}")
                return True
            print_error("Entry not found")
            return False

        print_error(f"Unknown action {act}")
        return False