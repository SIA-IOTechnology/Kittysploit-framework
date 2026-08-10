#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Collect AD attack-path data via bloodhound-python (Linux/Windows, no SharpHound.exe)."""

from kittysploit import *
from lib.protocols.ldap.bloodhound_python_collect import (
    bloodhound_python_available,
    collect_and_merge_kb,
    run_bloodhound_python,
)


class Module(Scanner):
    __info__ = {
        "name": "BloodHound.py collect",
        "description": (
            "Run bloodhound-python / bloodhound-ce-python against a Domain Controller "
            "from Linux or Windows, produce a zip, and merge into the agent attack graph. "
            "Default collection=DCOnly (LDAP-only, good from Kali). Use All for fuller "
            "Session/LocalAdmin fan-out when the network allows."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "modules": [],
        "tags": ["ad", "ldap", "bloodhound", "graph", "scanner"],
        "references": [
            "https://github.com/dirkjanm/BloodHound.py",
            "https://www.kali.org/tools/bloodhound.py/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 20,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 1.6,
            "noise": 0.55,
            "value": 0.9,
            "requires": {
                "capabilities_any": [],
                "capabilities_all": [],
            },
            "chain": {
                "consumes_capabilities": [],
                "produces_capabilities": ["ad_graph"],
            },
        },
    }

    domain = OptString("", "AD domain FQDN (e.g. CORP.LOCAL)", True)
    username = OptString("", "Domain username", True)
    password = OptString("", "Password (or leave empty and set hashes)", False)
    hashes = OptString("", "LM:NT or :NT hash (Impacket style)", False)
    nameserver = OptString("", "DNS / DC IP for -ns (recommended)", False)
    domain_controller = OptString("", "Override DC hostname (-dc)", False)
    collection = OptString(
        "DCOnly",
        "Collection methods: DCOnly, Default, All, Group, ACL, …",
        False,
    )
    use_ldaps = OptBool(False, "Use LDAPS", False)
    timeout = OptInteger(900, "Collector timeout seconds", False)
    import_graph = OptBool(True, "Merge into agent attack_graph after collect", False)
    replace = OptBool(True, "Replace existing attack_graph on import", False)

    def run(self):
        avail = bloodhound_python_available()
        if not avail.get("available"):
            print_error("bloodhound-python not installed")
            print_info(avail.get("install_hint") or "pip install bloodhound")
            return False

        domain = str(self.domain or "").strip()
        username = str(self.username or "").strip()
        password = str(self.password or "")
        hashes = str(self.hashes or "").strip()
        if not domain or not username:
            print_error("domain and username are required")
            return False
        if not password and not hashes:
            print_error("password or hashes required")
            return False

        kwargs = dict(
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            nameserver=str(self.nameserver or "").strip(),
            domain_controller=str(self.domain_controller or "").strip(),
            collection=str(self.collection or "DCOnly"),
            use_ldaps=bool(self.use_ldaps),
            timeout_sec=int(self.timeout or 900),
            replace=bool(self.replace),
        )

        print_status(
            f"bloodhound-python collect domain={domain} user={username} "
            f"collection={kwargs['collection']} cli={avail.get('cli')}"
        )

        if self.import_graph:
            result = collect_and_merge_kb(getattr(self, "framework", None), **kwargs)
        else:
            result = run_bloodhound_python(**{k: v for k, v in kwargs.items() if k != "replace"})

        if not result.get("success"):
            print_error(result.get("error") or "Collection failed")
            if result.get("stderr"):
                print_info(str(result["stderr"])[:2000])
            if result.get("install_hint"):
                print_info(result["install_hint"])
            return False

        export_path = result.get("export_path") or result.get("zip_path")
        print_success(f"BloodHound export: {export_path}")
        if result.get("imported"):
            print_success(f"Merged into attack_graph (+{result.get('nodes_added', 0)} nodes)")
        print_info(
            "Import into Cosmic Attack Graph: Attack Graph → file import, "
            "or POST /api/attack-graph/import with this zip path."
        )
        self.vulnerability_info = {
            "export_path": export_path,
            "collection": result.get("collection"),
            "cli": result.get("cli"),
            "imported": bool(result.get("imported")),
        }
        return True
