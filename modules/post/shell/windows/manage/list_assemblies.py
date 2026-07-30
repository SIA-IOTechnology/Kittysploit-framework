#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""List .NET assemblies available for loadmodule / run_assembly."""

from kittysploit import *

from lib.post.windows.assembly_loader import assemblies_dir, list_assemblies


class Module(Post):
    __info__ = {
        "name": "List Windows Assemblies Catalog",
        "description": (
            "List .NET tools under data/assemblies/ for use with "
            "post/shell/windows/manage/run_assembly (loadmodule)."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [
            SessionType.METERPRETER,
            SessionType.SHELL,
            SessionType.POLLING,
        ],
        "agent": {
            "risk": "passive",
            "effects": [],
            "expected_requests": 0,
            "reversible": True,
            "approval_required": False,
            "produces": [],
            "cost": 0.1,
            "noise": 0.0,
            "value": 0.5,
            "requires": {"capabilities_any": [], "capabilities_all": []},
            "chain": {"consumes_capabilities": [], "produces_capabilities": []},
        },
    }

    # session_id still inherited but not required for listing
    def run(self):
        base = assemblies_dir()
        rows = list_assemblies()
        print_status(f"Assembly catalog directory: {base}")
        if not rows:
            print_warning(
                "Empty catalog. Drop Seatbelt.exe / Rubeus.exe / SharpHound.exe "
                "into data/assemblies/ and optionally edit catalog.json"
            )
            return True
        headers = ["Name", "File", "Status", "Description"]
        table = []
        for entry in rows:
            table.append(
                [
                    entry.get("name") or "",
                    entry.get("file") or "",
                    "present" if entry.get("present") else "MISSING",
                    (entry.get("description") or "")[:60],
                ]
            )
        try:
            print_table(headers, table)
        except Exception:
            for row in table:
                print_info(" | ".join(row))
        print_info("Use: set module Seatbelt  (or set local_path C:\\tools\\Seatbelt.exe)")
        return True
