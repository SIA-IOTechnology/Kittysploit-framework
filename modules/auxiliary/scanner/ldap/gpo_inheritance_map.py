#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Map Active Directory GPO inheritance and affected computers."""

from __future__ import annotations

import json
from typing import Dict, List

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client
from lib.protocols.ldap.gpo_helpers import (
    enumerate_gpos,
    map_gpos_to_computers,
    summarize_gpo_scope,
)


class Module(Auxiliary, Ad_client):
    __info__ = {
        "name": "GPO Inheritance Map",
        "description": (
            "Enumerate GPO links on domains and OUs, compute inheritance order, "
            "and map which computers are affected by each GPO."
        ),
        "author": ["KittySploit Team"],
        "tags": ["ad", "ldap", "gpo", "auxiliary", "enumeration"],
        "references": [
            "https://github.com/cogiceo/GPOHound",
            "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "gpo_scope", "affected_computers"],
        },
    }

    min_computers = OptInteger(1, "Only report GPOs affecting at least N computers", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def run(self):
        if not self.conn:
            print_error("LDAP bind failed")
            return {"error": "ldap_bind_failed"}

        gpos = enumerate_gpos(self)
        inheritance, gpo_computers = map_gpos_to_computers(self)
        summary = summarize_gpo_scope(gpo_computers, gpos)

        threshold = max(0, int(self.min_computers or 1))
        scoped = [row for row in summary if row.get("computer_count", 0) >= threshold]
        if not scoped:
            print_info("No GPO scope matched the reporting threshold")
            return {"mapped_gpos": len(gpos), "reported": 0}

        print_success(f"Mapped {len(gpos)} GPO(s); {len(scoped)} affect >= {threshold} computer(s)")
        for row in scoped[:10]:
            print_info(
                f"{row.get('display_name')} ({row.get('guid')}): "
                f"{row.get('computer_count')} computer(s)"
            )

        payload = {
            "domain": self.domain,
            "gpos": gpos,
            "inheritance": inheritance[:100],
            "gpo_scope": scoped,
            "gpo_computer_map": {guid: rows[:50] for guid, rows in gpo_computers.items()},
        }

        if self.output_file:
            try:
                with open(str(self.output_file), "w", encoding="utf-8") as fp:
                    json.dump(payload, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return payload
