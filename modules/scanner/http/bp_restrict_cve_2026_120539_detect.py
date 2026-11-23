#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-120539 — Restrictions for BuddyPress eval RCE."""

from kittysploit import *
from lib.protocols.http.bp_restrict import Bp_restrict
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Bp_restrict):
    __info__ = {
        "name": "BuddyPress Restrict CVE-2026-120539 detect",
        "description": "Checks bp-restrict + BuddyPress + Paid Memberships Pro stack.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-120539"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-120539"],
        "tags": ["wordpress", "buddypress", "rce", "cve-2026-120539"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/bp_restrict_cve_2026_120539_eval_rce",
                ],
            },
        },
    }

    def run(self):
        fp = self.bp_restrict_fingerprint()
        ready = fp["bp_restrict"] and fp["buddypress"] and fp["pmpro"]
        if not fp["bp_restrict"]:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-120539",
            reason="bp-restrict plugin present",
            fingerprint=fp,
            preconditions_met=ready,
        )
        return True