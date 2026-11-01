#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect osTicket CVE-2026-22200 PDF / php filter file read surface (Horizon3)."""

from __future__ import annotations

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "osTicket CVE-2026-22200 Patch Detect",
        "description": (
            "Unauthenticated checks from Horizon3 check.py: login username pre-validation "
            "(v1.18.3+/v1.17.7+ patch) and optional open.php HTML srcset stripping. "
            "Full CNEXT RCE chain is not bundled — file read alone does not yield a session."
        ),
        "author": ["Horizon3 Attack Team", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-22200"],
        "references": [
            "https://github.com/horizon3ai/CVE-2026-22200",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-22200",
        ],
        "tags": ["web", "scanner", "osticket", "file-read", "unauth"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "requires": {"tech_hints_any": ["osticket"]},
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/osticket_cve_2026_22200_file_read",
                    "scanner/http/osticket_detect",
                ],
            },
        },
    }

    deep_check = OptBool(
        True,
        "If open.php is public, POST benign HTML to test srcset stripping",
        required=False,
        advanced=True,
    )

    @staticmethod
    def _csrf_token(html: str) -> str | None:
        patterns = (
            r'name=["\']__CSRFToken__["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
        )
        for pattern in patterns:
            match = re.search(pattern, html or "", re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _login_validation(self) -> str | None:
        """Return vulnerable, patched, or None."""
        r = self.http_request(method="GET", path="/login.php", allow_redirects=True)
        if not r or r.status_code != 200:
            return None
        content = r.text or ""
        lower = content.lower()
        if "luser" not in lower and "userid" not in lower:
            return None
        token = self._csrf_token(content)
        if not token:
            return None
        invalid_user = "test|invalid<>user"
        post = self.http_request(
            method="POST",
            path="/login.php",
            data={
                "__CSRFToken__": token,
                "luser": invalid_user,
                "lpasswd": "testpassword123",
            },
            allow_redirects=True,
        )
        if not post:
            return None
        resp_lower = (post.text or "").lower()
        if "invalid user id" in resp_lower:
            return "patched"
        if "invalid username or password" in resp_lower or "access denied" in resp_lower:
            return "vulnerable"
        return None

    def _open_ticket_accessible(self) -> bool:
        r = self.http_request(method="GET", path="/open.php", allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        url = (r.url or "").lower()
        if "login.php" in url:
            return False
        content = (r.text or "").lower()
        indicators = ("ajax.php/form/help-topic", "select a help topic")
        return "<form" in content and any(ind in content for ind in indicators)

    def _html_topic_id(self) -> int | None:
        r = self.http_request(method="GET", path="/open.php", allow_redirects=True)
        if not r or r.status_code != 200:
            return None
        content = r.text or ""
        topic_pattern = re.compile(
            r'<option[^>]*value=["\'](\d+)["\'][^>]*>(?!.*?Select.*?Topic)',
            re.IGNORECASE,
        )
        topic_ids = [int(t) for t in topic_pattern.findall(content) if t.isdigit()]
        for topic_id in topic_ids:
            ajax = self.http_request(
                method="GET",
                path=f"/ajax.php/form/help-topic/{topic_id}/forms",
                headers={"X-Requested-With": "XMLHttpRequest"},
                allow_redirects=False,
            )
            if ajax and ajax.status_code == 200 and 'class="richtext' in (ajax.text or "").lower():
                return topic_id
            direct = self.http_request(
                method="GET",
                path=f"/open.php?topicId={topic_id}",
                allow_redirects=True,
            )
            if direct and direct.status_code == 200 and 'class="richtext' in (direct.text or "").lower():
                return topic_id
        if 'class="richtext' in content.lower():
            default = re.search(
                r'name=["\']topicId["\'][^>]*value=["\'](\d+)["\']',
                content,
                re.IGNORECASE,
            )
            if default:
                return int(default.group(1))
        return None

    def _html_submission_vulnerable(self) -> bool | None:
        r = self.http_request(method="GET", path="/open.php", allow_redirects=True)
        if not r or r.status_code != 200:
            return None
        content = r.text or ""
        token = self._csrf_token(content)
        topic_id = self._html_topic_id()
        if not topic_id:
            return None
        marker = secrets.token_hex(6)
        test_html = (
            f'<img src="doesnotexist.jpg" srcset="http://{marker}.example.com/image-400.jpg 400w" '
            f'alt="test" width="800" height="600">'
        )
        payload = {
            "a": "open",
            "subject": "KittySploit CVE-2026-22200 probe",
            "message": test_html,
            "name": "Test User",
            "topicId": str(topic_id),
        }
        if token:
            payload["__CSRFToken__"] = token
        post = self.http_request(
            method="POST",
            path="/open.php",
            data=payload,
            allow_redirects=True,
        )
        if not post:
            return None
        resp = post.text or ""
        lower = resp.lower()
        validation = ("required", "error", "email address", "correct")
        if not any(ind in lower for ind in validation):
            return None
        return "srcset" in lower and f"http://{marker.lower()}.example.com" in lower

    def run(self):
        login = self._login_validation()
        submission: bool | None = None
        anon_surface = False

        if self._open_ticket_accessible():
            anon_surface = True
            if self.deep_check:
                submission = self._html_submission_vulnerable()

        if login == "patched" and submission is not True:
            return False

        is_vulnerable = login == "vulnerable" or submission is True
        if not is_vulnerable:
            return False

        reasons = []
        if login == "vulnerable":
            reasons.append("login lacks username format pre-validation")
        if submission is True:
            reasons.append("open.php preserves srcset in validation response")
        reason = "; ".join(reasons) or "CVE-2026-22200 indicators"
        if anon_surface and (login == "vulnerable" or submission is True):
            reason += " — likely exploitable by anonymous users"

        self.set_info(
            severity="critical",
            cve="CVE-2026-22200",
            reason=reason,
            path="/login.php",
        )
        return True
