#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phpMyAdmin default credentials."""

import re
from urllib.parse import urljoin

from kittysploit import *
from lib.protocols.http.http_client import Http_client


BASES = (
    "/",
    "/phpmyadmin/",
    "/phpMyAdmin/",
    "/pma/",
    "/mysql/",
)

USERS = ("root", "mysql")
PASSWORDS = ("123456", "root", "mysql", "toor")

_TOKEN_RE = re.compile(r'name="token"\s+value="([0-9a-zA-Z]+)"', re.I)
_SET_SESSION_RE = re.compile(r'name="set_session"\s+value="([0-9a-zA-Z]+)"', re.I)
_COOKIE_PMA_RE = re.compile(r"phpMyAdmin(?:_https)?=([0-9a-zA-Z]+)", re.I)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "phpMyAdmin Default Login",
        "description": (
            "Attempts common default phpMyAdmin credentials after extracting CSRF tokens."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "references": [
            "https://www.phpmyadmin.net",
        ],
        "tags": ["web", "scanner", "phpmyadmin", "default-login", "mysql", "vuln"],
        "modules": ["scanner/http/phpmyadmin_detect"],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "credential_testing"],
            "expected_requests": 16,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "credentials"],
            "cost": 1.5,
            "noise": 0.7,
            "value": 1.5,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "db_access", "from_detail": ""},
                    {"capability": "admin_surface", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    def _url(self, path: str) -> str:
        host = str(getattr(getattr(self, "target", None), "value", getattr(self, "target", "")) or "").strip()
        port = getattr(getattr(self, "port", None), "value", getattr(self, "port", 80))
        ssl = getattr(getattr(self, "ssl", None), "value", getattr(self, "ssl", False))
        scheme = "https" if ssl in (True, "true", "True", 1, "1") else "http"
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            port_i = 443 if scheme == "https" else 80
        if host.startswith(("http://", "https://")):
            return host.rstrip("/") + path
        return f"{scheme}://{host}:{port_i}{path}"

    def _try_base(self, base: str):
        index_path = urljoin(base, "index.php") if base != "/" else "/index.php"
        if base.endswith("/") and base != "/":
            index_path = base + "index.php"

        login_page = self.http_request(method="GET", path=index_path, allow_redirects=True)
        if not login_page or login_page.status_code not in (200, 401, 403):
            return None
        body = login_page.text or ""
        if "phpmyadmin" not in body.lower() and "pma_" not in body.lower():
            # Still allow if tokens present
            if not _TOKEN_RE.search(body):
                return None

        token_m = _TOKEN_RE.search(body)
        set_session_m = _SET_SESSION_RE.search(body)
        cookie_header = str(login_page.headers.get("Set-Cookie") or "")
        cookie_m = _COOKIE_PMA_RE.search(cookie_header)
        if not token_m:
            return None

        token = token_m.group(1)
        # Cookie phpMyAdmin often mirrors the set_session form value
        token2 = set_session_m.group(1) if set_session_m else (cookie_m.group(1) if cookie_m else token)
        session = cookie_m.group(1) if cookie_m else token2

        for user in USERS:
            for password in PASSWORDS:
                data = (
                    f"set_session={session}&pma_username={user}&pma_password={password}"
                    f"&server=1&route=%2F&token={token}"
                )
                response = self.http_request(
                    method="POST",
                    path=index_path,
                    allow_redirects=False,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    cookies={"phpMyAdmin": token2, "pma_lang": "en"},
                    data=data,
                )
                if not response:
                    continue
                headers = {k.lower(): v for k, v in dict(response.headers or {}).items()}
                set_cookie = str(headers.get("set-cookie") or "")
                location = str(headers.get("location") or "")
                if response.status_code != 302:
                    continue
                if "phpMyAdmin=" not in set_cookie or "pmaUser-1=" not in set_cookie:
                    continue
                if (
                    "collation_connection=utf8mb4_unicode_ci" not in location
                    and "route=/" not in location
                    and "route=%2F" not in location
                ):
                    # Some versions only set cookies + Location to index
                    if "index.php" not in location and location:
                        continue
                return {
                    "path": index_path,
                    "username": user,
                    "password": password,
                    "status_code": 302,
                    "url": self._url(index_path),
                }
        return None

    def run(self):
        for base in BASES:
            hit = self._try_base(base)
            if not hit:
                continue
            self.report_finding(
                "phpMyAdmin default credentials accepted",
                severity="high",
                evidence={
                    "url": hit["url"],
                    "status_code": hit["status_code"],
                    "path": hit["path"],
                    "username": hit["username"],
                    "password": hit["password"],
                },
                impact={
                    "summary": "An attacker can access the database administration interface with default credentials.",
                    "business_risk": "Database compromise / data exfiltration",
                },
                remediation={
                    "summary": "Remove default credentials and restrict phpMyAdmin access.",
                    "actions": [
                        "Change or disable default accounts",
                        "Restrict phpMyAdmin to trusted networks / VPN",
                        "Enforce strong passwords and MFA where possible",
                    ],
                },
            )
            return True
        return False
