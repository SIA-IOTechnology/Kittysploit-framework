#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Request a Quote for WooCommerce <= 2.9.2 upload (CVE-2026-18143)."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "woocommerce-request-a-quote"
_VULN_HIGH = (2, 9, 2)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Request Quote WC CVE-2026-18143 detect",
        "description": (
            "Detects CVE-2026-18143 when quote popup flow accepts qfile upload via "
            "afrfq_submit_quote_via_popup (requires quote rule on product)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-18143",
        "references": ["https://github.com/murrez/CVE-2026-18143"],
        "modules": ["exploits/multi/http/request_quote_wc_cve_2026_18143_upload_rce"],
        "tags": ["web", "scanner", "wordpress", "woocommerce", "file-upload", "cve-2026-18143"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["exploits/multi/http/request_quote_wc_cve_2026_18143_upload_rce"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    product_slug = OptString("", "WooCommerce product slug", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _slug(self) -> str:
        forced = (self.product_slug or "").strip()
        if forced:
            return forced.lstrip("/").split("/")[0]
        shop = self.http_request(method="GET", path=self._join("/shop/"), allow_redirects=True)
        if shop:
            m = re.search(r"/product/([a-zA-Z0-9_-]+)", shop.text or "")
            if m:
                return m.group(1)
        rest = self.http_request(
            method="GET",
            path=self._join("/wp-json/wc/store/products"),
            params={"per_page": "1"},
            allow_redirects=False,
        )
        if rest and rest.status_code == 200:
            m = re.search(r'"slug"\s*:\s*"([^"]+)"', rest.text or "")
            if m:
                return m.group(1)
        return ""

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        slug = self._slug()
        if not slug:
            return False
        prod = self.http_request(method="GET", path=self._join(f"/product/{slug}/"), allow_redirects=True)
        if not prod:
            return False
        html = prod.text or ""
        if "afrfq" not in html.lower() and "request a quote" not in html.lower():
            return False
        nonce_m = re.search(r'"nonce"\s*:\s*"([a-f0-9]{6,12})"', html)
        pid_m = re.search(r'postid-(\d+)|"product_id"\s*:\s*"?(\d+)"?', html)
        rule_m = re.search(r'data-rule_id="(\d+)"', html)
        if not nonce_m or not pid_m:
            self.set_info(
                severity="high",
                reason="Request Quote plugin present — manual quote flow may allow upload",
                path=f"/product/{slug}/",
                cve="CVE-2026-18143",
            )
            return True
        pid = pid_m.group(1) or pid_m.group(2)
        rule = rule_m.group(1) if rule_m else "1"
        self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            data={
                "action": "add_to_quote",
                "nonce": nonce_m.group(1),
                "product_id": pid,
                "rule_id": rule,
                "quantity": "1",
            },
            allow_redirects=False,
        )
        self.set_info(
            severity="critical",
            reason="Request Quote CVE-2026-18143 — quote AJAX surface on product",
            path="/wp-admin/admin-ajax.php",
            cve="CVE-2026-18143",
        )
        return True
