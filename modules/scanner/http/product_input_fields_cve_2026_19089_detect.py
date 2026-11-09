#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Product Input Fields for WooCommerce < 2.0.2 upload RCE (CVE-2026-19089)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "product-input-fields-for-woocommerce"
_VULN_HIGH = (2, 0, 1)
_CANARY = "PIF_CANARY_527_PHP"


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Product Input Fields CVE-2026-19089 detect",
        "description": (
            "Detects CVE-2026-19089: unauthenticated product file field upload through "
            "WooCommerce cart/checkout when accepted-types is empty."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-19089",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-19089"],
        "modules": ["exploits/multi/http/product_input_fields_cve_2026_19089_upload_rce"],
        "tags": ["web", "scanner", "wordpress", "woocommerce", "cve-2026-19089"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["exploits/multi/http/product_input_fields_cve_2026_19089_upload_rce"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        shop = self.http_request(method="GET", path=self._join("/shop/"), allow_redirects=True)
        if not shop:
            return False
        m = re.search(r'href="(?:https?://[^/]+)?(/product/[^"]+/?)"', shop.text or "")
        if not m:
            return False
        product = self.http_request(method="GET", path=self._join(m.group(1)), allow_redirects=True)
        if not product:
            return False
        field = re.search(r'name="(alg_wc_pif_global_\d+)"', product.text or "")
        pid = re.search(r'name="add-to-cart"\s+value="(\d+)"', product.text or "")
        if not field or not pid:
            return False
        self.set_info(
            severity="critical",
            reason="Product Input Fields CVE-2026-19089 — file upload surface on product page",
            path=m.group(1),
            cve="CVE-2026-19089",
        )
        return True
