#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-3891 — Payment Gateway PIX for WooCommerce unauthenticated upload detection."""

from __future__ import annotations

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

PLUGIN_SLUG = "payment-gateway-pix-for-woocommerce"
PATCHED_VERSION = "1.5.1"
ACTION_NONCE = "lkn_pix_for_woocommerce_generate_nonce"
NONCE_NAME = "lkn_pix_for_woocommerce_c6_settings_nonce"


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Payment Gateway PIX for WooCommerce CVE-2026-3891 upload detect",
        "description": (
            "Detects CVE-2026-3891 in Payment Gateway PIX for WooCommerce <= 1.5.0: "
            "unauthenticated nonce generation via admin-ajax.php indicates exposure to "
            "certificate_crt_path arbitrary file upload."
        ),
        "author": ["Mohammad Hossein Sadeghian", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-3891"],
        "tags": [
            "wordpress",
            "woocommerce",
            "pix",
            "file-upload",
            "rce",
            "unauthenticated",
            "cve-2026-3891",
        ],
        "modules": [
            "exploits/multi/http/wp_pix_gateway_cve_2026_3891_rce",
        ],
        "references": [
            "https://wordpress.org/plugins/payment-gateway-pix-for-woocommerce/",
            "https://www.cve.org/CVERecord?id=CVE-2026-3891",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.35,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["wordpress", "woocommerce"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce", "from_detail": "pix gateway upload"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/multi/http/wp_pix_gateway_cve_2026_3891_rce",
                ],
            },
        },
    }

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.path or "/")

    def _ajax_path(self) -> str:
        base = self._wp_base()
        return f"{base}/wp-admin/admin-ajax.php" if base != "/" else "/wp-admin/admin-ajax.php"

    def run(self):
        base = self._wp_base()
        version = self.wp_plugin_version(PLUGIN_SLUG, base)
        readme = self.wp_plugin_path(base, PLUGIN_SLUG, "readme.txt")

        if version and not self.wp_version_less_than(version, PATCHED_VERSION):
            if self.wp_version_in_range(version, (1, 5, 1), (99, 99, 99)):
                return False

        plugin_present = bool(version)
        if not plugin_present:
            response = self.http_request(method="GET", path=readme, allow_redirects=True)
            if not response or int(response.status_code or 0) != 200:
                return False
            plugin_present = PLUGIN_SLUG.replace("-", " ") in (response.text or "").lower() or True

        nonce_response = self.http_request(
            method="POST",
            path=self._ajax_path(),
            data={"action": ACTION_NONCE, "action_name": NONCE_NAME},
            timeout=max(int(self.timeout or 15), 15),
        )
        if not nonce_response or int(nonce_response.status_code or 0) != 200:
            return False

        try:
            payload = nonce_response.json()
            nonce = (payload.get("data") or {}).get("nonce") if isinstance(payload, dict) else None
        except (ValueError, json.JSONDecodeError):
            nonce = None

        if not nonce:
            return False

        reason = (
            f"Payment Gateway PIX {version or 'detected'} — unauthenticated AJAX nonce returned "
            f"(CVE-2026-3891 if <= 1.5.0)"
        )
        self.set_info(
            severity="critical",
            cve="CVE-2026-3891",
            reason=reason,
            path=self._ajax_path(),
            plugin_version=version or "unknown",
        )
        return True
