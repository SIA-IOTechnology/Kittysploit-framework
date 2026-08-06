#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect WP Maps CVE-2026-39492 blind SQLi (<= 4.9.1)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress
from lib.protocols.http.wp_maps_probe import (
    WP_MAPS_AJAX_PATH,
    WP_MAPS_PATCHED_VERSION,
    WP_MAPS_SLUG,
    WP_MAPS_VULN_MAX,
    WpMaps,
)


class Module(Scanner, Http_client, Wordpress, WpMaps):
    __info__ = {
        "name": "WordPress WP Maps CVE-2026-39492 Detect",
        "description": (
            "Detects WP Maps (wp-google-map-plugin) <= 4.9.1 vulnerable to "
            "CVE-2026-39492: unauthenticated time-based blind SQLi in "
            "wpgmp_ajax_call via backtick-wrapped location_id bypassing esc_sql(). "
            f"Fixed in {WP_MAPS_PATCHED_VERSION}."
        ),
        "author": ["Wordfence", "IONIX", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-39492"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-39492",
            "https://www.cve.org/CVERecord?id=CVE-2026-39492",
        ],
        "modules": ["exploits/multi/http/wp_maps_cve_2026_39492_sqli"],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "wp-plugin",
            "wp-maps",
            "sqli",
            "blind",
            "time-based",
            "cve-2026-39492",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints", "exploit_paths"],
            "chain": {
                "produces_capabilities": ["sqli"],
                "suggested_followups": [
                    "exploits/multi/http/wp_maps_cve_2026_39492_sqli",
                ],
            },
        },
    }

    confirm_sqli = OptBool(
        False,
        "Run time-based SQLi confirmation (slow, ~15 requests)",
        False,
        advanced=True,
    )

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(getattr(self, "path", "/"))

    def run(self):
        probe = self.wp_maps_probe(self._wp_base())
        if not probe.get("found"):
            return False

        version = str(probe.get("version") or "")
        vulnerable = self.wp_maps_is_vulnerable(version)
        sqli_confirmed = None
        response_time = 0.0

        if bool(self.confirm_sqli) and vulnerable is not False:
            alive, reason = self.wp_maps_endpoint_alive(self._wp_base())
            if alive:
                sqli_confirmed, response_time = self.wp_maps_confirm_sqli(self._wp_base())
            else:
                print_warning(f"WP Maps AJAX endpoint unavailable: {reason}")

        if sqli_confirmed is True:
            severity = "critical"
            reason = (
                f"WP Maps {version} <= {WP_MAPS_VULN_MAX} with confirmed blind SQLi "
                f"via {WP_MAPS_AJAX_PATH} (CVE-2026-39492)"
            )
        elif vulnerable is True:
            severity = "critical"
            reason = (
                f"WP Maps {version} <= {WP_MAPS_VULN_MAX} "
                f"(CVE-2026-39492 blind SQLi via {WP_MAPS_AJAX_PATH})"
            )
        elif vulnerable is False:
            severity = "info"
            reason = (
                f"WP Maps {version} >= {WP_MAPS_PATCHED_VERSION} "
                f"(patched for CVE-2026-39492)"
            )
        else:
            severity = "high"
            reason = (
                f"WP Maps detected (version unknown) at {probe.get('evidence')}; "
                f"CVE-2026-39492 if <= {WP_MAPS_VULN_MAX}"
            )

        print_status(
            f"wp-maps version={version or 'unknown'} vuln={vulnerable} "
            f"sqli={sqli_confirmed}"
        )
        self.set_info(
            severity=severity,
            reason=reason,
            plugin=WP_MAPS_SLUG,
            version=version or "unknown",
            vulnerable=vulnerable,
            sqli_confirmed=sqli_confirmed,
            response_time=response_time,
            cve="CVE-2026-39492",
            evidence=probe.get("evidence"),
        )
        return True
