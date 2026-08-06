#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Instant Appointment CVE-2026-15282 (<= 1.2 unauthenticated upload)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.instant_appointment_probe import (
    INSTANT_APPOINTMENT_AJAX_PATH,
    INSTANT_APPOINTMENT_PATCHED_VERSION,
    INSTANT_APPOINTMENT_SLUG,
    INSTANT_APPOINTMENT_VULN_MAX,
    InstantAppointment,
)
from lib.protocols.http.wordpress import Wordpress


class Module(Scanner, Http_client, Wordpress, InstantAppointment):
    __info__ = {
        "name": "WordPress Instant Appointment CVE-2026-15282 Detect",
        "description": (
            "Detects Instant Appointment <= 1.2 vulnerable to CVE-2026-15282: "
            "unauthenticated add_service_front AJAX writes arbitrary files via "
            "file_get_contents(image_url) + file_put_contents(image_name). "
            f"Fixed in {INSTANT_APPOINTMENT_PATCHED_VERSION}."
        ),
        "author": ["Random Robbie", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-15282"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-15282",
            "https://www.cve.org/CVERecord?id=CVE-2026-15282",
        ],
        "modules": ["exploits/multi/http/wp_instant_appointment_cve_2026_15282_rce"],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "wp-plugin",
            "instant-appointment",
            "file-upload",
            "rce",
            "cve-2026-15282",
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
                "produces_capabilities": ["rce"],
                "suggested_followups": [
                    "exploits/multi/http/wp_instant_appointment_cve_2026_15282_rce",
                ],
            },
        },
    }

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(getattr(self, "path", "/"))

    def _probe_version(self) -> tuple[str, str]:
        base = self._wp_base()
        version = self.wp_plugin_version(INSTANT_APPOINTMENT_SLUG, base)
        if version:
            readme = self.wp_plugin_path(base, INSTANT_APPOINTMENT_SLUG, "readme.txt")
            return INSTANT_APPOINTMENT_SLUG, version

        probe = self.instant_appointment_probe(base)
        if probe.get("found"):
            return INSTANT_APPOINTMENT_SLUG, str(probe.get("version") or "")
        return "", ""

    def run(self):
        slug, version = self._probe_version()
        if not slug:
            return False

        vulnerable = self.instant_appointment_is_vulnerable(version) if version else None

        if vulnerable is True:
            severity = "critical"
            reason = (
                f"Instant Appointment {version} <= {INSTANT_APPOINTMENT_VULN_MAX} "
                f"(CVE-2026-15282 unauthenticated upload via {INSTANT_APPOINTMENT_AJAX_PATH}, "
                f"fixed in {INSTANT_APPOINTMENT_PATCHED_VERSION})"
            )
        elif vulnerable is False:
            severity = "info"
            reason = (
                f"Instant Appointment {version} detected; patched for CVE-2026-15282 "
                f"(>= {INSTANT_APPOINTMENT_PATCHED_VERSION})"
            )
        else:
            severity = "high"
            reason = (
                f"Instant Appointment plugin detected ({slug}) version unknown; "
                f"CVE-2026-15282 if <= {INSTANT_APPOINTMENT_VULN_MAX}"
            )

        print_status(f"Instant Appointment {slug} version={version or 'unknown'} vuln={vulnerable}")
        self.set_info(
            severity=severity,
            reason=reason,
            plugin=slug,
            version=version or "unknown",
            vulnerable=vulnerable,
            cve="CVE-2026-15282",
        )
        return True
