#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Videos sync PDF 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Videos sync PDF <=1.7.4 - Local File Inclusion Detection',
        'description': 'WordPress Videos sync PDF 1.7.4 and prior does not validate the p parameter before using it in an include statement, which could lead to local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'lfi', 'wp-plugin', 'unauth', 'wpscan', 'packetstorm', 'wp', 'wordpress', 'commoninja', 'vuln'],
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
            'https://wpscan.com/vulnerability/fe3da8c1-ae21-4b70-b3f5-a7d014aa3815',
            'https://packetstormsecurity.com/files/166534/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1392',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-1392',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/video-synchro-pdf/reglages/Menu_Plugins/tout.php?p=tout', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('failed to open stream: No such file or directory', 'REPERTOIRE_VIDEOSYNCPDFreglages/Menu_Plugins/tout.php',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="WordPress Videos sync PDF <=1.7.4 - Local File Inclusion detected",
                path='/wp-content/plugins/video-synchro-pdf/reglages/Menu_Plugins/tout.php?p=tout',
            )
            return True
        return False

