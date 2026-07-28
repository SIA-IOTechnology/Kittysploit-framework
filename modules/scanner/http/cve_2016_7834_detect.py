#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple SONY network cameras are vulnerable to sensitive information disclosure via hardcoded credentials."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sony IPELA Engine IP Camera - Hardcoded Account Detection',
        'description': 'Multiple SONY network cameras are vulnerable to sensitive information disclosure via hardcoded credentials.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2016', 'sony', 'backdoor', 'unauth', 'telnet', 'iot', 'camera', 'vuln'],
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
            'https://sec-consult.com/vulnerability-lab/advisory/backdoor-vulnerability-in-sony-ipela-engine-ip-cameras/',
            'https://www.bleepingcomputer.com/news/security/backdoor-found-in-80-sony-surveillance-camera-models/',
            'https://jvn.jp/en/vu/JVNVU96435227/index.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2016-7834',
            'https://www.sony.co.uk/pro/article/sony-new-firmware-for-network-cameras',
        ],
        'cve': 'CVE-2016-7834',
    }

    def run(self):
        r = self.http_request(method="GET", path='/command/prima-factory.cgi', allow_redirects=False)
        if not r or r.status_code != 204:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('gen5th', 'gen6th',)
        if (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Sony IPELA Engine IP Camera - Hardcoded Account detected",
                path='/command/prima-factory.cgi',
            )
            return True
        return False

