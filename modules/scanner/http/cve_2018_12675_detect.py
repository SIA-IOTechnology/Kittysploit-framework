#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SV3C HD Camera L Series 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SV3C HD Camera L Series - Open Redirect Detection',
        'description': "SV3C HD Camera L Series 2.3.4.2103-S50-NTD-B20170508B and 2.3.4.2103-S50-NTD-B20170823B contains an open redirect vulnerability. It does not perform origin checks on URLs in the camera's web interface, which can be leveraged to send a user to an unexpected endpoint. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'redirect', 'sv3c', 'camera', 'iot', 'vuln'],
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
            'https://bishopfox.com/blog/sv3c-l-series-hd-camera-advisory',
            'https://vuldb.com/?id.125799',
            'https://www.bishopfox.com/news/2018/10/sv3c-l-series-hd-camera-multiple-vulnerabilities/',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-12675',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-12675',
    }

    def run(self):
        r = self.http_request(method="GET", path='/web/cgi-bin/hi3510/param.cgi?cmd=setmobilesnapattr&cururl=http%3A%2F%2Finteract.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<META http-equiv="Refresh" content="0;URL=http://interact.sh">',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="SV3C HD Camera L Series - Open Redirect detected",
                path='/web/cgi-bin/hi3510/param.cgi?cmd=setmobilesnapattr&cururl=http%3A%2F%2Finteract.sh',
            )
            return True
        return False

