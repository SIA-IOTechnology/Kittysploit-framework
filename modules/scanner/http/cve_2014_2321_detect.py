#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZTE F460 and F660 cable modems allows remote attackers to obtain administrative access via sendcmd requests to."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ZTE Cable Modem Web Shell Detection',
        'description': 'ZTE F460 and F660 cable modems allows remote attackers to obtain administrative access via sendcmd requests to web_shell_cmd.gch, as demonstrated by using "set TelnetCfg" commands to enable a TELNET service with specified credentials.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2014', 'iot', 'zte', 'vkev', 'vuln'],
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
            'https://yosmelvin.wordpress.com/2017/09/21/f660-modem-hack/',
            'https://jalalsela.com/zxhn-h108n-router-web-shell-secrets/',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-2321',
            'http://www.kb.cert.org/vuls/id/600724',
            'http://www.myxzy.com/post-411.html',
        ],
        'cve': 'CVE-2014-2321',
    }

    def run(self):
        r = self.http_request(method="GET", path='/web_shell_cmd.gch', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('please input shell command', 'ZTE Corporation. All rights reserved',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="ZTE Cable Modem Web Shell detected",
                path='/web_shell_cmd.gch',
            )
            return True
        return False

