#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Oracle Applications Framework component of Oracle E-Business Suite (subcomponent: Popup windows (lists of ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle E-Business Suite 12.1.3/12.2.x - Open Redirect Detection',
        'description': 'The Oracle Applications Framework component of Oracle E-Business Suite (subcomponent: Popup windows (lists of values, datepicker, etc.)) is impacted by open redirect issues in versions 12.1.3, 12.2.3, 12.2.4, 12.2.5 and 12.2.6. These easily exploitable vulnerabilities allow unauthenticated attackers with network access via HTTP to compromise Oracle Applications Framework. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Applications Framework, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Applications Framework accessible data.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'oracle', 'redirect', 'edb', 'vuln'],
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
            'https://blog.zsec.uk/cve-2017-3528/',
            'https://www.exploit-db.com/exploits/43592',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-3528',
            'http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html',
            'http://www.securitytracker.com/id/1038299',
        ],
        'cve': 'CVE-2017-3528',
    }

    def run(self):
        r = self.http_request(method="GET", path='/OA_HTML/cabo/jsps/a.jsp?_t=fredRC&configName=&redirect=%2f%5cinteract.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('noresize src="/\\interact.sh?configName=',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Oracle E-Business Suite 12.1.3/12.2.x - Open Redirect detected",
                path='/OA_HTML/cabo/jsps/a.jsp?_t=fredRC&configName=&redirect=%2f%5cinteract.sh',
            )
            return True
        return False

