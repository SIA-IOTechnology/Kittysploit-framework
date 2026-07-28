#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle WebLogic Server (Oracle Fusion Middleware (component: WLS Core Components) is susceptible to a remote c."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle WebLogic Server - Remote Code Execution Detection',
        'description': 'Oracle WebLogic Server (Oracle Fusion Middleware (component: WLS Core Components) is susceptible to a remote code execution vulnerability. Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 2.2.1.3.0 and 12.2.1.4.0. This easily exploitable vulnerability could allow unauthenticated attackers with network access via IIOP to compromise Oracle WebLogic Server.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'oracle', 'weblogic', 'rce', 'unauth', 'kev', 'vkev', 'vuln'],
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
            'https://github.com/hktalent/CVE-2020-2551',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-2551',
            'https://www.oracle.com/security-alerts/cpujan2020.html',
            'https://github.com/neilzhang1/Chinese-Charts',
            'https://github.com/pjgmonteiro/Pentest-tools',
        ],
        'cve': 'CVE-2020-2551',
    }

    def run(self):
        r = self.http_request(method="GET", path='/console/login/LoginForm.jsp', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('10.3.6.0', '12.1.3.0', '12.2.1.3', '12.2.1.4', 'WebLogic',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="Oracle WebLogic Server - Remote Code Execution detected",
                path='/console/login/LoginForm.jsp',
            )
            return True
        return False

