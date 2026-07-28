#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle E-Business Suite (component: Manage Proxies) 12."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle E-Business Suite <=12.2 - Authentication Bypass Detection',
        'description': 'Oracle E-Business Suite (component: Manage Proxies) 12.1 and 12.2 are susceptible to an easily exploitable vulnerability that allows an unauthenticated attacker with network access via HTTP to compromise it by self-registering for an account. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle E-Business Suite accessible data.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'oracle', 'misconfig', 'auth-bypass', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://orwaatyat.medium.com/my-new-discovery-in-oracle-e-business-login-panel-that-allowed-to-access-for-all-employees-ed0ec4cad7ac',
            'https://twitter.com/GodfatherOrwa/status/1514720677173026816',
            'https://www.oracle.com/security-alerts/alert-cve-2022-21500.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-21500',
            'https://www.oracle.com/security-alerts/cpujul2022.html',
        ],
        'cve': 'CVE-2022-21500',
    }

    def run(self):
        for path in ('/OA_HTML/ibeCAcpSSOReg.jsp', '/OA_HTML/ibeCRgpPrimaryCreate.jsp', '/OA_HTML/ibeCRgpIndividualUser.jsp', '/OA_HTML/ibeCRgpPartnerPriCreate.jsp'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('Registration', 'Register as individual', '<!-- ibeCZzpRuntimeIncl.jsp end -->',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="Oracle E-Business Suite <=12.2 - Authentication Bypass detected",
                    path=path,
                )
                return True
        return False

