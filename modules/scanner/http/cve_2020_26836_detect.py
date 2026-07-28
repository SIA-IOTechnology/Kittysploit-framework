#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SAP Solution Manager contains an open redirect vulnerability via the logoff endpoint."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SAP Solution Manager - Open Redirect Detection',
        'description': 'SAP Solution Manager contains an open redirect vulnerability via the logoff endpoint. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'redirect', 'sap', 'vuln', 'vkev'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2020-26836',
            'https://onapsis.com/security-advisories/sap-solution-manager-open-redirect-trace-analysis/',
            'http://packetstormsecurity.com/files/163136/SAP-Solution-Manager-7.2-ST-720-Open-Redirection.html',
            'http://seclists.org/fulldisclosure/2021/Jun/25',
        ],
        'cve': 'CVE-2020-26836',
    }

    def run(self):
        r = self.http_request(method="GET", path='/sap/public/bc/icf/logoff?redirecturl=https://interact.sh', allow_redirects=False)
        if not r or r.status_code not in (302, 301, 307):
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('Location: https://www.interact.sh', 'Location: https://interact.sh',)
        if (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="SAP Solution Manager - Open Redirect detected",
                path='/sap/public/bc/icf/logoff?redirecturl=https://interact.sh',
            )
            return True
        return False

