#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The installation wizard in DotNetNuke (DNN) before 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DotNetNuke 07.04.00 - Administration Authentication Bypass Detection',
        'description': 'The installation wizard in DotNetNuke (DNN) before 7.4.1 allows remote attackers to reinstall the application and gain SuperUser access via a direct request to Install/InstallWizard.aspx.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'dotnetnuke', 'auth-bypass', 'install', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2015-2794',
            'https://www.exploit-db.com/exploits/39777',
            'http://www.dnnsoftware.com/community-blog/cid/155198/workaround-for-potential-security-issue',
            'http://www.dnnsoftware.com/community/security/security-center',
            'https://dotnetnuke.codeplex.com/releases/view/615317',
        ],
        'cve': 'CVE-2015-2794',
    }

    def run(self):
        r = self.http_request(method="GET", path='/Install/InstallWizard.aspx?__VIEWSTATE', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Administrative Information', 'Database Information',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="DotNetNuke 07.04.00 - Administration Authentication Bypass detected",
                path='/Install/InstallWizard.aspx?__VIEWSTATE',
            )
            return True
        return False

