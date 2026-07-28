#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GitLab CE/EE contains a hard-coded credentials vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GitLab CE/EE - Hard-Coded Credentials Detection',
        'description': 'GitLab CE/EE contains a hard-coded credentials vulnerability. A hardcoded password was set for accounts registered using an OmniAuth provider (e.g. OAuth, LDAP, SAML), allowing attackers to potentially take over accounts. This template attempts to passively identify vulnerable versions of GitLab without the need for an exploit by matching unique hashes for the application-<hash>.css file in the header for unauthenticated requests. Positive matches do not guarantee exploitability. Affected versions are 14.7 prior to 14.7.7, 14.8 prior to 14.8.5, and 14.9 prior to 14.9.2.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'gitlab', 'packetstorm', 'vuln'],
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
            'https://gitlab.com/gitlab-com/gl-security/threatmanagement/redteam/redteam-public/cve-hash-harvester',
            'https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-1162.json',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1162',
            'http://packetstormsecurity.com/files/166828/Gitlab-14.9-Authentication-Bypass.html',
            'https://nvd.nist.gov/vuln/detail/cve-2022-1162',
        ],
        'cve': 'CVE-2022-1162',
    }

    def run(self):
        r = self.http_request(method="GET", path='/users/sign_in', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('003236d7e2c5f1f035dc8b67026d7583ee198b568932acd8faeac18cec673dfa', '1d840f0c4634c8813d3056f26cbab7a685d544050360a611a9df0b42371f4d98', '6eb5eaa5726150b8135a4fd09118cfd6b29f128586b7fa5019a04f1c740e9193', '6fa9fec63ba24ec06fcae0ec30d1369619c2c3323fe9ddc4849af86457d59eef', 'cfa6748598b5e507db0e53906a7639e2c197a53cb57da58b0a20ed087cc0b9d5', 'f8ba2470fbf1e30f2ce64d34705b8e6615ac964ea84163c8a6adaaf8a91f9eac',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="GitLab CE/EE - Hard-Coded Credentials detected",
                path='/users/sign_in',
            )
            return True
        return False

