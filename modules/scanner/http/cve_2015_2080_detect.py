#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Eclipse Jetty before 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Eclipse Jetty <9.2.9.v20150224 - Sensitive Information Leakage Detection',
        'description': 'Eclipse Jetty before 9.2.9.v20150224 allows remote attackers to obtain sensitive information from process memory via illegal characters in an HTTP header.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'jetty', 'packetstorm', 'fedoraproject', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/eclipse/jetty.project/blob/jetty-9.2.x/advisories/2015-02-24-httpparser-error-buffer-bleed.md',
            'https://blog.gdssecurity.com/labs/2015/2/25/jetleak-vulnerability-remote-leakage-of-shared-buffers-in-je.html',
            'http://packetstormsecurity.com/files/130567/Jetty-9.2.8-Shared-Buffer-Leakage.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-2080',
            'http://dev.eclipse.org/mhonarc/lists/jetty-announce/msg00074.html',
        ],
        'cve': 'CVE-2015-2080',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Referer': '\\x00'})
        if not r or r.status_code != 400:
            return False
        body = r.text or ""
        body_any = ('Illegal character 0x0 in state',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='high',
                reason='Eclipse Jetty <9.2.9.v20150224 - Sensitive Information Leakage detected',
                path=path,
            )
            return True
        return False

