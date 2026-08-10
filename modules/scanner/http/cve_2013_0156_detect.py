#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ruby on Rails XML/YAML deserialization probe (CVE-2013-0156)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Rails - XML YAML Deserialization Detection (CVE-2013-0156)',
        'description': (
            'Detects CVE-2013-0156 by POSTing XML probes (string vs yaml Time vs '
            'null-byte object) to /posts/search and comparing status codes.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2013', 'rails', 'yaml', 'rce', 'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2013-0156',
        ],
        'cve': 'CVE-2013-0156',
    }

    search_path = OptString('/posts/search', 'XML endpoint path', required=False)

    @staticmethod
    def _looks_like_rails(resp) -> bool:
        if not resp:
            return False
        headers = {str(k).lower(): str(v) for k, v in (resp.headers or {}).items()}
        if any(h in headers for h in ('x-runtime', 'x-request-id', 'x-action-dispatch')):
            return True
        server = headers.get('server', '')
        if 'phusion' in server.lower() or 'passenger' in server.lower():
            return True
        body = (resp.text or '').lower()
        return any(x in body for x in ('actioncontroller', 'activesupport', 'rails.root', 'ruby on rails'))

    def run(self):
        path = str(self.search_path or '/posts/search')
        if not path.startswith('/'):
            path = '/' + path
        headers = {'Content-Type': 'application/xml'}
        p1 = (
            '<?xml version="1.0" encoding="UTF-8"?>\r\n'
            '<probe type="string"><![CDATA[\r\nhello\r\n]]></probe>'
        )
        r1 = self.http_request(method='POST', path=path, data=p1, headers=headers, allow_redirects=False)
        if not r1 or r1.status_code >= 400:
            return False
        p2 = (
            '<?xml version="1.0" encoding="UTF-8"?>\r\n'
            '<probe type="yaml"><![CDATA[\r\n'
            '--- !ruby/object:Time {}\r\n\r\n]]></probe>'
        )
        r2 = self.http_request(method='POST', path=path, data=p2, headers=headers, allow_redirects=False)
        if not r2 or r2.status_code < 200 or r2.status_code >= 400:
            return False
        p3 = (
            '<?xml version="1.0" encoding="UTF-8"?>\r\n'
            '<probe type="yaml"><![CDATA[\r\n'
            '--- !ruby/object:\x00\r\n]]></probe>'
        )
        r3 = self.http_request(method='POST', path=path, data=p3, headers=headers, allow_redirects=False)
        # Status triad alone is noisy; require a Rails fingerprint on any probe response.
        if not any(self._looks_like_rails(r) for r in (r1, r2, r3)):
            return False
        if r3 and r3.status_code == 200:
            self.set_info(
                severity='critical',
                reason='Rails XML/YAML deserialization (CVE-2013-0156)',
                path=path,
            )
            return True
        return False
