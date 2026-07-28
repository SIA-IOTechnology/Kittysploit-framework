#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ametys CMS before 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ametys CMS Information Disclosure Detection',
        'description': 'Ametys CMS before 4.5.0 allows a remote unauthenticated attacker to read documents such as plugins/web/service/search/auto-completion/domain/en.xml (and similar pathnames for other languages) via the auto-completion plugin, which contain all characters typed by all users, including the content of private pages. For example, a private page may contain usernames, e-mail addresses, and possibly passwords.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'plugin', 'ametys', 'cms', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2022-26159',
            'https://podalirius.net/en/cves/2022-26159/',
            'https://issues.ametys.org/browse/CMS-10973',
            'https://github.com/p0dalirius/CVE-2022-26159-Ametys-Autocompletion-XML/',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-26159',
    }

    def run(self):
        r = self.http_request(method="GET", path='/plugins/web/service/search/auto-completion/domain/en.xml?q=adm', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<auto-completion>', '<item>',)
        header_any = ('text/xml',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Ametys CMS Information Disclosure detected",
                path='/plugins/web/service/search/auto-completion/domain/en.xml?q=adm',
            )
            return True
        return False

