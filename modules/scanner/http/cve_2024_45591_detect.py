#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in XWiki Platform's REST API allows unauthorized users to access document history information."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XWiki Platform - Unauthorized Document History Access Detection',
        'description': "A vulnerability in XWiki Platform's REST API allows unauthorized users to access document history information. The REST API endpoint exposes the history of any page including modification times, version numbers, author details (username and display name), and version comments, regardless of access rights configuration, even on private wikis.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'xwiki', 'exposure', 'rest-api', 'vuln'],
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
            'https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-pvmm-55r5-g3mm',
            'https://jira.xwiki.org/browse/XWIKI-22052',
            'https://nvd.nist.gov/vuln/detail/cve-2024-45591',
        ],
        'cve': 'CVE-2024-45591',
    }

    def run(self):
        r = self.http_request(method="GET", path='/xwiki/rest/wikis/xwiki/spaces/Main/pages/WebHome/history', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('version', 'historySummary', 'pageId', 'comment',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="XWiki Platform - Unauthorized Document History Access detected",
                path='/xwiki/rest/wikis/xwiki/spaces/Main/pages/WebHome/history',
            )
            return True
        return False

