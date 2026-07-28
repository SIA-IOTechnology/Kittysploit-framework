#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SolarWinds Web Help Desk before version 12."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SolarWinds Web Help Desk < 12.8.3 - Insecure Deserialization Detection',
        'description': "SolarWinds Web Help Desk before version 12.8.3 contain a critical Java deserialization vulnerability that enables remote code execution. Attackers can exploit this flaw to execute arbitrary commands on the host machine. Initially reported as unauthenticated, SolarWinds was unable to reproduce without authentication but still recommended immediate patching. With a CVSS score of 9.8, this vulnerability was discovered by Inmarsat Government researchers and added to CISA's Known Exploited Vulnerabilities Catalog due to active exploitation in the wild. The complete attack vector requires low complexity and has high impact on confidentiality, integrity, and availability. This vulnerability was later bypassed, leading to CVE-2024-28988 and subsequently CVE-2025-26399. Fixed in version 12.8.3 Hotfix 1.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'kev', 'solarwinds', 'webhelpdesk', 'deserialization', 'rce', 'vkev'],
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
            'https://www.helpnetsecurity.com/2024/08/15/cve-2024-28986/',
            'https://threatprotect.qualys.com/2024/08/18/solarwinds-web-help-desk-whd-java-deserialization-vulnerability-cve-2024-28986/',
            'https://thehackernews.com/2024/08/solarwinds-releases-patch-for-critical.html',
        ],
        'cve': 'CVE-2024-28986',
    }

    def run(self):
        path = '/helpdesk/WebObjects/Helpdesk.woa'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Web Help Desk Software', 'SolarWinds WorldWide', '/WebObjects/Helpdesk.woa', 'HCS Web Help Desk',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='critical',
                reason='SolarWinds Web Help Desk < 12.8.3 - Insecure Deserialization detected',
                path=path,
            )
            return True
        return False

