#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Microsoft System Center Configuration Manager (SCCM) can be configured to allow anonymous access to its distri."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microsoft SCCM - Anonymous Distribution Point Access Detection',
        'description': 'Microsoft System Center Configuration Manager (SCCM) can be configured to allow anonymous access to its distribution points.This can lead to sensitive data exposure and information gathering by unauthorized users.This misconfiguration is exploitable only via HTTP.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'microsoft', 'sccm', 'anonymous', 'distribution-point', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://www.synacktiv.com/en/publications/sccmsecretspy-exploiting-sccm-policies-distribution-for-credentials-harvesting-initial',
            'https://github.com/badsectorlabs/sccm-http-looter',
            'https://learn.microsoft.com/en-us/intune/configmgr/core/servers/deploy/configure/install-and-configure-distribution-points',
        ],
    }

    def run(self):
        for path in ('/SMS_DP_SMSPKG$/Datalib', '/:80/SMS_DP_SMSPKG$/Datalib'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('/SMS_DP_SMSPKG\\$\\/Datalib/([0-9a-z-]+)\\.INI',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='medium',
                    reason="Microsoft SCCM - Anonymous Distribution Point Access detected",
                    path=path,
                )
                return True
        return False

