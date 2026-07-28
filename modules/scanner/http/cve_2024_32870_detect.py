#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Combodo iTop is a simple, web based IT Service Management tool."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'iTop Hub Connector - Information Disclosure Detection',
        'description': 'Combodo iTop is a simple, web based IT Service Management tool. Server, OS, DBMS, PHP, and iTop info (name, version and parameters) can be read by anyone having access to iTop URI. This issue has been patched in versions 2.7.11, 3.0.5, 3.1.2, and 3.2.0.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'itop', 'disclosure', 'unauth', 'exposure', 'vkev', 'vuln'],
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
            'https://www.synacktiv.com/en/advisories/multiple-vulnerabilities-on-itop',
            'https://github.com/Combodo/iTop/security/advisories/GHSA-rfjh-2f5x-qxmx',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-32870',
        ],
        'cve': 'CVE-2024-32870',
    }

    def run(self):
        r = self.http_request(method="GET", path='/pages/exec.php?exec_module=itop-hub-connector&exec_page=launch.php&target=inform_after_setup', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('database_settings', 'database_version', 'instance_host',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="iTop Hub Connector - Information Disclosure detected",
                path='/pages/exec.php?exec_module=itop-hub-connector&exec_page=launch.php&target=inform_after_setup',
            )
            return True
        return False

