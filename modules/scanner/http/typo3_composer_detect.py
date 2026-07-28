#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The web application is based on Typo3 CMS."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Typo3 composer.json Exposure Detection',
        'description': 'The web application is based on Typo3 CMS. A sensitive file has been found. Access to such files must be restricted, as it may lead to disclosure of sensitive information about the web application.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'typo3', 'cms', 'exposure', 'misconfig', 'vuln'],
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
            'https://docs.typo3.org/c/typo3/cms-core/main/en-us/Changelog/9.0/Breaking-83302-ComposerRestrictsInstallationOfTypo3cms.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/typo3/sysext/install/composer.json', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('The Install Tool mounted as the module Tools>Install in TYPO3.', 'typo3-cms-framework',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="Typo3 composer.json Exposure detected",
                path='/typo3/sysext/install/composer.json',
            )
            return True
        return False

