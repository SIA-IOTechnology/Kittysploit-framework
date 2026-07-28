#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Favicon based AEM Detection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.osint.favicon_hash import shodan_mmh3


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Favicon based AEM Detection',
        'description': 'Detects Favicon based AEM Detection.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'aem', 'favicon', 'tech', 'adobe'],
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
            'https://twitter.com/brsn76945860/status/1171233054951501824',
            'https://gist.github.com/yehgdotnet/b9dfc618108d2f05845c4d8e28c5fc6a',
            'https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139',
            'https://github.com/devanshbatham/FavFreak',
            'https://github.com/sansatart/scrapts/blob/master/shodan-favicon-hashes.csv',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/libs/granite/core/content/login/favicon.ico', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        mmh3_vals = ('-144483185',)
        if (shodan_mmh3(r.content or b"") in mmh3_vals):
            self.set_info(
                severity='info',
                reason="Favicon based AEM detected",
                path='/libs/granite/core/content/login/favicon.ico',
            )
            return True
        return False

