#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is a rather strange file that directly echoes some content belonging to the inaccessible zzz_config."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zzzcms 1.75 - Information Disclosure Detection',
        'description': 'There is a rather strange file that directly echoes some content belonging to the inaccessible zzz_config.php. The information leakage file is located in plugins\\webuploader\\js\\webconfig.php, and the management path name of the management background can be obtained directly. No need to blast admin and add 3 digits anymore',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'zzzcms', 'info', 'disclosure', 'vuln'],
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
        'references': ['https://xz.aliyun.com/t/7414'],
    }

    def run(self):
        path = '/plugins/webuploader/js/webconfig.php'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('var adminpath', 'var imageMaxSize=',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='low', reason='Zzzcms 1.75 - Information Disclosure detected', path=path)
            return True
        return False

