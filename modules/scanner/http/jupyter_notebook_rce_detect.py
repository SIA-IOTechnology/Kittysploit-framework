#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jupyter Notebook is an interactive Notebook, computer application is a web based visualization, Jupyter Notebo."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jupyter Notebook - Remote Command Execution Detection',
        'description': 'Jupyter Notebook is an interactive Notebook, computer application is a web based visualization, Jupyter Notebook API/terminals path there are loopholes in the remote command execution.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'jupyter', 'notebook', 'rce', 'bypass', 'vuln'],
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
        'references': [
            'https://github.com/SCAMagic/SCAMagicScan/blob/de8130a2280ee08d719ac6612e590b8e2678fb97/pocs/poc-yaml-jupyter-notebook-rce.py',
        ],
    }

    def run(self):
        path = '/api/terminals'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'X-XSRFToken': '2|7a4faae0|819f5adf7edaef5e74502c9d0c75a604|1653492335', 'Cookie': '_xsrf=2|7a4faae0|819f5adf7edaef5e74502c9d0c75a604|1653492335'}, data='')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"name":', '"last_activity":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Jupyter Notebook - Remote Command Execution detected', path=path)
            return True
        return False

