#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wavlink WN530HG4, WN531G3, WN533A8, and WN551K are susceptible to improper access control via /cgi-bin/ExportA."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WAVLINK - Access Control Detection',
        'description': 'Wavlink WN530HG4, WN531G3, WN533A8, and WN551K are susceptible to improper access control via /cgi-bin/ExportAllSettings.sh, where a crafted POST request returns the current configuration of the device, including the administrator password. No authentication is required. The attacker must perform a decryption step, but all decryption information is readily available.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'exposure', 'wavlink', 'vuln'],
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
            'https://github.com/sudo-jtcsec/CVE/blob/master/CVE-2020-10973',
            'https://github.com/sudo-jtcsec/Nyra',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-10973',
            'https://github.com/Roni-Carta/nyra',
            'https://github.com/sudo-jtcsec/CVE/blob/master/CVE-2020-10973-affected_devices',
        ],
        'cve': 'CVE-2020-10973',
    }

    def run(self):
        path = '/backupsettings.dat'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('Salted__',)
        header_any = ('application/octet-stream',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='WAVLINK - Access Control detected', path=path)
            return True
        return False

