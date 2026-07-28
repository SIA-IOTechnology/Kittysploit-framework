#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KevinLab is a venture company specialized in IoT, Big Data, A."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'KevinLAB Devices Detection',
        'description': "KevinLab is a venture company specialized in IoT, Big Data, A.I based energy management platform. KevinLAB's BEMS (Building Energy Management System) enables efficient energy management in buildings by collecting and analyzing various information of energy usage and facilities as well as efficiency and indoor environment control.",
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'iot', 'kevinlab'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
    }

    def run(self):
        for path in ('/pages/', '/dashboard/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('<title>BEMS</title>', '../http/index.php', '<title>HEMS</title>', '../dashboard/proc.php',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='info',
                    reason="KevinLAB Devices detected",
                    path=path,
                )
                return True
        return False

