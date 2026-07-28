#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Beckhoff TwinCAT HMI (Human Machine Interface) Server is part of the TwinCAT industrial automation platform us."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Beckhoff TwinCAT HMI Server - Login Panel Detection',
        'description': 'Beckhoff TwinCAT HMI (Human Machine Interface) Server is part of the TwinCAT industrial automation platform used in manufacturing, robotics, and process automation. It exposes a web-based HMI accessible via browser for monitoring and controlling PLC-driven systems.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'scada', 'ics', 'beckhoff', 'twincat', 'hmi', 'plc', 'automation'],
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
                'confidence_min': {
                },
                'confidence_min_any': {
                },
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
                'option_bindings': {
                },
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://www.beckhoff.com/en-en/products/automation/twincat/te2xxx-twincat-3-target/te2000.html',
            'https://infosys.beckhoff.com/english.php?content=../content/1033/te2000_tc3_hmi_engineering/index.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "")
        markers = (
            'TwinCAT',
            'Beckhoff',
        )
        if any(m in body for m in markers):
            self.set_info(
                severity='info',
                reason="Beckhoff TwinCAT HMI Server - Login Panel detected",
                path='/',
            )
            return True
        return False

