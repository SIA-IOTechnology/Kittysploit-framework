#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OSIsoft PI Vision (now AVEVA PI Vision) is a web-based data visualisation platform for the PI System, widely u."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OSIsoft PI Vision - Login Panel Detection',
        'description': 'OSIsoft PI Vision (now AVEVA PI Vision) is a web-based data visualisation platform for the PI System, widely used in energy, utilities, oil and gas, and manufacturing for real-time operational data monitoring. Exposed instances may provide access to sensitive operational technology data.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'scada', 'historian', 'ics', 'osisoft', 'aveva', 'pi-vision', 'pi-system', 'energy'],
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
        'references': ['https://www.aveva.com/en/products/pi-vision/', 'https://docs.aveva.com/bundle/pi-vision/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "")
        markers = (
            '<title>PI Vision</title>',
            'PI Vision User Guide',
            'PI Vision display',
            'project=PIVISION',
        )
        if any(m in body for m in markers):
            self.set_info(
                severity='info',
                reason="OSIsoft PI Vision - Login Panel detected",
                path='/',
            )
            return True
        return False

