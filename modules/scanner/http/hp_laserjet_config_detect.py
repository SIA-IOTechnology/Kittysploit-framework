#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HP LaserJet printer web interface exposes sensitive configuration information without authentication."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HP LaserJet Configuration Exposure Detection',
        'description': 'HP LaserJet printer web interface exposes sensitive configuration information without authentication.This includes device information, network configuration, SNMP settings, and other sensitive data that could be leveraged for further attacks or network reconnaissance.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'hp', 'laserjet', 'printer', 'iot', 'config', 'misconfig'],
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
            'https://support.hp.com/us-en/document/ish_4629476-1206130-16',
            'https://h10032.www1.hp.com/ctg/Manual/c03137192.pdf',
            'https://www.exploit-db.com/ghdb/6459',
        ],
    }

    def run(self):
        for path in ('/hp/device/this.LCDispatcher?nav=hp.Config', '/info_configuration.html?tab=Home&menu=DevConfig', '/SSI/info_configuration.htm'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('Configuration Page', 'Device Configuration', 'set_config_deviceinfo',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='medium',
                    reason="HP LaserJet Configuration Exposure detected",
                    path=path,
                )
                return True
        return False

