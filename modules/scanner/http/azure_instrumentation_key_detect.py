#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed Azure Application Insights Instrumentation Keys (classic ikey format) in HTTP responses, whic."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Azure Instrumentation Key - Exposure Detection',
        'description': 'Detected exposed Azure Application Insights Instrumentation Keys (classic ikey format) in HTTP responses, which allowed anyone to send telemetry data and, in some older configurations, could enable read access via undocumented or legacy APIs.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'azure', 'instrumentation', 'appinsights', 'token'],
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
        'references': [
            'https://learn.microsoft.com/en-us/azure/azure-monitor/app/connection-strings',
            'http://www.medic-consulting.com/2016/07/10/Share-Asp-Net-Core-appsettings-json-with-Service-Fabric-Microservices/',
        ],
    }

    def run(self):
        for path in ('/', '/appsettings.json'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('InstrumentationKey', 'instrumentationKey', 'APPINSIGHTS_INSTRUMENTATIONKEY', '<InstrumentationKey>',)
            body_regexes = ('instrumentationKey:"([0-9a-z-]+)"', '<InstrumentationKey>(.*)</InstrumentationKey>', 'APPINSIGHTS_INSTRUMENTATIONKEY=([a-z0-9-]+)', 'InstrumentationKey": "([0-9a-z-]+)"',)
            if (any(m in body for m in body_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='medium',
                    reason="Azure Instrumentation Key - Exposure detected",
                    path=path,
                )
                return True
        return False

