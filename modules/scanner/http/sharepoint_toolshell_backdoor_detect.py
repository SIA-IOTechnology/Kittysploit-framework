#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects a persistent webshell named 'spinstall0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SharePoint Webshell - ToolShell Detection',
        'description': "Detects a persistent webshell named 'spinstall0.aspx' deployed on Microsoft SharePoint servers. This file exposes sensitive cryptographic machineKey values from the SharePoint configuration, indicating the presence of a ToolShell backdoor implant. This implant is linked to targeted post-auth RCE campaigns exploiting CVE-2025-53770.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'sharepoint', 'webshell', 'implant', 'aspx', 'backdoor', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': ['https://research.eye.security/sharepoint-under-siege/'],
    }

    def run(self):
        path = '/_layouts/15/spinstall0.aspx'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        body_all = ('hmacsha256', 'framework20sp1', 'auto',)
        header_any = ('microsoftsharepointteamservices',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason='SharePoint Webshell - ToolShell detected',
                path=path,
            )
            return True
        return False

