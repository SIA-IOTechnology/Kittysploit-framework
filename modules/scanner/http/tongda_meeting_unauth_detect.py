#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tongda Meeting Unauthorized Access were Detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tongda OA Meeting - Unauthorized Access Detection',
        'description': 'Tongda Meeting Unauthorized Access were Detected.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'tongda', 'unauth', 'misconfig', 'vuln'],
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
            'https://github.com/hktalent/scan4all/blob/2a7faf7862265eab33699034fd193bcf11b44e0f/config/poc/%E9%80%9A%E8%BE%BEoa/%E9%80%9A%E8%BE%BEoa-meeting-unauthorized-access.json#L10',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/general/calendar/arrange/get_cal_list.php?starttime=1548058874&endtime=33165447106&view=agendaDay', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = (":', 'originalTitle\\", ":', 'type\\", 'creator\\":', 'originalTitle\\":', 'view\\":', 'type\\":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Tongda OA Meeting - Unauthorized Access detected",
                path='/general/calendar/arrange/get_cal_list.php?starttime=1548058874&endtime=33165447106&view=agendaDay',
            )
            return True
        return False

