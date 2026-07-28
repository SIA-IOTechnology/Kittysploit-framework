#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected SAP systems where the SAP Start Service (sapstartsrv) SAPControl SOAP web service exposes the GetEnvi."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SAPControl GetEnvironment - Disclosure Detection',
        'description': 'Detected SAP systems where the SAP Start Service (sapstartsrv) SAPControl SOAP web service exposes the GetEnvironment web method without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfig', 'sap', 'soap', 'env', 'exposure'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://help.sap.com/docs/SUPPORT_CONTENT/si/3362959700.html',
            'https://itsiti.com/csmon/',
            'https://docs.avantra.com/api/latest/js/sap-control.html',
        ],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'text/xml; charset=UTF-8', 'SOAPAction': '\'""\''}, data='<?xml version="1.0" encoding="utf-8"?>\n<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">\n  <SOAP-ENV:Header>\n    <sapsess:Session xmlns:sapsess="http://www.sap.com/webas/630/soap/features/session/">\n      <enableSession>true</enableSession>\n    </sapsess:Session>\n  </SOAP-ENV:Header>\n  <SOAP-ENV:Body>\n    <ns1:GetEnvironment xmlns:ns1="urn:SAPControl"/>\n  </SOAP-ENV:Body>\n</SOAP-ENV:Envelope>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('GetEnvironmentResponse',)
        body_all = ('LOGNAME=', 'USER=',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(severity='medium', reason='SAPControl GetEnvironment - Disclosure detected', path=path)
            return True
        return False

