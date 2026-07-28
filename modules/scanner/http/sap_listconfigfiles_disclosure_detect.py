#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected SAP systems where the SAP Start Service (sapstartsrv) SAPControl SOAP interface exposes the ListConfi."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SAPControl ListConfigFiles - Disclosure Detection',
        'description': 'Detected SAP systems where the SAP Start Service (sapstartsrv) SAPControl SOAP interface exposes the ListConfigFiles web method without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfig', 'sap', 'sapcontrol', 'soap', 'config', 'disclosure'],
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
            'https://itsiti.com/csmon/',
            'https://cloud.ibm.com/docs/sap?topic=sap-monitoring-prereqs',
            'https://help.sap.com/docs/SUPPORT_CONTENT/si/3362959700.html',
        ],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'text/xml; charset=UTF-8', 'SOAPAction': '\'""\''}, data='<?xml version="1.0" encoding="utf-8"?>\n<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">\n  <SOAP-ENV:Header>\n    <sapsess:Session xmlns:sapsess="http://www.sap.com/webas/630/soap/features/session/">\n      <enableSession>true</enableSession>\n    </sapsess:Session>\n  </SOAP-ENV:Header>\n  <SOAP-ENV:Body>\n    <ns1:ListConfigFiles xmlns:ns1="urn:SAPControl"/>\n  </SOAP-ENV:Body>\n</SOAP-ENV:Envelope>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('ListConfigFilesResponse', '<configfiles>',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='SAPControl ListConfigFiles - Disclosure detected', path=path)
            return True
        return False

